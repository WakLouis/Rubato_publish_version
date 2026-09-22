"""Online DBSP+DQA orchestration. No PD-ECN or legacy phase gates."""

import json
import logging
import math
import os
import time

try:
    from .ns3_contract import equal_quanta, demand_quanta, burst_bytes, validate_logical_flows
except (ImportError, ValueError, SystemError):
    from ns3_contract import equal_quanta, demand_quanta, burst_bytes, validate_logical_flows

try:
    from .online_planner import (
        BurstObservation,
        DemandQueues,
        SolverProcess,
        queue_rates,
        validate_profile,
    )
except (ImportError, ValueError, SystemError):
    from online_planner import (
        BurstObservation,
        DemandQueues,
        SolverProcess,
        queue_rates,
        validate_profile,
    )

LOG = logging.getLogger("rubato.aligned")


class AlignedRuntime(object):
    def __init__(self, controller):
        self.c = controller
        self.cfg = controller.config["online_dbsp"]
        self.mode = self.cfg.get("mode", "rubato")
        if self.mode not in ("rubato", "no_control", "classify_only", "static"):
            raise ValueError("invalid online_dbsp.mode")
        if self.cfg.get("pd_ecn_enabled") or self.cfg.get("pecn_enabled"):
            raise ValueError("PD-ECN is not part of this implementation")
        if int(controller.config.get("cms_depth", 1024)) != 1024:
            raise ValueError("compiled P4 CMS depth is 1024; rebuild P4 before changing it")
        window = float(controller.config.get("behavior", {}).get("window_seconds", 0.5))
        if window != 0.5 or float(controller.config.get("sample_interval_s", 0.5)) != window:
            raise ValueError("online profiles and classifier require matching 0.5s windows")
        self.root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(self.root, self.cfg["profiles_file"])) as handle:
            document = json.load(handle)
        if document["schema"] != "rubato_platform_p95_v1":
            raise ValueError("unsupported platform profile schema")
        self.profiles = document["platforms"]
        for p in self.profiles.values():
            validate_profile(p)
        self.platform_names = {v: k for k, v in controller.config["platform_ids"].items()}
        self.solver = SolverProcess(
            os.path.join(self.root, self.cfg["solver_path"]),
            float(self.cfg.get("solve_timeout_s", 2.0)),
        )
        self.logical_flows = self.cfg.get("logical_video_flows", {})
        validate_logical_flows(self.logical_flows)
        count = int(self.cfg["video_queues"])
        self.cfg["video_queues"] = count
        self.dqa = DemandQueues(count, None if self.c.args.dry_run else self.solver)
        self.physical_queue_count = int(self.cfg.get("physical_queue_count", count + 1))
        minimum_physical_queues = 1 if self.mode == "no_control" else 2
        if not minimum_physical_queues <= self.physical_queue_count <= count + 1:
            raise ValueError("physical_queue_count must include q0 and fit the logical queue pool")
        self.video_queue_weighting = self.cfg.get("video_queue_weighting", "equal")
        if self.video_queue_weighting not in ("static_equal", "equal", "demand"):
            raise ValueError("invalid video_queue_weighting")
        self.static_video_weights = (
            {}
            if self.physical_queue_count == 1
            else equal_quanta(
                int(self.cfg.get("video_pool_dwrr_weight", 700)), self.physical_queue_count - 1
            )
        )
        self.logical_observations = {ip: BurstObservation() for ip in self.logical_flows}
        self.logical_pending = {}
        self.identity_reservations = {}
        if self.logical_flows and self.mode not in ("no_control", "classify_only"):
            self.dqa.initialize(
                {int(spec["id"]): float(spec["demand_bps"]) for spec in self.logical_flows.values()}
            )
        self.observations = {}
        self.video_mapping = {}
        self.ids = {}
        self.next_id = 1 + max([int(s["id"]) for s in self.logical_flows.values()] or [0])
        self.applied = {}
        self.fallback_flows = set()
        self.version = 0
        self.last_good = 0.0
        self.safety_bypass = False
        self.prepared = False
        self.last_epoch = None
        self.last_signature = None
        self.realized_rates = {}
        self.references = {}
        self.realized_weights = {q: 100 for q in range(1, self.physical_queue_count)}
        self.apply_deadline = 0.0
        self.watchdog_generation = None
        self.coverage = {
            "observed_bytes": 0,
            "confirmed_bytes": 0,
            "assigned_bytes": 0,
            "shaping_assigned_bytes": 0,
        }
        self.smoothed_ids = set()
        self.original_port_buffer_cells = None
        self.last_egress_sample = None
        self.egress_residence_reset_verified = False
        self.shaping_gate_state = None

    def shaping_allowed(self, now):
        """Fail closed until the trial supplies its TF2-clock activation deadline."""
        delay = float(self.cfg.get("shaping_start_delay_s", 0))
        if self.mode != "rubato" or delay <= 0:
            return True
        path = self.cfg.get("shaping_activation_file")
        activation = None
        if path:
            try:
                with open(os.path.join(self.root, path)) as handle:
                    activation = json.load(handle)
            except (IOError, OSError, ValueError):
                activation = None
        try:
            start = float(activation.get("shaping_start_unix"))
            valid = (
                activation.get("schema") == "rubato_shaping_activation_v1"
                and float(activation.get("delay_seconds")) == delay
                and math.isfinite(start)
            )
        except (AttributeError, TypeError, ValueError):
            start, valid = None, False
        allowed = valid and now >= start
        state = "active" if allowed else "warmup"
        if state != self.shaping_gate_state:
            self.shaping_gate_state = state
            self.audit(
                "shaping_gate",
                state=state,
                delay_seconds=delay,
                shaping_start_unix=(activation or {}).get("shaping_start_unix"),
                schedule_valid=valid,
            )
        return allowed

    def identity_qid(self, ip):
        if self.mode == "no_control":
            return 0
        # DQA isolation is initialized before traffic.  Only maximum-rate
        # shaping is delayed; this avoids a live q0 -> video-queue migration.
        if self.mode == "classify_only":
            return 1  # ns-3's explicit classify-only comparator, never Rubato.
        if ip in self.logical_flows:
            return self.dqa.mapping[int(self.logical_flows[ip]["id"])]
        if ip not in self.identity_reservations:
            # Unknown deployment endpoints reserve a DQA slot immediately. They
            # are not silently treated as 100G sources or admitted to shaping.
            existing = [fid for flow, fid in self.ids.items() if flow.src_ip == ip]
            fid = min(existing) if existing else self.next_id
            if not existing:
                self.next_id += 1
            demands = {f: 1.0 for f in self.dqa.mapping}
            demands.update(
                {int(s["id"]): float(s["demand_bps"]) for s in self.logical_flows.values()}
            )
            demands[fid] = float(self.cfg.get("source_access_rates_bps", {}).get(ip, 1.0))
            self.dqa.allocate(demands)
            self.identity_reservations[ip] = fid
            if self.prepared and not self.c.args.dry_run:
                q = self.tm_qid(self.dqa.mapping[fid])
                self.c.tm_client.tm_disable_q_max_shaping_rate(
                    self.c.device_id(), int(self.cfg["dev_port"]), q
                )
                self.c.tm_client.tm_complete_operations(self.c.device_id())
                self.realized_rates.pop(q, None)
                self.last_signature = None
        return self.dqa.mapping[self.identity_reservations[ip]]

    def admit(self, flow):
        """First connection inherits the already accounted logical-flow DQA map."""
        if flow in self.video_mapping:
            return self.video_mapping[flow]
        qid = self.identity_qid(flow.src_ip)
        if flow.src_ip in self.logical_flows:
            self.ids[flow] = int(self.logical_flows[flow.src_ip]["id"])
        if flow.src_ip not in self.logical_flows and self.mode not in (
            "no_control",
            "classify_only",
        ):
            if flow not in self.ids:
                reserved = self.identity_reservations[flow.src_ip]
                self.ids[flow] = reserved if reserved not in self.ids.values() else self.next_id
                if self.ids[flow] == self.next_id:
                    self.next_id += 1
            demands = {fid: 1.0 for fid in self.dqa.mapping}
            demands.update(
                {int(s["id"]): float(s["demand_bps"]) for s in self.logical_flows.values()}
            )
            demands[self.ids[flow]] = float(
                self.cfg.get("source_access_rates_bps", {}).get(flow.src_ip, 1.0)
            )
            qid = self.dqa.allocate(demands)[self.ids[flow]]
            # A newly admitted, unmeasured member must not inherit another
            # member's old aggregate ceiling. The next epoch supplies its rate.
            if not self.c.args.dry_run:
                self.c.connect_tm()
                self.c.tm_client.tm_disable_q_max_shaping_rate(
                    self.c.device_id(), int(self.cfg["dev_port"]), self.tm_qid(qid)
                )
                self.c.tm_client.tm_complete_operations(self.c.device_id())
            self.realized_rates.pop(self.tm_qid(qid), None)
            self.last_signature = None
        self.c.install_flow_policy(flow, qid, self.version, self.c.candidates[flow].platform_id)
        self.video_mapping[flow] = qid
        if flow.src_ip in self.logical_flows and self.tm_qid(qid) in self.realized_rates:
            self.applied[flow] = qid
        return qid

    def flush_observations(self):
        for ip, sample in self.logical_pending.items():
            self.logical_observations[ip].observe(
                sample["bytes"], sample["start"], sample["end"], self.c.config.get("behavior", {})
            )
        self.logical_pending.clear()

    def recovery_path(self):
        return os.path.join(
            self.root,
            self.cfg.get("watchdog_recovery_file", self.cfg["heartbeat_file"] + ".recovery"),
        )

    def read_recovery(self):
        try:
            with open(self.recovery_path()) as handle:
                recovery = json.load(handle)
            return recovery if recovery.get("parent_pid") == os.getpid() else {}
        except FileNotFoundError:
            return {}

    def reconcile_recovery(self):
        recovery = self.read_recovery()
        if recovery.get("state") == "releasing":
            raise RuntimeError("watchdog_release_in_progress")
        generation = recovery.get("generation")
        if generation != self.watchdog_generation:
            self.watchdog_generation = generation
            self.release("watchdog_generation_changed")

    def static_rate(self, flow):
        configured = self.cfg.get("static_rates_bps", {}).get(flow.src_ip)
        if configured is None:
            return None
        rate = float(configured)
        if not math.isfinite(rate) or rate <= 0:
            raise ValueError("invalid static_rates_bps")
        return rate

    def baseline_descriptor(self, observation, now, ttl):
        recent = observation.completed[-3:]
        if len(recent) < 3 or now - observation.last_complete > ttl:
            return None, "insufficient_or_stale_bursts"
        span = recent[-1][0] - recent[0][0]
        if span <= 0:
            return None, "invalid_observation_span"
        return {"demand_bps": sum(b[2] for b in recent[1:]) * 8.0 / span}, "confirmed"

    def profile(self, platform_id):
        return self.profiles.get(self.platform_names.get(platform_id))

    def tm_qid(self, logical_qid):
        """Map 128 ingress qids onto q0 plus the carved physical video queues."""
        qid = int(logical_qid)
        return (
            0
            if qid == 0 or self.physical_queue_count == 1
            else 1 + (qid - 1) % (self.physical_queue_count - 1)
        )

    def observed_queue_ids(self):
        """Read active physical queues only; logical q1-q127 remain available."""
        queues = {0}
        queues.update(self.tm_qid(q) for q in self.dqa.mapping.values())
        queues.update(self.tm_qid(q) for q in self.video_mapping.values())
        queues.update(int(q) for q in self.realized_rates)
        return sorted(q for q in queues if 0 <= q < self.physical_queue_count)

    def telemetry_queue_ids(self):
        maximum = int(self.cfg.get("telemetry_queue_max", self.dqa.count))
        return [q for q in self.observed_queue_ids() if q <= maximum]

    def observe(self, state, value, start, end):
        flow = state.flow
        sample_file = self.cfg.get("observation_samples_file")
        if sample_file:
            path = os.path.join(self.root, sample_file)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "a") as handle:
                handle.write(
                    json.dumps(
                        dict(
                            flow=flow._asdict(),
                            bytes=value,
                            start=start,
                            end=end,
                            confirmed=flow in self.c.confirmed_flows,
                            assigned=flow in self.applied,
                        ),
                        sort_keys=True,
                    )
                    + "\n"
                )
        if flow not in self.observations:
            self.observations[flow] = BurstObservation()
            self.observations[flow].last_activity = end
            if flow.src_ip in self.logical_flows:
                self.ids[flow] = int(self.logical_flows[flow.src_ip]["id"])
            else:
                if flow not in self.ids:
                    self.ids[flow] = self.next_id
                    self.next_id += 1
        profile = self.profile(state.platform_id)
        self.observations[flow].observe(
            value,
            start,
            end,
            self.c.config.get("behavior", {}),
            profile["burst_p95_bytes"] if profile else None,
        )
        if flow.src_ip in self.logical_flows:
            previous = self.logical_pending.get(flow.src_ip)
            if previous and (previous["start"], previous["end"]) != (start, end):
                self.logical_observations[flow.src_ip].observe(
                    previous["bytes"],
                    previous["start"],
                    previous["end"],
                    self.c.config.get("behavior", {}),
                )
                previous = None
            if previous is None:
                self.logical_pending[flow.src_ip] = dict(bytes=value, start=start, end=end)
            else:
                previous["bytes"] = (
                    None
                    if value is None or previous["bytes"] is None
                    else previous["bytes"] + value
                )
        if value is not None:
            self.coverage["observed_bytes"] += value
            if flow in self.c.confirmed_flows:
                self.coverage["confirmed_bytes"] += value
            if flow in self.applied:
                self.coverage["assigned_bytes"] += value
                if self.ids[flow] in self.smoothed_ids:
                    self.coverage["shaping_assigned_bytes"] += value

    def audit(self, event, **values):
        path = os.path.join(self.root, self.cfg["audit_file"])
        os.makedirs(os.path.dirname(path), exist_ok=True)
        values.update(event=event, timestamp=time.time(), version=self.version, mode=self.mode)
        with open(path, "a") as handle:
            handle.write(json.dumps(values, sort_keys=True) + "\n")

    def prepare(self):
        if self.prepared:
            return
        if self.c.hardware_policy is not None or self.c.tm_backend() != "thrift":
            raise ValueError("online DBSP requires Thrift and excludes legacy --policy")
        if self.c.args.dry_run:
            self.prepared = True
            return
        self.c.connect_tm()
        tm, dev, port = self.c.tm_client, self.c.device_id(), int(self.cfg["dev_port"])
        port_table = self.c.bfrt_info.table_get("$PORT")
        port_key = port_table.make_key([self.c.gc.KeyTuple("$DEV_PORT", port)])
        port_data = next(port_table.entry_get(self.c.target, [port_key], {"from_hw": True}))[
            0
        ].to_dict()
        if (
            port_data.get("$SPEED") != "BF_SPEED_100G"
            or not 0 < float(self.cfg["capacity_bps"]) <= 100e9
        ):
            raise ValueError("capacity must fit the configured physical 100G port")
        ingress_qids = int(self.c.config.get("tm", {}).get("queues_per_port_group", 128))
        if self.dqa.count + 1 > ingress_qids or self.physical_queue_count > ingress_qids:
            raise ValueError("requested queues exceed the configured port-group queue count")
        desired_mapping = [self.tm_qid(q) for q in range(ingress_qids)]
        before_mapping = list(tm.tm_get_port_q_mapping_adv(dev, port, ingress_qids))
        if before_mapping != desired_mapping:
            # Tofino2 defaults to fewer queues per port. P4 qid values above
            # that count otherwise alias modulo q_count instead of naming
            # distinct TM queues.
            tm.tm_set_port_q_mapping_adv(dev, port, self.physical_queue_count, desired_mapping)
            tm.tm_complete_operations(dev)
        after_mapping = list(tm.tm_get_port_q_mapping_adv(dev, port, ingress_qids))
        if after_mapping != desired_mapping:
            raise RuntimeError("port queue carving readback mismatch")
        self.audit(
            "port_queue_mapping",
            dev_port=port,
            before_distinct_queues=len(set(before_mapping)),
            before_mapping=before_mapping,
            physical_count=self.physical_queue_count,
            logical_count=self.dqa.count + 1,
            mapping=after_mapping,
        )
        pool = tm.tm_get_app_pool_size(dev, 4)  # BF_TM_EG_APP_POOL_0, SDE enum.
        if float(self.cfg["buffer_bytes"]) > pool * int(self.cfg["cell_size_bytes"]):
            raise ValueError("planning buffer exceeds physical egress pool")
        if self.cfg.get("shared_buffer_bytes") is not None:
            cells = int(
                math.ceil(float(self.cfg["shared_buffer_bytes"]) / int(self.cfg["cell_size_bytes"]))
            )
            self.original_port_buffer_cells = int(tm.tm_get_egress_port_drop_limit(dev, port))
            self.audit(
                "port_buffer_before", cells=self.original_port_buffer_cells, requested_cells=cells
            )
            tm.tm_set_egress_port_drop_limit(dev, port, cells)
            tm.tm_complete_operations(dev)
            actual_cells = int(tm.tm_get_egress_port_drop_limit(dev, port))
            if actual_cells != cells:
                raise RuntimeError("shared egress buffer limit readback mismatch")
            self.audit(
                "port_buffer_applied",
                cells=actual_cells,
                bytes=actual_cells * int(self.cfg["cell_size_bytes"]),
            )
        weights = self.static_video_weights
        sensitive_priority = 7 if self.cfg.get("sensitive_q_high_priority", False) else 0
        for q in range(self.physical_queue_count):
            tm.tm_enable_q_sched(dev, port, q)
            tm.tm_disable_q_min_shaping_rate(dev, port, q)
            tm.tm_disable_q_max_shaping_rate(dev, port, q)
            priority = sensitive_priority if q == 0 else 0
            tm.tm_set_q_sched_priority(dev, port, q, priority)
            tm.tm_set_q_remaining_bw_sched_priority(dev, port, q, priority)
            total_weight = int(self.cfg.get("video_pool_dwrr_weight", 700))
            default_weight = int(self.cfg.get("default_queue_dwrr_weight", 700))
            video_weight = weights.get(q, 1)
            if self.mode == "classify_only":
                video_weight = total_weight - self.physical_queue_count + 2 if q == 1 else 1
            tm.tm_set_q_dwrr_weight(dev, port, q, default_weight if q == 0 else video_weight)
            if q:
                self.realized_weights[q] = video_weight
                # Static queue ceiling; leave shared pool size and q0 untouched.
                # 9 is BF_TM_Q_BAF_DISABLE in the installed SDE 9.7 header.
                tm.tm_set_q_app_pool_usage(
                    dev, port, q, 4, int(self.cfg["queue_limit_cells"]), 9, 32
                )
        tm.tm_complete_operations(dev)
        for q in range(self.physical_queue_count):
            expected_priority = sensitive_priority if q == 0 else 0
            sched = self.c.queue_scheduler_read(port, q)
            if (
                not bool(sched["scheduling_enable"])
                or tm.tm_get_q_sched_priority(dev, port, q) != expected_priority
                or tm.tm_get_q_remaining_bw_sched_priority(dev, port, q) != expected_priority
            ):
                raise RuntimeError("queue priority readback mismatch")
            if q:
                usage = tm.tm_get_q_app_pool_usage(dev, port, q)
                if (
                    usage.base_use_limit < int(self.cfg["queue_limit_cells"])
                    or usage.dynamic_baf != 9
                ):
                    raise RuntimeError("queue ceiling readback mismatch")
        self.prepared = True
        if self.cfg.get("egress_observation", False):
            self.egress_residence_reset_verified = all(
                self.c.register_write("queue_residence_max", q * 512 + port, 0)
                for q in self.telemetry_queue_ids()
            )
        self.audit(
            "prepared",
            dev_port=port,
            queues=self.dqa.count,
            sensitive_q=0,
            sensitive_priority=sensitive_priority,
            logical_video_q_min=1,
            logical_video_q_max=self.dqa.count,
            physical_video_q_min=1,
            physical_video_q_max=self.physical_queue_count - 1,
            video_priority=0,
        )

    def egress_observation(self, now):
        """ASIC egress counters, not ingress-as-output or silently zero-filled reads."""
        if self.c.args.dry_run or not self.cfg.get("egress_observation", False):
            return
        port, pipe = int(self.cfg["dev_port"]), int(self.cfg["pipe"])
        fields = ("video_egress_bytes", "queue_egress_packets", "queue_residence_max")
        rows = {q: {} for q in self.telemetry_queue_ids()}
        for name in fields:
            table = self.c.table(name)
            keys = [
                table.make_key([self.c.gc.KeyTuple("$REGISTER_INDEX", q * 512 + port)])
                for q in rows
            ]
            for data, key in table.entry_get(self.c.target, keys, {"from_hw": True}):
                index = key.to_dict()["$REGISTER_INDEX"]
                if isinstance(index, dict):
                    index = index["value"]
                q = (int(index) - port) // 512
                values = data.to_dict()[self.c.register_field(name)]
                rows[q][name] = int(values[pipe] if isinstance(values, list) else values)
        if any(len(row) != len(fields) for row in rows.values()):
            raise RuntimeError("incomplete ASIC egress counter read")
        previous = self.last_egress_sample
        self.last_egress_sample = (now, rows)
        rates = None
        if previous and now > previous[0]:
            rates = {
                q: ((rows[q]["video_egress_bytes"] - previous[1][q]["video_egress_bytes"]) % 2**32)
                * 8.0
                / (now - previous[0])
                for q in rows
            }
        self.audit(
            "egress_observation",
            queues=rows,
            interval_rate_bps=rates,
            residence_reset_verified=self.egress_residence_reset_verified,
            semantics="32-bit ASIC counters, per-pipe read; residence max is cumulative raw deq_timedelta, not FCT or a percentile",
            window_start=previous[0] if previous else None,
            window_end=now,
        )

    def release(self, reason):
        """Withdraw rate limits only. Identity, routing and observations survive."""
        if not self.c.args.dry_run:
            self.c.connect_tm()
            for q in range(1, self.physical_queue_count):
                self.c.tm_client.tm_disable_q_max_shaping_rate(
                    self.c.device_id(), int(self.cfg["dev_port"]), q
                )
            self.c.tm_client.tm_complete_operations(self.c.device_id())
            for q in range(1, self.physical_queue_count):
                if self.c.queue_scheduler_read(int(self.cfg["dev_port"]), q)["max_rate_enable"]:
                    raise RuntimeError("shaping release readback failed")
        self.applied.clear()
        self.smoothed_ids.clear()
        self.fallback_flows = {flow for flow in self.c.confirmed_flows if flow in self.c.candidates}
        self.last_good = 0.0
        self.last_signature = None
        self.realized_rates = {}
        self.audit("shaping_disabled", reason=reason, classification_preserved=True)
        self.heartbeat(time.time())

    def restore_port_buffer(self):
        if self.original_port_buffer_cells is None or self.c.args.dry_run:
            return
        tm, dev, port = self.c.tm_client, self.c.device_id(), int(self.cfg["dev_port"])
        tm.tm_set_egress_port_drop_limit(dev, port, self.original_port_buffer_cells)
        tm.tm_complete_operations(dev)
        if int(tm.tm_get_egress_port_drop_limit(dev, port)) != self.original_port_buffer_cells:
            raise RuntimeError("original port buffer restoration failed")
        self.audit("port_buffer_restored", cells=self.original_port_buffer_cells)
        self.original_port_buffer_cells = None

    def maintain_video_isolation(self, reason):
        """Keep video routing stable when the rate planner has no valid plan."""
        targets = {
            flow
            for flow in self.c.confirmed_flows
            if flow in self.observations and flow in self.c.candidates
        }
        if not targets:
            self.release(reason)
            return
        changed = bool(self.applied) or targets != self.fallback_flows
        if not changed:
            self.heartbeat(time.time())
            return
        self.release(reason)
        for flow in targets:
            self.admit(flow)
        self.fallback_flows = targets
        self.audit("video_isolation", reason=reason, isolated_flows=len(targets), shaping=False)
        self.heartbeat(time.time())

    def reset_reference(self, flow):
        self.references.pop(flow, None)
        self.video_mapping.pop(flow, None)

    def migration_ready(self, flow):
        """A flow already isolated is stable; a q0 flow moves only while idle."""
        if self.tm_qid(self.video_mapping.get(flow, 0)) != 0:
            return True
        observation = self.observations.get(flow)
        return observation is not None and observation.start is None

    def occupancy(self):
        if self.c.args.dry_run:
            return {q: 0 for q in self.observed_queue_ids()}
        return {
            q: self.c.tm_q_count_cells(int(self.cfg["dev_port"]), q, self.cfg)
            for q in self.observed_queue_ids()
        }

    def require_fresh_apply(self):
        if time.monotonic() > self.apply_deadline or time.time() - self.last_epoch > float(
            self.cfg["plan_ttl_s"]
        ):
            raise RuntimeError("plan application exceeded its observation/lease deadline")
        recovery = self.read_recovery()
        if (
            recovery.get("state") == "releasing"
            or recovery.get("generation") != self.watchdog_generation
        ):
            raise RuntimeError("watchdog_generation_changed_during_apply")

    def tick(self, now=None):
        now = time.time() if now is None else now
        try:
            self.prepare()
            self.flush_observations()
            for flow in sorted(self.c.confirmed_flows):
                if flow in self.c.candidates and flow not in self.video_mapping:
                    self.admit(flow)
            self.reconcile_recovery()
            usage = self.occupancy()
            try:
                self.egress_observation(now)
            except Exception as exc:
                self.audit("egress_observation_error", error=str(exc))
            self.audit(
                "coverage",
                counters=dict(self.coverage),
                observed_flows=len(self.observations),
                confirmed_flows=len(self.c.confirmed_flows),
                assigned_flows=len(self.applied),
                occupancy_cells=usage,
                semantics="CMS estimates assigned under last readback; not packet-ground-truth",
            )
            limit = float(self.cfg.get("shared_buffer_bytes", self.cfg["buffer_bytes"]))
            peak = sum(usage.values()) * int(self.cfg["cell_size_bytes"]) / limit
            if self.cfg.get("safety_release_enabled", False) and peak >= 0.8:
                self.safety_bypass = True
            elif not self.cfg.get("safety_release_enabled", False) or peak <= 0.6:
                self.safety_bypass = False
            if self.safety_bypass:
                self.release("queue_high_watermark")
                return
            if not self.shaping_allowed(now):
                # All admitted traffic stays in q0 during warm-up.  The first
                # feasible post-warm-up plan migrates confirmed video flows.
                self.maintain_video_isolation("shaping_warmup")
                return
            if self.last_epoch is None or now - self.last_epoch > float(self.cfg["plan_ttl_s"]):
                self.release("stale_observation_epoch")
                return
            if self.mode == "classify_only":
                # Classification is persistent and independent of DBSP.
                self.maintain_video_isolation("classify_only")
                self.audit("observation", reasons={"comparator": "persistent_video_isolation"})
                return
            flows, keys, reasons = {}, {}, {}
            unmodeled_queues = set()
            ttl = float(self.cfg["observation_ttl_s"])
            if self.mode != "no_control":
                for ip, spec in self.logical_flows.items():
                    fid = int(spec["id"])
                    members = [
                        f
                        for f in self.c.confirmed_flows
                        if f.src_ip == ip and f in self.c.candidates and self.migration_ready(f)
                    ]
                    profile = spec.get("profile") or self.profile(int(spec["platform_id"]))
                    desc, reason = self.logical_observations[ip].descriptor(
                        profile, now, ttl, envelope=spec
                    )
                    if self.mode == "static":
                        rate = self.cfg.get("static_rates_bps", {}).get(ip)
                        if rate is None:
                            raise ValueError("missing static rate for " + ip)
                        desc["static_rate_bps"] = float(rate)
                    flows[fid], keys[fid], reasons[str(fid)] = desc, members, reason
            for flow, observation in list(self.observations.items()):
                if now - observation.last_activity > float(self.cfg["flow_idle_s"]):
                    # Retire connection measurements only. The source IP's
                    # persistent identity handles its next packet/connection.
                    self.c.delete_flow_policy(flow)
                    self.c.confirmed_flows.discard(flow)
                    self.c.candidates.pop(flow, None)
                    self.observations.pop(flow, None)
                    self.reset_reference(flow)
                    if (
                        flow.src_ip not in self.logical_flows
                        and self.ids.get(flow) not in self.identity_reservations.values()
                    ):
                        self.dqa.mapping.pop(self.ids.get(flow), None)
                    self.applied.pop(flow, None)
                    self.fallback_flows.discard(flow)
                    self.ids.pop(flow, None)
                    continue
                state = self.c.candidates.get(flow)
                if flow not in self.c.confirmed_flows or state is None:
                    continue
                if flow.src_ip in self.logical_flows:
                    continue
                if self.mode == "no_control":
                    reasons[str(self.ids[flow])] = "no_control"
                    continue
                if self.mode == "rubato":
                    profile = self.profile(state.platform_id)
                    envelope = self.cfg.get("arrival_envelopes", {}).get(flow.src_ip, {})
                    envelope = dict(envelope)
                    envelope.setdefault(
                        "source_access_bps",
                        self.cfg.get("source_access_rates_bps", {}).get(flow.src_ip),
                    )
                    if not any(
                        envelope.get(k)
                        for k in ("source_access_bps", "enforced_peak_bps", "physical_peak_bps")
                    ):
                        reasons[str(self.ids[flow])] = "missing_explicit_source_access_rate"
                        unmodeled_queues.add(self.tm_qid(self.video_mapping[flow]))
                        continue
                    desc, reason = observation.descriptor(
                        profile, now, ttl, self.references.get(flow), envelope
                    )
                else:
                    desc, reason = self.baseline_descriptor(observation, now, ttl)
                    if desc is not None and self.mode == "static":
                        rate = self.static_rate(flow)
                        if rate is None:
                            desc, reason = None, "missing_static_rate"
                        else:
                            desc["static_rate_bps"] = rate
                reasons[str(self.ids[flow])] = reason
                if desc is not None:
                    fid = self.ids[flow]
                    flows[fid], keys[fid] = desc, [flow]
            keys = {
                fid: [flow for flow in members if flow in self.c.candidates]
                for fid, members in keys.items()
            }
            if not flows:
                if self.mode != "no_control":
                    self.maintain_video_isolation("no_eligible_flows")
                elif self.applied or self.fallback_flows:
                    self.release("no_eligible_flows")
                self.audit("observation", reasons=reasons)
                self.heartbeat(now)
                return
            retained = set(flows).intersection(self.dqa.mapping)
            retained_queues = {
                self.tm_qid(self.dqa.mapping[f]) for f in retained if f in self.dqa.mapping
            }
            unavailable_tm = {q for q, cells in usage.items() if cells and q not in retained_queues}
            unavailable = {
                q for q in range(1, self.dqa.count + 1) if self.tm_qid(q) in unavailable_tm
            }
            configured_pool = int(self.cfg.get("video_pool_dwrr_weight", 700))
            planned_mapping = self.dqa.allocate(
                {f: d["demand_bps"] for f, d in flows.items()}, unavailable, commit=False
            )
            capacity = float(self.cfg["capacity_bps"])
            occupied_bytes = sum(usage.values()) * int(self.cfg["cell_size_bytes"])
            buffer_bytes = float(self.cfg["buffer_bytes"])
            decision_inputs = {
                fid: {
                    k: d.get(k)
                    for k in ("burst_bits", "period_s", "on_s", "max_delay_s", "static_rate_bps")
                }
                for fid, d in flows.items()
            }
            for fid, desc in flows.items():
                decision_inputs[fid]["weight"] = desc.get("profile", {}).get("weight", 1)
                if self.cfg.get("video_queue_weighting", "equal") == "demand":
                    decision_inputs[fid]["demand_bps"] = desc["demand_bps"]
            signature = json.dumps(
                {
                    "flows": decision_inputs,
                    "capacity": capacity,
                    "buffer": buffer_bytes,
                    "mapping": planned_mapping,
                    "unmodeled_queues": sorted(unmodeled_queues),
                    "boundary_ready_members": {
                        fid: [flow._asdict() for flow in sorted(members)]
                        for fid, members in keys.items()
                    },
                    "mode": self.mode,
                },
                sort_keys=True,
                allow_nan=False,
            )
            if signature == self.last_signature:
                self.heartbeat(now)
                return
            self.version = (self.version + 1) % 65536
            self.heartbeat(time.time())
            self.apply_deadline = time.monotonic() + max(0.1, float(self.cfg["plan_ttl_s"]) - 0.5)
            if self.mode == "rubato":
                result = self.solver.solve(flows, capacity, buffer_bytes, self.version)
                overload = float(result.get("overload_bps", float("inf")))
                tolerance = float(self.cfg.get("residual_overload_tolerance_bps", 1.0))
                if not math.isfinite(overload) or overload > tolerance:
                    raise RuntimeError("infeasible_dbsp_residual_overload_bps={}".format(overload))
            else:
                result = {
                    "overload_bps": 0,
                    "flows": [
                        {"id": fid, "rate_bps": desc.get("static_rate_bps", 0), "backlog_bits": 0}
                        for fid, desc in flows.items()
                    ],
                }
            # Formerly occupied empty queues are not re-leased until drained.
            mapping = planned_mapping
            logical_rates = queue_rates(result, mapping)
            rates = {}
            for logical_q, rate in logical_rates.items():
                physical_q = self.tm_qid(logical_q)
                rates[physical_q] = rates.get(physical_q, 0) + rate
            for q in unmodeled_queues:
                rates.pop(q, None)
            advisory_only = bool(self.cfg.get("zero_delay_advisory_only", False)) and all(
                desc.get("max_delay_s", 0) <= 0 for desc in flows.values()
            )
            if advisory_only:
                # Source pacing already enforces the solver's zero-delay rate.
                # A second equal-rate token bucket changes TCP burst timing but
                # provides no additional DBSP smoothing guarantee.
                rates = {}
            port_kbps = int(float(self.cfg.get("nominal_port_capacity_bps", 100e9)) / 1000)
            programmed_rates = {q: min(rate, port_kbps) for q, rate in rates.items()}
            rounding_tolerance = 1000.0 * max(1, len(programmed_rates))
            if sum(programmed_rates.values()) * 1000.0 > capacity + rounding_tolerance:
                raise RuntimeError("programmed_video_rates_exceed_capacity")
            active = sorted(rates)
            demand = {}
            if self.video_queue_weighting == "static_equal":
                weights = {q: self.static_video_weights[q] for q in active}
            elif configured_pool > 1023:
                # A single Tofino queue weight is 10 bits. Preserve the full
                # configured pool by spreading oversized totals over all
                # carved video queues.
                weights = equal_quanta(configured_pool, self.physical_queue_count - 1)
            elif self.video_queue_weighting == "demand":
                for fid, desc in flows.items():
                    q = self.tm_qid(mapping[fid])
                    demand[q] = demand.get(q, 0) + desc["demand_bps"]
                weights = demand_quanta(demand, configured_pool, self.solver)
            else:
                logical_weights = equal_quanta(configured_pool, len(flows))
                weights = {}
                for slot, fid in enumerate(sorted(flows), 1):
                    q = self.tm_qid(mapping[fid])
                    weights[q] = weights.get(q, 0) + logical_weights[slot]
            # Readbacks first; mappings last. Never disable a live queue scheduler.
            actual = {}
            for q in active:
                self.require_fresh_apply()
                settings = dict(
                    self.cfg, max_burst_size=burst_bytes(programmed_rates[q] * 1000, self.cfg)
                )
                if (
                    self.realized_rates.get(q) != programmed_rates[q]
                    or self.realized_weights.get(q) != weights[q]
                ):
                    self.c.configure_tm_queue_thrift(
                        int(self.cfg["dev_port"]), q, programmed_rates[q], settings, weights[q]
                    )
                if not self.c.args.dry_run:
                    actual[q] = self.c.tm_q_shaping_rate_kbps(int(self.cfg["dev_port"]), q)
                    # RATE_UPPER can still quantize just below the requested
                    # value on this SDK. Retry upward while retaining the
                    # conservative readback requirement.
                    for attempt in range(1, 4):
                        if actual[q] is None or actual[q] >= programmed_rates[q]:
                            break
                        requested = programmed_rates[q] + attempt * max(
                            1, int(math.ceil(programmed_rates[q] * 0.001))
                        )
                        self.audit(
                            "rate_quantization_retry",
                            queue=q,
                            minimum_kbps=programmed_rates[q],
                            previous_actual_kbps=actual[q],
                            requested_kbps=requested,
                        )
                        self.c.configure_tm_queue_thrift(
                            int(self.cfg["dev_port"]), q, requested, settings, weights[q]
                        )
                        actual[q] = self.c.tm_q_shaping_rate_kbps(int(self.cfg["dev_port"]), q)
                    weight = self.c.tm_client.tm_get_q_dwrr_weight(
                        self.c.device_id(), int(self.cfg["dev_port"]), q
                    )
                    sched = self.c.queue_scheduler_read(int(self.cfg["dev_port"]), q)
                    shaping = self.mode != "classify_only"
                    if (
                        weight != weights[q]
                        or bool(sched["max_rate_enable"]) != shaping
                        or (shaping and (actual[q] is None or actual[q] < programmed_rates[q]))
                    ):
                        raise RuntimeError(
                            "TM readback mismatch q={} requested={} actual={} weight={}/{} enabled={}/{}".format(
                                q,
                                programmed_rates[q],
                                actual[q],
                                weight,
                                weights[q],
                                sched["max_rate_enable"],
                                shaping,
                            )
                        )
            for flow in list(self.applied):
                if not any(flow in members for members in keys.values()):
                    del self.applied[flow]
            for fid, members in keys.items():
                for flow in members:
                    self.require_fresh_apply()
                    if self.tm_qid(mapping[fid]) in rates:
                        self.applied[flow] = mapping[fid]
                    else:
                        self.applied.pop(flow, None)
                    self.video_mapping[flow] = mapping[fid]
                    self.c.install_flow_policy(
                        flow, mapping[fid], self.version, self.c.candidates[flow].platform_id
                    )
                    if (
                        self.mode == "rubato"
                        and flow.src_ip not in self.logical_flows
                        and flow not in self.references
                    ):
                        if flows[fid]["max_delay_s"] > 0:
                            self.references[flow] = {
                                "on_s": flows[fid]["on_s"],
                                "period_s": flows[fid]["period_s"],
                            }
            self.fallback_flows.clear()
            if not self.c.args.dry_run:
                for q in range(1, self.physical_queue_count):
                    if q not in active:
                        self.c.tm_client.tm_disable_q_max_shaping_rate(
                            self.c.device_id(), int(self.cfg["dev_port"]), q
                        )
                self.c.tm_client.tm_complete_operations(self.c.device_id())
            self.require_fresh_apply()
            self.last_good = now
            self.dqa.mapping.update(mapping)
            queue_peak = {}
            for fid, desc in flows.items():
                q = self.tm_qid(mapping[fid])
                queue_peak[q] = queue_peak.get(q, 0) + desc.get("peak_bps", 0)
            self.smoothed_ids = {
                item["id"]
                for item in result["flows"]
                if self.tm_qid(mapping[item["id"]]) in rates
                and (actual or programmed_rates)[self.tm_qid(mapping[item["id"]])] * 1000
                < queue_peak[self.tm_qid(mapping[item["id"]])] * (1 - 1e-9)
                and item["rate_bps"]
                < flows[item["id"]].get("peak_bps", item["rate_bps"]) * (1 - 1e-9)
            }
            self.last_signature = signature
            self.realized_rates = programmed_rates
            self.realized_weights.update(weights)
            self.audit(
                "applied",
                inputs=flows,
                result=result,
                mapping=mapping,
                physical_mapping={fid: self.tm_qid(q) for fid, q in mapping.items()},
                logical_rates_kbps=logical_rates,
                rates_kbps=rates,
                programmed_kbps=programmed_rates,
                actual_kbps=actual,
                weights=weights,
                executor_residual_overload_bps=max(
                    0, sum((actual or programmed_rates).values()) * 1000 - capacity
                ),
                occupancy_cells=usage,
                effective_capacity_bps=capacity,
                effective_lp_buffer_bytes=buffer_bytes,
                unmodeled_queues=sorted(unmodeled_queues),
                occupied_debt_bytes=occupied_bytes,
                allowance_reserved_bytes=sum(
                    d.get("reserved_buffer_bytes", 0) for d in flows.values()
                ),
                advisory_only=advisory_only,
                reasons=reasons,
            )
            self.heartbeat(time.time())
        except Exception as exc:
            LOG.exception("aligned planning failed; releasing limits")
            self.release(str(exc))
            if self.cfg.get("fail_on_infeasible_plan", False) and "infeasible_dbsp" in str(exc):
                raise

    def heartbeat(self, now):
        path = os.path.join(self.root, self.cfg["heartbeat_file"])
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path + ".tmp", "w") as handle:
            json.dump(
                {
                    "timestamp": now,
                    "monotonic": time.monotonic(),
                    "pid": os.getpid(),
                    "version": self.version,
                },
                handle,
            )
        os.replace(path + ".tmp", path)
