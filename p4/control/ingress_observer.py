"""Loss-accounted ASIC ingress learns, independent of planner execution (Python 3.5)."""

import ipaddress
import json
import os
from queue import Empty, Full, Queue
import threading
import time
import uuid


def decode_wire_entry(learn, entry, names):
    """Read primitive P4 digest streams without constructing SDK DataTuple objects."""
    row = {}
    for field in entry.fields:
        field_id = int(field.field_id)
        name = names.get(field_id)
        if name is None:
            name = learn.info.data_field_name_get(field_id)
            names[field_id] = name
        if not field.HasField("stream"):
            raise ValueError("Non-stream field in primitive wire digest: " + name)
        row[name] = int.from_bytes(field.stream, byteorder="big")
    row["action_name"] = None
    row["is_default_entry"] = False
    return row


class DigestReceiver(object):
    def __init__(self, interface, info, raw_path=None, queue_limit=16384):
        self.interface = interface
        self.learns = {}
        for kind in ("candidate", "dns", "wire_observation"):
            name = kind + "_digest"
            for candidate in ("pipe.SwitchIngressDeparser." + name, name):
                try:
                    learn = info.learn_get(candidate)
                    learn_id = int(learn.info.id_get())
                    if learn_id in self.learns:
                        raise RuntimeError("Duplicate learn ID for distinct digest types")
                    self.learns[learn_id] = (kind, learn)
                    break
                except KeyError:
                    continue
            else:
                if kind != "wire_observation" or raw_path is not None:
                    raise RuntimeError("Required learn not found: " + name)
        self.events = Queue(maxsize=queue_limit)
        self.wire_field_names = {}
        self.wire_decode_verified = False
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.stats = dict(
            batches=0,
            records=0,
            trace_records=0,
            unknown_digest=0,
            parse_errors=0,
            receive_errors=0,
            queue_overflows=0,
            write_errors=0,
            handler_errors=0,
        )
        self.totals = {}
        self.raw = None
        if raw_path:
            os.makedirs(os.path.dirname(os.path.abspath(raw_path)), exist_ok=True)
            self.raw = open(raw_path, "x", buffering=1024 * 1024)
        self.thread = threading.Thread(target=self.run, name="rubato-digest-receiver")
        self.thread.daemon = True

    def start(self):
        self.thread.start()

    def dispatch(self, digest):
        self.stats["batches"] += 1
        found = self.learns.get(int(digest.digest_id))
        if found is None:
            self.stats["unknown_digest"] += 1
            return
        kind, learn = found
        pipe = int(digest.target.pipe_id)
        if kind == "wire_observation" and all(hasattr(entry, "fields") for entry in digest.data):
            parsed = [
                decode_wire_entry(learn, entry, self.wire_field_names) for entry in digest.data
            ]
            if not self.wire_decode_verified:
                reference = [item.to_dict() for item in learn.make_data_list(digest)]
                if parsed != reference:
                    raise RuntimeError("Fast wire digest decoder disagrees with SDK parser")
                self.wire_decode_verified = True
        else:
            parsed = [item.to_dict() for item in learn.make_data_list(digest)]
        for data in parsed:
            self.stats["records"] += 1
            if kind == "wire_observation":
                requested = int(data["candidate_requested"])
                if requested not in (0, 1):
                    raise ValueError("Invalid candidate_requested bit")
                if self.raw is None:
                    self.stats["write_errors"] += 1
                else:
                    try:
                        self.raw.write(
                            json.dumps(
                                dict(kind="asic_ingress", pipe_id=pipe, data=data),
                                separators=(",", ":"),
                                allow_nan=False,
                            )
                            + "\n"
                        )
                    except Exception:
                        self.stats["write_errors"] += 1
                        raise
                key = (int(data["epoch_id"]), pipe, int(data["sampler_id"]))
                with self.lock:
                    total = self.totals.setdefault(key, {"count": 0, "bytes": 0})
                    total["count"] += 1
                    total["bytes"] += int(data["total_len"])
                    self.stats["trace_records"] += 1
                if not requested:
                    continue
                data = dict(data, ip_version=4)
                kind_for_event = "candidate"
            else:
                kind_for_event = kind
            try:
                self.events.put_nowait((kind_for_event, data))
            except Full:
                self.stats["queue_overflows"] += 1

    def run(self):
        while not self.stop_event.is_set():
            try:
                digest = self.interface.digest_get(timeout=0.1)
            except RuntimeError as exc:
                if "Digest list not received" not in str(exc):
                    self.stats["receive_errors"] += 1
                    time.sleep(0.05)
                continue
            except Exception:
                self.stats["receive_errors"] += 1
                time.sleep(0.05)
                continue
            try:
                self.dispatch(digest)
            except Exception:
                self.stats["parse_errors"] += 1

    def drain(self, candidate_handler, dns_handler, limit=1024):
        for _ in range(limit):
            try:
                kind, data = self.events.get_nowait()
            except Empty:
                return
            try:
                (candidate_handler if kind == "candidate" else dns_handler)(data)
            except Exception:
                self.stats["handler_errors"] += 1
                raise

    def count(self, key):
        with self.lock:
            return dict(self.totals.get(key, {"count": 0, "bytes": 0}))

    def stop(self):
        self.stop_event.set()
        if self.thread.ident is not None:
            self.thread.join(timeout=2)
        if self.thread.is_alive():
            raise RuntimeError("Digest receiver did not terminate")
        if self.raw is not None and not self.raw.closed:
            try:
                self.raw.flush()
                os.fsync(self.raw.fileno())
            except Exception:
                self.stats["write_errors"] += 1
                raise
            finally:
                self.raw.close()
        return dict(self.stats)


class WireObservation(object):
    def __init__(self, controller, receiver, config):
        self.c, self.receiver, self.cfg = controller, receiver, config
        self.entries = []
        self.record = {
            "schema": "rubato_asic_ingress_capture_v1",
            "epoch_id": int(config["epoch_id"]),
            "capture_id": uuid.uuid4().hex,
            "raw_file": config["raw_file"],
            "status": "initializing",
            "sources": [],
            "capture_complete_verified": False,
        }
        if not 0 < self.record["epoch_id"] < 0xFFFFFFFF:
            raise ValueError("Positive bounded epoch ID required")
        if os.path.abspath(config["raw_file"]) == os.path.abspath(config["summary_file"]):
            raise ValueError("Raw and summary paths must differ")
        used, filters = set(), set()
        if not config["sources"]:
            raise ValueError("At least one source required")
        for source in config["sources"]:
            port, slot = int(source["ingress_port"]), int(source["sampler_id"])
            address = str(ipaddress.IPv4Address(source["src_ip"]))
            if (
                not 0 <= port < 512
                or not 0 <= slot < 32
                or (port >> 7, slot) in used
                or (port, address) in filters
            ):
                raise ValueError("Unique valid sampler per pipe and exact source filter required")
            used.add((port >> 7, slot))
            filters.add((port, address))

    def target(self, port):
        return self.c.gc.Target(device_id=self.c.device_id(), pipe_id=int(port) >> 7)

    def counter(self, name, slot, port, reset=False):
        table = self.c.table(name)
        field = self.c.register_field(name)
        target = self.target(port)
        key = table.make_key([self.c.gc.KeyTuple("$REGISTER_INDEX", slot)])
        if reset:
            table.entry_mod(target, [key], [table.make_data([self.c.gc.DataTuple(field, 0)])])
        values = next(table.entry_get(target, [key], {"from_hw": True}))[0].to_dict()[field]
        if isinstance(values, list):
            if len(values) == 1:
                value = values[0]
            elif len(values) == 4:
                value = values[int(port) >> 7]
            else:
                raise RuntimeError("Ambiguous register pipe readback")
        else:
            value = values
        return int(value)

    def save(self):
        path = os.path.abspath(self.cfg["summary_file"])
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path) as handle:
            if json.load(handle).get("capture_id") != self.record["capture_id"]:
                raise RuntimeError("Summary ownership changed; refusing overwrite")
        temporary = path + "." + self.record["capture_id"] + ".tmp"
        with open(temporary, "x") as handle:
            json.dump(self.record, handle, indent=2, sort_keys=True, allow_nan=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)

    def read_entry(self, table, key):
        try:
            entries = list(table.entry_get(self.c.target, [key], {"from_hw": True}))
        except Exception as exc:
            if "not found" in str(exc).lower() or "not_found" in str(exc).lower():
                return None
            raise
        if not entries:
            return None
        if len(entries) != 1:
            raise RuntimeError("Ambiguous observation entry readback")
        return entries[0][0].to_dict()

    def disable_owned(self, table, entry):
        key, applied, port, slot = entry
        current = self.read_entry(table, key)
        if current is None:
            raise RuntimeError("Owned sampler entry disappeared before close")
        if any(int(current.get(k, -1)) != int(applied[k]) for k in ("epoch_id", "sampler_id")):
            raise RuntimeError("Sampler entry ownership changed; refusing removal")
        table.entry_del(self.c.target, [key])
        if self.read_entry(table, key) is not None:
            raise RuntimeError("Sampler disable readback failed")

    def start(self):
        try:
            return self._start()
        except Exception as exc:
            self.record.update(
                status="capture_failed", start_error=str(exc), cleanup_errors=self.cleanup_owned()
            )
            try:
                self.record["receiver"] = self.receiver.stop()
            finally:
                if os.path.exists(self.cfg["summary_file"]):
                    self.save()  # Refuses an existing summary owned by another capture.
            raise

    def cleanup_owned(self):
        errors = []
        table = self.c.table("wire_observation_filter")
        for entry in self.entries:
            try:
                if self.read_entry(table, entry[0]) is not None:
                    self.disable_owned(table, entry)
            except Exception as exc:
                errors.append(str(exc))
        return errors

    def _start(self):
        table = self.c.table("wire_observation_filter")
        # Existing observation entries may belong to another run. Never clear them implicitly.
        existing = list(table.entry_get(self.c.target, [], {"from_hw": True}))
        if existing:
            raise RuntimeError("Wire observation table is not empty")
        summary_path = os.path.abspath(self.cfg["summary_file"])
        os.makedirs(os.path.dirname(summary_path), exist_ok=True)
        with open(summary_path, "x") as handle:
            json.dump(self.record, handle)
        used = set()
        for source in self.cfg["sources"]:
            port, slot = int(source["ingress_port"]), int(source["sampler_id"])
            if not 0 <= slot < 32 or (port >> 7, slot) in used:
                raise ValueError("Unique sampler per pipe, in 0..31, required")
            used.add((port >> 7, slot))
            for name in ("wire_packet_count", "wire_ipv4_byte_count"):
                if self.counter(name, slot, port, reset=True) != 0:
                    raise RuntimeError("Sampler reset readback mismatch")
            key = table.make_key(
                [
                    self.c.gc.KeyTuple("md.ingress_port", port),
                    self.c.gc.KeyTuple(
                        "hdr.ipv4.src_addr", int(ipaddress.IPv4Address(source["src_ip"]))
                    ),
                ]
            )
            data = table.make_data(
                [
                    self.c.gc.DataTuple("epoch_id", self.record["epoch_id"]),
                    self.c.gc.DataTuple("sampler_id", slot),
                ],
                "SwitchIngress.enable_wire_observation",
            )
            # Remember the intent before a write that might partially succeed.
            self.entries.append(
                (key, {"epoch_id": self.record["epoch_id"], "sampler_id": slot}, port, slot)
            )
            table.entry_add(self.c.target, [key], [data])
            readback = next(table.entry_get(self.c.target, [key], {"from_hw": True}))[0].to_dict()
            if (
                int(readback.get("epoch_id", -1)) != self.record["epoch_id"]
                or int(readback.get("sampler_id", -1)) != slot
            ):
                raise RuntimeError("Sampler enable readback mismatch")
            self.record["sources"].append(dict(source, readback=readback))
        self.record.update(status="capturing", started_unix=time.time())
        self.save()

    def finish(self):
        try:
            return self._finish()
        except Exception as exc:
            self.record.update(
                status="capture_failed",
                close_error=str(exc),
                capture_complete_verified=False,
                finished_unix=time.time(),
                cleanup_errors=self.cleanup_owned(),
            )
            try:
                self.record["receiver"] = self.receiver.stop()
            finally:
                self.save()
            raise

    def _finish(self):
        table = self.c.table("wire_observation_filter")
        terminal = []
        for entry in self.entries:
            self.disable_owned(table, entry)
        for key, applied, port, slot in self.entries:
            previous = None
            for _ in range(5):
                values = tuple(
                    self.counter(name, slot, port)
                    for name in ("wire_packet_count", "wire_ipv4_byte_count")
                )
                if values == previous:
                    break
                previous = values
                time.sleep(0.02)
            else:
                raise RuntimeError("Sampler terminal counters are unstable")
            terminal.append(
                dict(
                    ingress_port=port,
                    pipe_id=port >> 7,
                    sampler_id=slot,
                    packet_count=values[0],
                    ipv4_byte_count=values[1],
                    disable_verified=True,
                    terminal_stable_verified=True,
                )
            )
        drain_seconds = float(self.cfg.get("drain_timeout_s", 5))
        if not 5 <= drain_seconds <= 180:
            raise ValueError("ASIC drain timeout must be 5..180 seconds")
        deadline = time.monotonic() + drain_seconds
        while time.monotonic() < deadline:
            if all(
                self.receiver.count((self.record["epoch_id"], r["pipe_id"], r["sampler_id"]))[
                    "count"
                ]
                >= r["packet_count"]
                for r in terminal
            ):
                break
            time.sleep(0.05)
        stats = self.receiver.stop()
        for row in terminal:
            row["received"] = self.receiver.count(
                (self.record["epoch_id"], row["pipe_id"], row["sampler_id"])
            )
            row["counts_match"] = row["received"] == {
                "count": row["packet_count"],
                "bytes": row["ipv4_byte_count"],
            }
        failures = [
            name
            for name, value in stats.items()
            if value
            and (name.endswith("errors") or name.endswith("overflows") or name == "unknown_digest")
        ]
        if any(not r["counts_match"] for r in terminal):
            failures.append("terminal_counts_mismatch")
        if any(
            r["packet_count"] >= 0xFFFFFFFF or r["ipv4_byte_count"] >= 0xFFFFFFFF for r in terminal
        ):
            failures.append("terminal_counter_saturated")
        self.record.update(
            status="capture_failed" if failures else "closed_pending_sequence_validation",
            terminal=terminal,
            close_failures=failures,
            receiver=stats,
            finished_unix=time.time(),
            capture_complete_verified=False,
            caveat="Matching totals alone do not prove completeness; offline sequence and timestamp validation required.",
        )
        self.save()
        return self.record
