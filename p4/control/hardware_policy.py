#!/usr/bin/env python3
"""Validation and lifecycle state for solver-generated Tofino policies."""

from __future__ import print_function

import ipaddress
import json


SCHEMA = "rubato_hardware_policy_v1"
TOFINO2_QUEUE_COUNT = 128
CONTROLLED_QID_MIN = 1
CONTROLLED_QID_MAX = TOFINO2_QUEUE_COUNT - 1
FREE = "FREE"
PREPARING = "PREPARING"
ACTIVE = "ACTIVE"
DRAINING = "DRAINING"


class PolicyError(ValueError):
    pass


class QueueLease(object):
    def __init__(
        self,
        dev_port,
        qid,
        rate_kbps,
        burst_bytes,
        flow_ids,
        phase_delay_s=0.0,
        period_s=0.0,
        window_s=0.0,
    ):
        self.dev_port = int(dev_port)
        self.qid = int(qid)
        self.rate_kbps = int(rate_kbps)
        self.burst_bytes = int(burst_bytes)
        self.flow_ids = tuple(flow_ids)
        self.phase_delay_s = float(phase_delay_s)
        self.period_s = float(period_s)
        self.window_s = float(window_s)
        self.state = PREPARING

    @property
    def telemetry_index(self):
        return self.qid * 256 + self.dev_port

    def scheduler_enabled(self, now_s, activation_epoch_s):
        if self.period_s <= 0 or self.window_s <= 0:
            return now_s >= activation_epoch_s
        elapsed = now_s - activation_epoch_s - self.phase_delay_s
        return elapsed >= 0 and (elapsed % self.period_s) < self.window_s


class HardwarePolicy(object):
    def __init__(self, data):
        if data.get("schema_version") != SCHEMA:
            raise PolicyError("unsupported hardware policy schema")
        self.group_id = str(data["group_id"])
        self.version = int(data["version"])
        self.node_id = str(data.get("node_id", ""))
        self.require_behavior_confirmation = bool(data.get("require_behavior_confirmation", True))
        self.activation_epoch_s = float(data.get("activation_epoch_s", 0.0))
        self.expires_epoch_s = float(data.get("expires_epoch_s", 0.0))
        if not self.group_id or self.version <= 0:
            raise PolicyError("group_id must be set and version must be positive")
        if self.expires_epoch_s and self.expires_epoch_s <= self.activation_epoch_s:
            raise PolicyError("policy expiry must be after activation")
        self.flows = tuple(_validate_flow(item, self.version) for item in data.get("flows", ()))
        if not self.flows:
            raise PolicyError("hardware policy must contain at least one flow")
        seen = set()
        for flow in self.flows:
            key = flow["flow_key"]
            if key in seen:
                raise PolicyError("duplicate five-tuple in hardware policy")
            seen.add(key)
        queues = {}
        for flow in self.flows:
            key = (flow["dev_port"], flow["qid"])
            queue = queues.setdefault(
                key,
                {
                    "rate_kbps": 0,
                    "burst_bytes": flow["burst_bytes"],
                    "flow_ids": [],
                    "phase_delay_s": flow["phase_delay_s"],
                    "period_s": flow["period_s"],
                    "window_s": flow["window_s"],
                },
            )
            queue["rate_kbps"] += flow["rate_kbps"]
            queue["burst_bytes"] = max(queue["burst_bytes"], flow["burst_bytes"])
            queue["flow_ids"].append(flow["flow_id"])
            queue["phase_delay_s"] = min(queue["phase_delay_s"], flow["phase_delay_s"])
            if queue["period_s"] != flow["period_s"] or queue["window_s"] != flow["window_s"]:
                raise PolicyError("shared queue members must have the same release schedule")
        self.leases = tuple(
            QueueLease(
                dev_port,
                qid,
                item["rate_kbps"],
                item["burst_bytes"],
                item["flow_ids"],
                item["phase_delay_s"],
                item["period_s"],
                item["window_s"],
            )
            for (dev_port, qid), item in sorted(queues.items())
        )

    def is_due(self, now_s):
        return self.activation_epoch_s <= 0 or now_s >= self.activation_epoch_s

    def is_expired(self, now_s):
        return self.expires_epoch_s > 0 and now_s >= self.expires_epoch_s


def load_hardware_policy(path):
    with open(path, "r") as handle:
        return HardwarePolicy(json.load(handle))


def _validate_flow(item, policy_version):
    version = int(item["ip_version"])
    if version not in (4, 6):
        raise PolicyError("ip_version must be 4 or 6")
    src_ip = str(ipaddress.ip_address(str(item["src_ip"])))
    dst_ip = str(ipaddress.ip_address(str(item["dst_ip"])))
    if (
        ipaddress.ip_address(src_ip).version != version
        or ipaddress.ip_address(dst_ip).version != version
    ):
        raise PolicyError("flow address family does not match ip_version")
    qid = int(item["qid"])
    if not CONTROLLED_QID_MIN <= qid <= CONTROLLED_QID_MAX:
        raise PolicyError("controlled qid must be in [1, 127]")
    result = dict(item)
    result.update(
        {
            "flow_id": str(item["flow_id"]),
            "ip_version": version,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": int(item["src_port"]),
            "dst_port": int(item["dst_port"]),
            "protocol": int(item["protocol"]),
            "dev_port": int(item["dev_port"]),
            "qid": qid,
            "rate_kbps": max(1, int(round(float(item["rate_bps"]) / 1000.0))),
            "burst_bytes": int(item.get("burst_bytes", 12000)),
            "phase_delay_s": max(0.0, float(item.get("phase_delay_s", 0.0))),
            "period_s": max(0.0, float(item.get("period_s", 0.0))),
            "window_s": max(0.0, float(item.get("window_s", 0.0))),
            "platform_id": int(item.get("platform_id", 0)),
            "policy_version": policy_version,
        }
    )
    result["flow_key"] = (
        version,
        src_ip,
        dst_ip,
        result["src_port"],
        result["dst_port"],
        result["protocol"],
    )
    return result
