"""Causal P95 DBSP inputs and persistent demand-balanced DQA (Python 3.5)."""

import json
import math
import subprocess
import threading
from queue import Queue


def safe_budget(profile, period, duration):
    return float(profile["confidence"]) * max(
        0.0,
        min(
            float(profile["buffer_margin_s"]),
            period / float(profile["theta"]) - duration,
            period - duration,
        ),
    )


def validate_profile(profile):
    for key in ("burst_p95_bytes", "buffer_margin_s", "theta", "confidence", "weight"):
        value = float(profile[key])
        if (
            not math.isfinite(value)
            or value < 0
            or (key in ("burst_p95_bytes", "theta") and value == 0)
        ):
            raise ValueError("invalid profile " + key)
    if float(profile["theta"]) < 1 or float(profile["confidence"]) > 1:
        raise ValueError("invalid headroom/confidence")
    if not profile.get("source"):
        raise ValueError("profile requires input provenance")


class BurstObservation(object):
    """Closed qualified bursts only; window timestamps never synthesized over gaps."""

    def __init__(self):
        self.current_bytes = 0
        self.start = None
        self.end = None
        self.completed = []
        self.last_activity = 0.0
        self.last_complete = 0.0

    def observe(self, value, start, end, cfg, p95=None):
        if value is None:
            self.current_bytes = 0
            self.start = self.end = None
            self.completed = []
            self.last_complete = 0.0
            return
        if value > 0:
            self.last_activity = end
        active_min = (
            float(cfg.get("active_min_bytes", 32768))
            * (end - start)
            / float(cfg.get("window_seconds", 0.5))
        )
        if value >= active_min:
            if self.start is None:
                self.start = start
            self.end = end
            self.current_bytes += value
            self.last_activity = end
        elif self.start is not None:
            if self.current_bytes >= int(cfg.get("min_burst_bytes", 262144)):
                self.completed.append((self.start, self.end, self.current_bytes))
                self.completed = self.completed[-8:]
                self.last_complete = end
            self.current_bytes = 0
            self.start = self.end = None

    def descriptor(self, profile, now, ttl, reference=None, envelope=None):
        # ns-3 includes zero-budget flows in the same LP at their access rate.
        # Hardware estimates chunk parameters; unavailable parameters imply a
        # zero delay budget for this flow, never vetoing the other flows.
        envelope = envelope or {}
        peak = float(
            envelope.get("enforced_peak_bps")
            or envelope.get("physical_peak_bps")
            or envelope.get("source_access_bps")
            or 0
        )
        if not math.isfinite(peak) or peak <= 0:
            raise ValueError("positive source access rate required")
        missing_profile = profile is None
        profile = profile or {
            "burst_p95_bytes": 1,
            "buffer_margin_s": 0,
            "theta": 1,
            "confidence": 0,
            "weight": 1,
        }
        recent = self.completed[-3:]
        # Only closed chunks are measurements.  An open byte counter has no
        # chunk boundary and previously grew for the whole HTTP/2 session,
        # turning a few-MiB segment into a hundreds-of-MiB fictitious burst.
        size = max([float(profile["burst_p95_bytes"])] + [b[2] for b in recent]) * 8
        on = size / peak
        duration = max((b[1] - b[0] for b in recent), default=on)
        ready = len(recent) >= 2 and now - self.last_complete <= ttl
        period = min((recent[i][0] - recent[i - 1][0] for i in range(1, len(recent))), default=on)
        measured_period = period
        if reference:
            period = float(reference["period_s"])
        if envelope.get("period_s"):
            period = float(envelope["period_s"])
            ready = not missing_profile
        input_basis = "closed_chunk_or_profile_p95"
        if envelope.get("chunk_bytes"):
            size = float(envelope["chunk_bytes"]) * 8
            on = size / peak
            input_basis = "declared_closed_chunk"
        budget = 0.0
        reason = "missing_profile" if missing_profile else "learning_or_stale"
        if ready and not missing_profile and period >= on:
            budget = max(
                0.0, safe_budget(profile, period, on) - float(envelope.get("used_budget_s", 0))
            )
            reason = "eligible" if budget > 0 else "zero_delay_budget"
        elif ready and period < on:
            reason = "source_chunk_exceeds_period"
        period = max(period, on)
        span = recent[-1][0] - recent[0][0] if len(recent) >= 2 else 0
        demand = float(
            envelope.get("demand_bps")
            or (sum(b[2] for b in recent[1:]) * 8.0 / span if span > 0 else peak)
        )
        return {
            "burst_bits": size,
            "period_s": period,
            "on_s": on,
            "bin_on_s": duration,
            "max_delay_s": budget,
            "profile": profile,
            "peak_bps": peak,
            "demand_bps": demand,
            "measured_on_s": duration,
            "measured_period_s": measured_period,
            "reserved_buffer_bytes": 0,
            "input_basis": input_basis,
            "zero_delay_reason": reason if budget == 0 else None,
        }, reason


class SolverProcess(object):
    def __init__(self, executable, timeout=2.0):
        self.executable = executable
        self.timeout = timeout
        self.process = None
        self.responses = None

    def close(self):
        if self.process is not None:
            if self.process.poll() is None:
                self.process.kill()
            self.process.wait()
            self.process.stdin.close()
            self.process.stdout.close()
            self.process = None

    def _start(self):
        self.responses = Queue()
        self.process = subprocess.Popen(
            [self.executable],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            universal_newlines=True,
            bufsize=1,
        )
        process, responses = self.process, self.responses

        def read():
            for line in process.stdout:
                responses.put(line)
            responses.put(None)

        reader = threading.Thread(target=read)
        reader.daemon = True
        reader.start()

    def solve(self, flows, capacity, buffer_bytes, version):
        if self.process is None or self.process.poll() is not None:
            self.close()
            self._start()
        tokens = ["DBSP2", str(version), str(len(flows)), repr(capacity), repr(buffer_bytes * 8.0)]
        for fid, desc in sorted(flows.items()):
            p = desc["profile"]
            values = [
                fid,
                desc["burst_bits"],
                desc["period_s"],
                desc["on_s"],
                desc["max_delay_s"],
                p["weight"],
            ]
            if any(not math.isfinite(float(v)) for v in values):
                raise ValueError("nonfinite solver input")
            tokens.extend(str(v) for v in values)
        try:
            self.process.stdin.write(" ".join(tokens) + "\n")
            self.process.stdin.flush()
            line = self.responses.get(timeout=self.timeout)
            result = json.loads(line) if line else {}
            if (
                result.get("schema") != "DBSP2"
                or result.get("version") != version
                or result.get("status") != "optimal"
            ):
                raise RuntimeError("invalid or failed DBSP reply")
            if set(f["id"] for f in result["flows"]) != set(flows):
                raise RuntimeError("incomplete DBSP reply")
            return result
        except Exception:
            self.close()
            raise

    def allocate(self, magic, demands, total):
        if magic not in ("DQA2", "QNT2"):
            raise ValueError("unsupported allocation operation")
        if self.process is None or self.process.poll() is not None:
            self.close()
            self._start()
        tokens = [magic, "1", str(len(demands)), str(total)]
        for fid, demand in sorted(demands.items()):
            tokens.extend((str(fid), repr(float(demand))))
        try:
            self.process.stdin.write(" ".join(tokens) + "\n")
            self.process.stdin.flush()
            line = self.responses.get(timeout=self.timeout)
            result = json.loads(line) if line else {}
            if (
                result.get("schema") != magic
                or result.get("version") != 1
                or result.get("status") != "optimal"
            ):
                raise RuntimeError("invalid native ns-3 allocation reply")
            allocation = dict(result["allocation"])
            if set(allocation) != set(demands):
                raise RuntimeError("incomplete native ns-3 allocation")
            return allocation
        except Exception:
            self.close()
            raise


class DemandQueues(object):
    def __init__(self, count, native=None):
        if not 1 <= count <= 127:
            raise ValueError("video queue count must be 1..127")
        self.count = count
        self.mapping = {}
        self.native = native

    def initialize(self, demands):
        """ns-3 AllocateDqaQueues: full descending-demand batch, once at setup."""
        if self.mapping:
            raise RuntimeError("DQA initialization must precede admission")
        if self.native is not None:
            self.mapping = self.native.allocate("DQA2", demands, self.count)
            return dict(self.mapping)
        return self.allocate(demands)

    def allocate(self, demands, unavailable=(), commit=True):
        if any(not math.isfinite(v) or v <= 0 for v in demands.values()):
            raise ValueError("DQA requires positive finite demand")
        mapping = {fid: q for fid, q in self.mapping.items() if fid in demands}
        load = {q: 0.0 for q in range(1, self.count + 1)}
        for fid, q in mapping.items():
            load[q] += demands[fid]
        choices = [q for q in load if q not in unavailable]
        for fid in sorted(set(demands) - set(mapping), key=lambda f: (-demands[f], f)):
            if not choices:
                raise RuntimeError("all queues draining")
            q = min(choices, key=lambda q: (load[q], q))
            mapping[fid] = q
            load[q] += demands[fid]
        if commit:
            self.mapping = mapping
        return dict(mapping)


def queue_rates(result, mapping):
    groups = {}
    for flow in result["flows"]:
        q = mapping[flow["id"]]
        groups[q] = groups.get(q, 0.0) + flow["rate_bps"]
    # Upward kbps rounding cannot introduce an additional delay in the model.
    return {q: int(math.ceil(rate / 1000.0)) for q, rate in groups.items()}


def service_weights(programmed_kbps, capacity_bps, pool_weight, allow_overload=False):
    """Give each active queue enough DWRR share for its verified max rate."""
    if not programmed_kbps or capacity_bps <= 0 or pool_weight <= 0:
        raise ValueError("positive rates, capacity and pool weight required")
    lower = {
        q: max(1, int(math.ceil(rate * 1000.0 * pool_weight / capacity_bps)))
        for q, rate in programmed_kbps.items()
    }
    if any(rate <= 0 for rate in programmed_kbps.values()):
        raise RuntimeError("programmed rates exceed realizable DWRR shares")
    if sum(lower.values()) > pool_weight:
        if not allow_overload or pool_weight < len(lower):
            raise RuntimeError("programmed rates exceed realizable DWRR shares")
        # As in ns-3, the shaper ceiling may exceed the available service.
        # Preserve the class share and report residual overload, rather than
        # dropping the whole LP result when a zero-budget flow is present.
        spare = pool_weight - len(lower)
        total = float(sum(programmed_kbps.values()))
        shares = {q: spare * rate / total for q, rate in programmed_kbps.items()}
        weights = {q: 1 + int(math.floor(share)) for q, share in shares.items()}
        order = sorted(shares, key=lambda q: (-(shares[q] - math.floor(shares[q])), q))
        for q in order[: pool_weight - sum(weights.values())]:
            weights[q] += 1
        return weights
    spare = pool_weight - sum(lower.values())
    order = sorted(lower, key=lambda q: (-programmed_kbps[q], q))
    each, extra = divmod(spare, len(order))
    return {q: lower[q] + each + (index < extra) for index, q in enumerate(order)}
