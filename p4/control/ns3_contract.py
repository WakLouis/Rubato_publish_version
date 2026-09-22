"""Single-switch DBSP contract; explicit inputs, no ECN or admission heuristics."""

import math


def equal_quanta(total, queues):
    """Integer division/remainder used by SetClassQuanta in rubato-experiment.cc."""
    if queues < 1 or total < queues:
        raise ValueError("positive quantum for each configured video queue required")
    each, extra = divmod(int(total), int(queues))
    return {q: each + (q <= extra) for q in range(1, queues + 1)}


def demand_quanta(demands, total, solver):
    """Use ns-3 C++ long-double rounding, not a second Python approximation."""
    return solver.allocate("QNT2", demands, total)


def burst_bytes(rate_bps, cfg):
    return max(
        int(cfg.get("shaper_burst_floor_bytes", 9216)),
        int(rate_bps / 8.0 * float(cfg.get("shaper_burst_seconds", 0.002))),
    )


def validate_logical_flows(flows):
    """Only explicitly dedicated endpoints may represent a logical video stream."""
    ids = set()
    for ip, spec in flows.items():
        if spec.get("dedicated_source") is not True:
            raise ValueError("logical flow source must be dedicated: " + ip)
        for key in ("id", "source_access_bps", "demand_bps", "period_s"):
            value = spec.get(key)
            if value is None or not math.isfinite(float(value)) or float(value) <= 0:
                raise ValueError("logical flow requires positive " + key + ": " + ip)
        if int(spec["id"]) != spec["id"] or spec["id"] in ids:
            raise ValueError("logical flow IDs must be unique integers")
        ids.add(spec["id"])
