#!/usr/bin/env python3
"""Python 3.5-compatible online form of the frozen behavior detector."""

from __future__ import print_function

import math


DEFAULTS = {
    "window_seconds": 0.5,
    "sample_duration_seconds": 60.0,
    "active_min_bytes": 32768,
    "min_burst_bytes": 262144,
    "min_burst_windows": 1,
    "min_idle_windows": 1,
    "stable_min_bursts": 3,
    "stable_max_interval_cv": 0.35,
    "recurrent_min_bursts": 3,
    "recurrent_min_total_bytes": 1000000,
    "recurrent_max_active_ratio": 0.90,
}


def behavior_config(config):
    values = dict(DEFAULTS)
    values.update(config or {})
    return values


def classify_windows(values_by_window, config=None):
    """Return the frozen stable/recurrent decision for one causal prefix."""

    cfg = behavior_config(config)
    window_s = float(cfg["window_seconds"])
    limit = max(1, int(math.ceil(float(cfg["sample_duration_seconds"]) / window_s)))
    values = [max(0, int(value)) for value in values_by_window[:limit]]
    if not values:
        return _result(False, False, (), values, None, "empty_sequence", cfg)

    active = [value >= int(cfg["active_min_bytes"]) for value in values]
    runs = _merge_short_idle_gaps(_active_runs(active), int(cfg["min_idle_windows"]))
    bursts = []
    for start, end in runs:
        byte_count = sum(values[start : end + 1])
        if end - start + 1 < int(cfg["min_burst_windows"]):
            continue
        if byte_count < int(cfg["min_burst_bytes"]):
            continue
        bursts.append((start, end, byte_count))

    intervals = [
        (bursts[index][0] - bursts[index - 1][0]) * window_s for index in range(1, len(bursts))
    ]
    cv = _coefficient_of_variation(intervals)
    stable = (
        len(bursts) >= int(cfg["stable_min_bursts"])
        and cv is not None
        and cv <= float(cfg["stable_max_interval_cv"])
    )
    total_burst_bytes = sum(item[2] for item in bursts)
    active_ratio = float(sum(active)) / len(active)
    recurrent = (
        len(bursts) >= int(cfg["recurrent_min_bursts"])
        and total_burst_bytes >= int(cfg["recurrent_min_total_bytes"])
        and active_ratio <= float(cfg["recurrent_max_active_ratio"])
    )
    if stable:
        reason = "stable_periodic_refill"
    elif recurrent:
        reason = "recurrent_media_burst"
    elif len(bursts) < min(int(cfg["stable_min_bursts"]), int(cfg["recurrent_min_bursts"])):
        reason = "not_enough_qualified_bursts"
    elif total_burst_bytes < int(cfg["recurrent_min_total_bytes"]):
        reason = "insufficient_total_burst_bytes"
    elif active_ratio > float(cfg["recurrent_max_active_ratio"]):
        reason = "too_continuously_active"
    else:
        reason = "irregular_bursts_below_frozen_criteria"
    return _result(stable, recurrent, bursts, values, cv, reason, cfg)


def _result(stable, recurrent, bursts, values, interval_cv, reason, cfg):
    active_count = sum(value >= int(cfg["active_min_bytes"]) for value in values)
    return {
        "stable_periodic_refill": bool(stable),
        "recurrent_media_burst": bool(recurrent),
        "behavior_match": bool(stable or recurrent),
        "burst_count": len(bursts),
        "total_burst_bytes": sum(item[2] for item in bursts),
        "observed_total_bytes": sum(values),
        "active_window_count": active_count,
        "active_ratio": float(active_count) / len(values) if values else 0.0,
        "interval_cv": interval_cv,
        "reason": reason,
    }


def _active_runs(active):
    runs = []
    start = None
    for index, is_active in enumerate(active):
        if is_active and start is None:
            start = index
        elif not is_active and start is not None:
            runs.append((start, index - 1))
            start = None
    if start is not None:
        runs.append((start, len(active) - 1))
    return runs


def _merge_short_idle_gaps(runs, min_idle_windows):
    if not runs:
        return []
    merged = [runs[0]]
    for start, end in runs[1:]:
        previous_start, previous_end = merged[-1]
        if start - previous_end - 1 < min_idle_windows:
            merged[-1] = (previous_start, end)
        else:
            merged.append((start, end))
    return merged


def _coefficient_of_variation(values):
    if len(values) < 2:
        return None
    average = sum(values) / float(len(values))
    if average <= 0:
        return None
    variance = sum((value - average) ** 2 for value in values) / float(len(values))
    return math.sqrt(variance) / average
