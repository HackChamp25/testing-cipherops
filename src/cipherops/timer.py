"""How much the harness clock itself costs, and whether it can resolve the fastest operations.

The fastest timed calls (one condensed MTL verification, one Ed25519 verification) take microseconds, close to what
two ``clock_gettime`` calls cost. ``mtlbench calibrate`` therefore measures, on the same core and in the same image as
the benchmark:

- the clock: the cost of an empty timed region and the smallest step the clock was seen to take;
- two timings of the same fast operation: each call alone (what the benchmark does) and 1,000 calls in one region,
  divided by 1,000 (the timer's cost is spread over many calls).

If the two agree, per-call timing of that operation can be trusted. The summary is stored in ``environment.json``.
"""

from __future__ import annotations

import numpy as np

from .codepoints import MODES
from .harness import HarnessError, run_calibrate

# Share of a fast operation's time that a timed empty region may take before per-call timing is called unreliable.
MAX_TIMER_SHARE = 0.05


def summarise(raw: dict) -> dict:
    empty = raw["empty_region"]
    ops = {}
    for name, o in raw["operations"].items():
        each = np.asarray(o["per_call_ns"], dtype=float)
        batch = np.asarray(o["batch_total_ns"], dtype=float) / o["calls"]
        batch_med = float(np.median(batch))
        ops[name] = {
            "calls": int(o["calls"]),
            "batches": int(batch.size),
            "per_call_median_ns": float(np.median(each)),
            "per_call_mean_ns": float(each.mean()),
            "per_call_p95_ns": float(np.percentile(each, 95)),
            "batch_per_call_median_ns": batch_med,
            "batch_per_call_min_ns": float(batch.min()),
            "batch_per_call_max_ns": float(batch.max()),
            "per_call_vs_batch_pct": 100.0 * (float(np.median(each)) - batch_med) / batch_med,
            "timer_share_of_operation": float(empty["median_ns"]) / batch_med,
        }
    reliable = all(o["timer_share_of_operation"] <= MAX_TIMER_SHARE for o in ops.values())
    return {
        "clock": raw["clock"],
        "clock_getres_ns": raw["clock_getres_ns"],
        "smallest_observed_step_ns": raw["smallest_observed_step_ns"],
        "empty_region": empty,
        "operations": ops,
        "max_timer_share": MAX_TIMER_SHARE,
        "per_call_timing_reliable": reliable,
    }


def calibrate() -> dict:
    """Run the calibration; a failure is recorded, not raised, so it cannot stop a benchmark."""
    try:
        return summarise(run_calibrate(MODES["slh-dsa-mtl"].harness_algo))
    except (HarnessError, KeyError, ValueError, OSError) as e:
        return {"error": str(e)[:300]}
