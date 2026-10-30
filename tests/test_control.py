"""The A/A control and the timer calibration summary."""

import pandas as pd
import pytest

from cipherops import codepoints, results, timer


def test_control_copy_runs_the_same_harness_call_as_its_mode():
    aa = codepoints.mode_for("ed25519-aa")
    base = codepoints.MODES["ed25519"]
    assert aa.key == "ed25519-aa" and (aa.harness_mode, aa.harness_algo, aa.family) == (
        base.harness_mode, base.harness_algo, base.family)
    assert codepoints.base_key("ed25519-aa") == "ed25519" and codepoints.is_control("ed25519-aa")
    assert "ed25519-aa" not in codepoints.MODES  # the preflight and the report never see it as a mode
    with pytest.raises(KeyError):
        codepoints.mode_for("nonsense-aa")


def _frames(noise: float):
    rows, aa = [], []
    for t in range(6):
        drift = 1 + 0.5 * t
        rows.append({"dataset": "small", "mode": "ed25519", "trial": t, "sign_total_ns": 100.0 * drift,
                     "verify_warm_total_ns": 50.0 * drift})
        wobble = 1 + noise * (-1) ** t
        aa.append({"dataset": "small", "mode": "ed25519-aa", "trial": t, "sign_total_ns": 100.0 * drift * wobble,
                   "verify_warm_total_ns": 50.0 * drift * wobble})
        for mode, scale in (("slh-dsa", 10.0), ("slh-dsa-mtl", 1.0)):
            rows.append({"dataset": "small", "mode": mode, "trial": t, "sign_total_ns": 1000.0 * scale * drift,
                         "verify_warm_total_ns": 500.0 * scale * drift})
    return pd.DataFrame(rows), pd.DataFrame(aa)


def test_identical_copies_give_a_ratio_of_one_and_a_small_band():
    trials, control = _frames(noise=0.0)
    floor = results.noise_floor_table(trials, control, "ed25519")
    assert floor.ratio.tolist() == pytest.approx([1.0, 1.0]) and floor.band.tolist() == pytest.approx([0.0, 0.0])


def test_noise_band_comes_from_the_spread_of_the_copies():
    trials, control = _frames(noise=0.05)
    floor = results.noise_floor_table(trials, control, "ed25519")
    assert floor.band.max() == pytest.approx(1 / 0.95 - 1, abs=1e-6)  # copies differ by up to 5% either way


def test_a_difference_is_claimed_only_outside_the_noise_band():
    assert results.exceeds_noise(1.2, 1.3, 0.1)
    assert results.exceeds_noise(0.5, 0.8, 0.1)
    assert not results.exceeds_noise(0.95, 1.4, 0.1)
    assert not results.exceeds_noise(1.05, 1.08, 0.1)
    trials, control = _frames(noise=0.05)
    floor = results.noise_floor_table(trials, control, "ed25519")
    pr = results.paired_ratio_table(trials, "slh-dsa", "slh-dsa-mtl", floor=floor)
    assert pr.above_noise.all() and pr.ratio.tolist() == pytest.approx([10.0, 10.0])
    same = results.paired_ratio_table(trials, "ed25519", "ed25519", floor=floor)
    assert not same.above_noise.any()


def test_no_control_means_no_floor():
    trials, _ = _frames(0.0)
    assert results.noise_floor_table(trials, pd.DataFrame(), "ed25519").empty
    assert "above_noise" not in results.paired_ratio_table(trials, "slh-dsa", "slh-dsa-mtl")


def _raw(overhead: int, per_call: int, batch_per_call: int) -> dict:
    return {"clock": "CLOCK_MONOTONIC_RAW", "clock_getres_ns": 1, "smallest_observed_step_ns": 25,
            "empty_region": {"samples": 10, "min_ns": 20, "median_ns": overhead, "p99_ns": 90, "max_ns": 500,
                             "mean_ns": 40.0, "zero_fraction": 0.0},
            "operations": {"fast_op": {"calls": 1000, "per_call_ns": [per_call] * 1000,
                                       "batch_total_ns": [batch_per_call * 1000] * 5}}}


def test_timer_summary_flags_a_clock_that_is_too_coarse_for_an_operation():
    ok = timer.summarise(_raw(overhead=30, per_call=1160, batch_per_call=1140))
    op = ok["operations"]["fast_op"]
    assert op["per_call_vs_batch_pct"] == pytest.approx(100 * 20 / 1140)
    assert op["timer_share_of_operation"] == pytest.approx(30 / 1140)
    assert ok["per_call_timing_reliable"]
    bad = timer.summarise(_raw(overhead=30, per_call=330, batch_per_call=300))
    assert not bad["per_call_timing_reliable"]
