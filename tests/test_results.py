"""Paired per-trial ratios between two modes of one run."""

import pandas as pd
import pytest

from cipherops import results


def _trials(extrapolated: bool = False) -> pd.DataFrame:
    rows = []
    for t in range(6):
        scale = 1 + t  # drift: later trials are slower for every mode
        for mode, sign, verify in (("slh-dsa", 100.0, 40.0), ("slh-dsa-mtl", 5.0, 2.0)):
            row = {"dataset": "small", "mode": mode, "trial": t, "sign_total_ns": sign * scale,
                   "verify_warm_total_ns": verify * scale}
            if extrapolated and mode == "slh-dsa":
                row["sign_total_extrapolated_ns"] = sign * scale * 10
            rows.append(row)
    return pd.DataFrame(rows)


def test_paired_ratio_table_reports_the_per_trial_ratio():
    t = results.paired_ratio_table(_trials(), "slh-dsa", "slh-dsa-mtl")
    sign = t[t.metric == "signing"].iloc[0]
    assert sign.ratio == pytest.approx(20.0) and sign.ratio_lo == sign.ratio_hi == pytest.approx(20.0)
    assert sign.trials == 6 and not sign.extrapolated
    verify = t[t.metric == "verification (warm)"].iloc[0]
    assert verify.ratio == pytest.approx(20.0)


def test_capped_direct_run_is_compared_through_its_extrapolated_total():
    t = results.paired_ratio_table(_trials(extrapolated=True), "slh-dsa", "slh-dsa-mtl")
    sign = t[t.metric == "signing"].iloc[0]
    assert sign.ratio == pytest.approx(200.0) and sign.extrapolated
    assert not t[t.metric == "verification (warm)"].iloc[0].extrapolated


def test_missing_mode_gives_an_empty_table():
    only = _trials()[lambda d: d["mode"] == "slh-dsa"]
    assert results.paired_ratio_table(only, "slh-dsa", "slh-dsa-mtl").empty
