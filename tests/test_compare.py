"""Pure-function tests for the dashboard's Compare and benchmark-suite helpers (no Docker, no Streamlit)."""

import sys
from pathlib import Path

import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "dashboard"))

from live_lab import compare, suite, suite_report  # noqa: E402


def test_bench_shape_keeps_hierarchy_and_sums_to_dataset():
    for n in (20, 50, 500, 5000):
        s = suite.bench_shape(n)
        assert sum(s["sld_sizes"]) == n
        assert s["sld_count"] == len(s["sld_sizes"]) == 4
    assert suite.bench_shape(2)["sld_count"] == 2


def test_sample_sizes_two_points_capped_by_dataset():
    assert suite.sample_sizes(5000, 100) == [100, 25]
    assert suite.sample_sizes(50, 100) == [50, 12]
    assert suite.sample_sizes(2, 100) == [2]


def test_ratio_text_reads_both_directions():
    assert compare.ratio_text(100, 10, "faster", "slower") == "10× faster"
    assert compare.ratio_text(10, 100, "faster", "slower") == "10× slower"
    assert compare.ratio_text(10, 10.2, "faster", "slower") == "about the same"
    assert compare.ratio_text(None, 5, "faster", "slower") == "—"


def test_analytical_storage_matches_draft_formulas():
    rows = [
        {"scenario": "slh-dsa", "algorithm": "SLH-DSA-SHA2-128s", "rrsig_count": 10},
        {"scenario": "mtl", "algorithm": "SLH-DSA-SHA2-128s-MTL-SHA2-128", "rrsig_count": 10},
        {"scenario": "ecdsa", "algorithm": "ECDSAP256SHA256", "rrsig_count": 10},
    ]
    a = compare.analytical_by_scenario(rows).set_index("scenario")["analytic_sig_bytes"]
    assert a["slh-dsa"] == 10 * 7856
    assert a["mtl"] == 10 * compare.analytical.max_condensed_signature(16, 10) + compare.analytical.max_signed_ladder(
        16, 10, 7856)
    assert "ecdsa" not in a.index


def test_trial_stats_recover_a_known_fixed_plus_per_rrsig_cost():
    # 0.5 s fixed per zone plus 0.01 s per RRSIG, three trials, two sample sizes, two zones in the dataset.
    rows = []
    for t in (1, 2, 3):
        for names, rr in ((100, 300), (25, 80)):
            rows.append({"dataset": 500, "scenario": "mtl", "trial": t, "names": names, "rrsigs": rr,
                         "sign_s": 0.5 + 0.01 * rr, "verify_s": 0.1, "algorithm": "x", "signed_bytes": 1})
    full = pd.DataFrame([{"dataset": 500, "scenario": "mtl", "rrsig_count": r, "sign_seconds": 1.0,
                          "verify_seconds": 0.1, "signed_bytes": 10} for r in (1000, 600)])
    s = compare.signing_trial_stats(pd.DataFrame(rows), full).iloc[0]
    assert s["trials"] == 3
    assert s["est_sign_s"] == pytest.approx(2 * 0.5 + 0.01 * 1600)
    assert s["sign_ms_per_rrsig"] == pytest.approx(10.0)
    assert s["sample_names"] == "100 and 25"
    assert s["full_sign_s"] == pytest.approx(2.0)


def test_headline_ratios_from_a_merged_frame():
    df = pd.DataFrame({
        "scenario": ["slh-dsa", "mtl"], "sign_s": [100.0, 5.0], "verify_s": [1.0, 0.5],
        "signed_bytes": [4e6, 4e5], "upstream_bytes": [4e6, 3e5], "cache_rrset": [2e6, 2e5],
    })
    cards = {c["label"]: c["value"] for c in compare.headline(df, "slh-dsa", "mtl")}
    assert cards["Signing time"] == "20× faster"
    assert cards["Signed zone size"] == "10× smaller"
    assert cards["Cache size"] == "10× less memory"


def test_suite_report_writes_md_html_when_suite_present(tmp_path):
    """Smoke: regenerate from the finished local suite if it exists; otherwise skip."""
    suites = ROOT / "ecosystem" / "results" / "suites"
    if not suites.is_dir():
        pytest.skip("no suites directory")
    finished = sorted(
        (p for p in suites.iterdir() if p.is_dir() and (p / "suite.json").is_file()),
        key=lambda p: p.stat().st_mtime, reverse=True,
    )
    if not finished:
        pytest.skip("no finished suite on disk")
    out = suite_report.write(finished[0])
    assert out.is_file() and "PS-036" in out.read_text(encoding="utf-8")
    html = out.with_suffix(".html")
    assert html.is_file() and "Signing" in html.read_text(encoding="utf-8")


def test_lookup_problems_names_the_scenario_and_counts():
    summary = pd.DataFrame([
        {"scenario": "slh-dsa", "profile": "lan", "pass": "cold", "trials": 3, "valid_trials": 0, "failed": 30,
         "servfail": 30, "timeouts": 0},
        {"scenario": "mtl", "profile": "lan", "pass": "cold", "trials": 3, "valid_trials": 3, "failed": 0,
         "servfail": 0, "timeouts": 0}])
    notes = compare.lookup_problems(summary)
    assert len(notes) == 1 and "slh-dsa" in notes[0] and "SERVFAIL 30" in notes[0] and "0 of 3" in notes[0]
    assert compare.lookup_problems(pd.DataFrame()) == [] and compare.lookup_problems(None) == []
