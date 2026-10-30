"""The confidence interval for a median over a few repeated trials."""

import numpy as np
import pytest

from cipherops import stats


@pytest.mark.parametrize("n,cov", [(2, 0.5), (3, 0.75), (4, 0.875), (5, 0.9375), (6, 0.96875), (7, 0.984375)])
def test_coverage_of_the_full_range(n, cov):
    assert stats.median_ci_coverage(n) == pytest.approx(cov)
    values = list(range(1, n + 1))
    if cov < 0.95 or n <= 7:
        assert stats.median_ci(values) == (1.0, float(n))


def test_interval_narrows_once_more_trials_allow_it():
    values = list(range(1, 11))  # n = 10: [x(2), x(9)] covers 97.85%, [x(3), x(8)] only 89%
    assert stats.median_ci(values) == (2.0, 9.0)
    assert stats.median_ci_coverage(10) == pytest.approx(1 - 2 * (1 + 10) / 1024)


def test_single_and_empty_inputs():
    assert stats.median_ci([4.0]) == (4.0, 4.0)
    assert stats.median_ci_coverage(1) == 0.0
    lo, hi = stats.median_ci([])
    assert np.isnan(lo) and np.isnan(hi)


def test_nan_values_are_ignored():
    assert stats.median_ci([1.0, float("nan"), 3.0, 2.0, 5.0, 4.0]) == (1.0, 5.0)


@pytest.mark.parametrize("n", [5, 10, 21])
def test_empirical_coverage_matches_the_formula(n):
    rng = np.random.default_rng(7)
    hits = 0
    reps = 4000
    for _ in range(reps):
        lo, hi = stats.median_ci(rng.standard_normal(n))
        hits += lo <= 0.0 <= hi
    assert hits / reps == pytest.approx(stats.median_ci_coverage(n), abs=0.02)


def test_label_says_when_trials_are_too_few():
    assert "too few trials" in stats.ci_label(3)
    assert "too few" not in stats.ci_label(7)
    assert stats.ci_label(5).startswith("94% CI")


def test_paired_ratio_uses_each_trials_own_pairing():
    base = [10.0, 20.0, 30.0, 40.0, 50.0, 60.0]
    cand = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0]
    r = stats.paired_ratio(base, cand)
    assert r["n"] == 6 and r["median"] == pytest.approx(10.0) and (r["lo"], r["hi"]) == (10.0, 10.0)
    assert r["coverage"] == pytest.approx(0.96875)


def test_paired_ratio_differs_from_a_ratio_of_medians_when_trials_drift():
    # a slow trial slows both modes alike: the per-trial ratio is steady even though the medians move a lot
    base = [10.0, 20.0, 100.0, 12.0, 24.0, 120.0]
    cand = [1.0, 2.0, 10.0, 1.2, 2.4, 12.0]
    r = stats.paired_ratio(base, cand)
    assert (r["lo"], r["hi"]) == (10.0, 10.0)


def test_paired_ratio_skips_unusable_pairs():
    r = stats.paired_ratio([4.0, float("nan"), 9.0, 8.0], [2.0, 1.0, 0.0, 4.0])
    assert r["n"] == 2 and r["median"] == pytest.approx(2.0)
    assert stats.paired_ratio([], [])["n"] == 0
