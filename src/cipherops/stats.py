"""Summary statistics and distribution-free confidence intervals for a few repeated trials."""

from __future__ import annotations

import math

import numpy as np


def summarize(values) -> dict:
    a = np.asarray(values, dtype=float)
    if a.size == 0:
        return {"n": 0}
    return {
        "n": int(a.size),
        "mean": float(a.mean()),
        "median": float(np.median(a)),
        "std": float(a.std(ddof=1)) if a.size > 1 else 0.0,
        "p05": float(np.percentile(a, 5)),
        "p95": float(np.percentile(a, 95)),
        "min": float(a.min()),
        "max": float(a.max()),
    }


def median_ci_coverage(n: int, confidence: float = 0.95) -> float:
    """Actual coverage of the interval returned by ``median_ci`` for ``n`` observations.

    The interval [x(k), x(n+1-k)] contains the true median with probability 1 - 2 * P(Bin(n, 1/2) <= k-1),
    whatever the distribution of the data. With few trials the widest interval (the full range) may still fall
    short of the requested confidence, and this function says by how much.
    """
    if n < 2:
        return 0.0
    k = _order_index(n, confidence)
    return 1.0 - 2.0 * sum(math.comb(n, i) for i in range(k)) / 2.0 ** n


def _order_index(n: int, confidence: float) -> int:
    for k in range(n // 2, 0, -1):
        if 1.0 - 2.0 * sum(math.comb(n, i) for i in range(k)) / 2.0 ** n >= confidence:
            return k
    return 1


def median_ci(values, confidence: float = 0.95) -> tuple[float, float]:
    """Distribution-free confidence interval for the median, from order statistics.

    Repeated trials are few (3 to 10), where a bootstrap of the median is not a valid interval: its endpoints can
    only be observed values and its coverage is unknown. The order-statistic interval is exact for any
    distribution. It needs at least 6 trials to reach 95% (the full range then covers 96.9%); with 5 trials the
    full range covers 93.8%, with 3 trials 75%. Use ``median_ci_coverage`` to report the real figure.
    """
    a = np.sort(np.asarray(values, dtype=float))
    a = a[~np.isnan(a)]
    if a.size == 0:
        return (float("nan"), float("nan"))
    if a.size == 1:
        return (float(a[0]), float(a[0]))
    k = _order_index(a.size, confidence)
    return (float(a[k - 1]), float(a[a.size - k]))


def ci_label(n: int, confidence: float = 0.95) -> str:
    """Short text for a table or figure: what the bracketed interval is and how much it covers."""
    cov = median_ci_coverage(n, confidence)
    return f"{cov * 100:.0f}% CI of the median over {n} trials" + (
        "" if cov >= confidence else f" (below the {confidence * 100:.0f}% target: too few trials)")


def paired_ratio(numerator, denominator, confidence: float = 0.95) -> dict:
    """Median of the per-trial ratio numerator/denominator, with its order-statistic interval.

    The two series come from the same trials (modes are interleaved inside each trial), so each trial gives one
    ratio and the interval describes the ratio itself. This is tighter and more honest than dividing two medians,
    whose separate intervals say nothing about how the ratio varies.
    """
    a = np.asarray(numerator, dtype=float)
    b = np.asarray(denominator, dtype=float)
    ok = ~np.isnan(a) & ~np.isnan(b) & (b > 0)
    ratios = a[ok] / b[ok]
    if ratios.size == 0:
        return {"n": 0, "median": float("nan"), "lo": float("nan"), "hi": float("nan"), "coverage": 0.0}
    lo, hi = median_ci(ratios, confidence)
    return {"n": int(ratios.size), "median": float(np.median(ratios)), "lo": lo, "hi": hi,
            "coverage": median_ci_coverage(int(ratios.size), confidence)}
