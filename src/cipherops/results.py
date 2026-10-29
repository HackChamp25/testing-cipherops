"""Load a run directory and derive the tables shared by the report and dashboard."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd
import yaml

from . import stats
from .codepoints import MODES

MODE_ORDER = ["rsa-2048", "ecdsa-p256", "ed25519", "slh-dsa", "slh-dsa-mtl"]
FRAMES = ("datasets", "trials", "responses", "workload", "cache", "sizes")


@dataclass
class Run:
    root: Path
    config: dict
    environment: dict
    preflight: dict
    summary: dict
    frames: dict[str, pd.DataFrame] = field(default_factory=dict)

    @property
    def dataset_order(self) -> list[str]:
        return [d["name"] for d in sorted(self.config["datasets"], key=lambda d: d["n_names"])]

    @property
    def mode_order(self) -> list[str]:
        return [m for m in MODE_ORDER if m in self.config["modes"]]

    def label(self, mode_key: str) -> str:
        return MODES[mode_key].label


def _json(path: Path) -> dict:
    return json.loads(path.read_text()) if path.exists() else {}


def list_runs(results_dir: Path) -> list[Path]:
    runs = Path(results_dir) / "runs"
    if not runs.exists():
        return []
    return sorted((p for p in runs.iterdir() if (p / "summary.json").exists()), reverse=True)


def load(root: Path) -> Run:
    root = Path(root)
    run = Run(root, yaml.safe_load((root / "config.yaml").read_text()), _json(root / "environment.json"),
              _json(root / "preflight.json"), _json(root / "summary.json"))
    for name in FRAMES:
        path = root / f"{name}.parquet"
        if path.exists():
            run.frames[name] = pd.read_parquet(path)
    return run


def timing_table(trials: pd.DataFrame) -> pd.DataFrame:
    """Median over trials with a distribution-free CI of the median (stats.median_ci) for each zone-level timing."""
    rows = []
    metrics = ("sign_total_ns", "verify_warm_total_ns", "sign_per_rrset_ns", "verify_per_rrset_ns",
               "verify_full_median_ns", "keygen_ns", "sign_total_extrapolated_ns",
               "verify_warm_total_extrapolated_ns")
    for (ds, mk), g in trials.groupby(["dataset", "mode"]):
        row = {"dataset": ds, "mode": mk, "trials": len(g), "n_signed": int(g.n_signed.iloc[0]),
               "dataset_rrsets": int(g.dataset_rrsets.iloc[0]), "limited": bool(g.limited.any()),
               "checks_passed": bool((g.exit_code == 0).all() and (g.failures_total == 0).all()
                                     and g.tamper_all_rejected.all())}
        for m in metrics:
            if m in g and g[m].notna().any():
                vals = g[m].dropna()
                lo, hi = stats.median_ci(vals)
                row[m] = float(vals.median())
                row[m + "_lo"], row[m + "_hi"] = lo, hi
        rows.append(row)
    return pd.DataFrame(rows)


PAIRED_METRICS = {"sign_total_ns": "signing", "verify_warm_total_ns": "verification (warm)"}


def paired_ratio_table(trials: pd.DataFrame, baseline: str, candidate: str,
                       metrics: dict[str, str] | None = None) -> pd.DataFrame:
    """Per-trial ratio baseline/candidate ("N times faster") with an interval, one row per dataset and metric.

    Both modes ran inside the same trial, so the trials are paired. A capped direct SLH-DSA run is compared through
    its extrapolated whole-zone total, and the row says so.
    """
    rows = []
    for ds, g in trials.groupby("dataset", sort=False):
        b, c = g[g["mode"] == baseline].set_index("trial"), g[g["mode"] == candidate].set_index("trial")
        common = b.index.intersection(c.index)
        if len(common) == 0:
            continue
        b, c = b.loc[common], c.loc[common]
        for col, name in (metrics or PAIRED_METRICS).items():
            def effective(frame: pd.DataFrame) -> tuple[pd.Series, bool]:
                ext = col.replace("_ns", "_extrapolated_ns")
                if ext in frame and frame[ext].notna().any():
                    return frame[ext], True
                return frame[col], False
            bv, b_ext = effective(b)
            cv, c_ext = effective(c)
            r = stats.paired_ratio(bv, cv)
            if r["n"] == 0:
                continue
            rows.append({"dataset": ds, "metric": name, "baseline": baseline, "candidate": candidate,
                         "trials": r["n"], "ratio": r["median"], "ratio_lo": r["lo"], "ratio_hi": r["hi"],
                         "coverage": r["coverage"], "extrapolated": b_ext or c_ext,
                         "ratio_of_medians": float(bv.median() / cv.median())})
    return pd.DataFrame(rows)


def fit_table(responses: pd.DataFrame, udp_limit: int = 1232) -> pd.DataFrame:
    d = responses[(responses.variant == "default") & (responses.udp_limit == udp_limit)]
    return (d.groupby(["dataset", "mode", "record_class"])
             .agg(responses=("response_bytes", "size"), median_bytes=("response_bytes", "median"),
                  max_bytes=("response_bytes", "max"), fit_pct=("fits_udp", lambda s: 100 * s.mean()),
                  median_rrsig_bytes=("rrsig_signature_bytes", "median"))
             .reset_index())


def fmt_seconds(ns: float | None) -> str:
    if ns is None or pd.isna(ns):
        return "–"
    s = ns / 1e9
    if s >= 1:
        return f"{s:,.2f} s"
    if s >= 1e-3:
        return f"{s * 1e3:,.2f} ms"
    return f"{s * 1e6:,.1f} µs"


def fmt_bytes(b: float | None) -> str:
    if b is None or pd.isna(b):
        return "–"
    b = float(b)
    for unit, scale in (("MB", 1e6), ("KB", 1e3)):
        if b >= scale:
            return f"{b / scale:,.2f} {unit}"
    return f"{b:,.0f} B"
