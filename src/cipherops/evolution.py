"""The evolving-zone experiment: MTL authenticates a series that keeps growing, so what does an update cost?

A real zone changes. Every changed RRset becomes a new leaf in the MTL series (old leaves never leave it) and each
round needs one new signed ladder. This module runs ``mtlbench evolve`` (MTL) and ``mtlbench evolve-direct`` (plain
SLH-DSA, the same updates signed one by one) and turns the output into the tables the report and the dashboard show.

Everything in ``evolution`` and ``evolution_direct`` is measured (``kind`` = ``measured``). The tables derived from
them here are labelled as derived where they combine measured values with an assumption.

What is measured per round, with the library itself and not a model:

- cost: appending the k changed leaves plus signing one new ladder, against signing k RRsets one by one;
- growth: leaf count, rung count, ladder bytes, condensed-signature size;
- cached ladders: every RRset of the current zone gets a fresh condensed signature, and the library verifies it
  against the ladder from ``age`` rounds earlier. An unchanged RRset must pass, an RRset whose leaf was appended after
  that ladder must fail. Both are checked against the leaf index, so a mismatch fails the run;
- published signatures: a condensed signature issued when a leaf was created, verified against the newest ladder.
  When rungs merge as the series grows, the earlier path no longer ends at a rung of the new ladder and the
  signature has to be reissued.
"""

from __future__ import annotations

import random
import time

import numpy as np
import pandas as pd

from . import stats
from .codepoints import MODES
from .harness import run_evolve
from .progress import log

KEYS = ("k", "rounds", "ages")


def settings(cfg: dict) -> dict | None:
    """The validated ``evolution:`` block, or None when the experiment is off or its modes are not configured."""
    ev = cfg.get("evolution")
    if not ev:
        return None
    if not {"slh-dsa", "slh-dsa-mtl"} <= set(cfg["modes"]):
        log("evolving zone skipped: it needs both slh-dsa and slh-dsa-mtl in `modes`")
        return None
    ks, rounds, ages = [list(map(int, ev[x])) for x in KEYS]
    if not ks or len(ks) != len(rounds) or min(ks) < 1 or min(rounds) < 1:
        raise SystemExit("evolution: `k` and `rounds` must be lists of the same length with positive values")
    if 0 not in ages or min(ages) < 0:
        raise SystemExit("evolution: `ages` must contain 0 (the newest ladder) and no negative values")
    return {"k": ks, "rounds": rounds, "ages": sorted(set(ages)), "seed": int(ev.get("seed", cfg["seed"]))}


def _mtl_rows(res: dict, dataset: str, trial: int) -> list[dict]:
    rows = []
    for series in res["series"]:
        for r in series["rows"]:
            row = {"trial": trial, "dataset": dataset, "k": series["k"], "round": r["round"], "changed": r["changed"],
                   "leaf_count": r["leaf_count"], "rung_count": r["rung_count"], "ladder_bytes": r["ladder_bytes"],
                   "append_ns": r["append_ns"], "ladder_sign_ns": r["ladder_sign_ns"],
                   "ladder_verify_ns": r["ladder_verify_ns"], "condensed_extract_ns": r["condensed_extract_ns"],
                   "condensed_bytes_median": r["condensed_bytes_median"], "condensed_bytes_max": r["condensed_bytes_max"],
                   "condensed_bytes_mean": r["condensed_bytes_mean"], "stale_tested": r["stale_tested"],
                   "stale_ok": r["stale_ok"], "rss_bytes": r["rss"], "leaf_index_mismatch": 0,
                   "exit_code": res["exit_code"], "kind": "measured"}
            for a in r["ages"]:
                row[f"tested_age_{a['age']}"] = a["tested"]
                row[f"ok_age_{a['age']}"] = a["ok"]
                row["leaf_index_mismatch"] += a["mismatch"]
            rows.append(row)
    return rows


def _direct_rows(res: dict, trial: int) -> list[dict]:
    return [{"trial": trial, "k": s["k"], "round": r["round"], "signed": r["signed"], "sign_ns": r["sign_ns"],
             "verify_ns": r["verify_ns"], "exit_code": res["exit_code"], "kind": "measured"}
            for s in res["series"] for r in s["rows"]]


def run(cfg: dict, paths: dict, ev: dict) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Every trial runs each dataset's MTL series and the direct baseline once, in a seeded random order."""
    smallest = min(cfg["datasets"], key=lambda d: d["n_names"])["name"]
    jobs = [(d["name"], "slh-dsa-mtl") for d in cfg["datasets"]] + [(smallest, "slh-dsa")]
    sigs = sum(ev["k"][i] * ev["rounds"][i] for i in range(len(ev["k"])))
    log(f"evolving zone: k={ev['k']} changed RRsets per round, rounds={ev['rounds']}, cached-ladder ages={ev['ages']}; "
        f"the direct baseline signs {sigs} RRsets per trial")
    rng = random.Random(cfg["seed"] + 1)
    mtl, direct = [], []
    for t in range(cfg["trials"]):
        order = list(jobs)
        rng.shuffle(order)
        for name, mk in order:
            start = time.time()
            res = run_evolve(MODES[mk], paths[(name, mk)], ev["k"], ev["rounds"], ev["ages"], ev["seed"])
            if mk == "slh-dsa-mtl":
                rows = _mtl_rows(res, name, t)
                mtl += rows
                bad = res["exit_code"] != 0 or res["failures"]["leaf_index_mismatch"] or res["failures"]["ladder"]
                tail = (f"{sum(x['rounds'] for x in res['series'])} update rounds, "
                        f"{'all ladder checks passed' if not bad else 'CHECK FAILED'}")
            else:
                direct += _direct_rows(res, t)
                tail = f"{sum(s['rounds'] for s in res['series'])} rounds signed one by one, " \
                       f"{'verified' if not res['failures']['verify'] else 'VERIFY FAILED'}"
            log(f"evolution trial {t + 1}/{cfg['trials']} {name:<7} {mk:<12} {tail}  wall={time.time() - start:6.1f}s")
    return pd.DataFrame(mtl), pd.DataFrame(direct)


def checks_passed(mtl: pd.DataFrame, direct: pd.DataFrame) -> bool:
    return bool((mtl.exit_code == 0).all() and (mtl.leaf_index_mismatch == 0).all()
                and (direct.exit_code == 0).all()) if len(mtl) and len(direct) else False


# ---------------------------------------------------------------- tables for the report and the dashboard

def ages_in(mtl: pd.DataFrame) -> list[int]:
    return sorted(int(c.rsplit("_", 1)[1]) for c in mtl.columns if c.startswith("tested_age_"))


def update_cost(mtl: pd.DataFrame, direct: pd.DataFrame) -> pd.DataFrame:
    """Per dataset and k: the signing cost of one update round with MTL against signing the k RRsets one by one.

    Each trial gives one MTL figure and one direct figure (median over its rounds), so the trials are paired and the
    ratio comes with the same order-statistic interval as everywhere else. MTL = appending the k changed leaves plus
    one new signed ladder; extracting condensed signatures is a per-answer serving cost and is left out."""
    if mtl.empty or direct.empty:
        return pd.DataFrame()
    m = mtl[mtl["round"] >= 1].assign(round_ns=lambda d: d.append_ns + d.ladder_sign_ns)
    m = m.groupby(["dataset", "k", "trial"]).agg(mtl_ns=("round_ns", "median"), verify_ns=("ladder_verify_ns", "median"),
                                                 append_ns=("append_ns", "median"), sign_ns=("ladder_sign_ns", "median"))
    d = direct.groupby(["k", "trial"]).agg(direct_ns=("sign_ns", "median"), direct_verify_ns=("verify_ns", "median"))
    j = m.reset_index().merge(d.reset_index(), on=["k", "trial"])
    rows = []
    for (ds, k), g in j.groupby(["dataset", "k"], sort=False):
        pr = stats.paired_ratio(g.direct_ns, g.mtl_ns)
        lo, hi = stats.median_ci(g.mtl_ns)
        rows.append({"dataset": ds, "k": int(k), "trials": len(g), "mtl_round_ns": float(g.mtl_ns.median()),
                     "mtl_lo_ns": lo, "mtl_hi_ns": hi, "mtl_append_ns": float(g.append_ns.median()),
                     "mtl_ladder_sign_ns": float(g.sign_ns.median()), "direct_round_ns": float(g.direct_ns.median()),
                     "ratio": pr["median"], "ratio_lo": pr["lo"], "ratio_hi": pr["hi"], "coverage": pr["coverage"],
                     "mtl_resolver_ns": float(g.verify_ns.median()),
                     "direct_resolver_ns": float(g.direct_verify_ns.median()),
                     "signatures_mtl": 1, "signatures_direct": int(k)})
    return pd.DataFrame(rows)


def coverage_by_round(mtl: pd.DataFrame) -> pd.DataFrame:
    """Share of the current zone's RRsets whose condensed signature verifies against the ladder ``age`` rounds old."""
    rows = []
    for a in ages_in(mtl):
        t, o = f"tested_age_{a}", f"ok_age_{a}"
        g = mtl[mtl[t].notna()].groupby(["dataset", "k", "round"])[[t, o]].sum().reset_index()
        g = g.assign(age=a, share=g[o] / g[t]).rename(columns={t: "tested", o: "ok"})
        rows.append(g[["dataset", "k", "round", "age", "tested", "ok", "share"]])
    return pd.concat(rows, ignore_index=True) if rows else pd.DataFrame()


def coverage_table(mtl: pd.DataFrame) -> pd.DataFrame:
    """The share above, pooled over the rounds in which that age exists (age 0 is 100% by construction)."""
    c = coverage_by_round(mtl)
    c = c[c["round"] >= 1]
    if c.empty:
        return c
    g = c.groupby(["dataset", "k", "age"])[["tested", "ok"]].sum().reset_index()
    return g.assign(share=g["ok"] / g["tested"])


def growth(mtl: pd.DataFrame) -> pd.DataFrame:
    cols = ["leaf_count", "rung_count", "ladder_bytes", "condensed_bytes_median", "condensed_bytes_max", "rss_bytes"]
    return mtl.groupby(["dataset", "k", "round"])[cols].median().reset_index()


def stale_by_round(mtl: pd.DataFrame) -> pd.DataFrame:
    """Share of the signatures published earlier that still verify against the newest ladder."""
    g = mtl[mtl["round"] >= 1].groupby(["dataset", "k", "round"])[["stale_tested", "stale_ok"]].sum().reset_index()
    return g.assign(share=g.stale_ok / g.stale_tested.where(g.stale_tested > 0))


def effective_bytes(mtl: pd.DataFrame) -> pd.DataFrame:
    """Signature bytes per answer if every answer that the cached ladder does not cover fetched a full signature.

    Derived, not measured: the condensed size and the ladder size are measured; the fetch rule is an upper bound,
    because a real resolver refreshes its ladder once and then covers the rest."""
    cov = coverage_table(mtl)
    if cov.empty:
        return cov
    g = mtl[mtl["round"] >= 1].groupby(["dataset", "k"])[["condensed_bytes_mean", "ladder_bytes"]].mean().reset_index()
    j = cov.merge(g, on=["dataset", "k"])
    j["effective_bytes"] = j.condensed_bytes_mean + (1 - j.share) * (j.condensed_bytes_mean + j.ladder_bytes)
    j["kind"] = "derived"
    return j


def rungs_of(leaf_count: int) -> list[tuple[int, int, int]]:
    """The rungs of a ladder for ``leaf_count`` leaves as (size, first leaf, last leaf): the binary breakdown, e.g.
    11 = 8 + 2 + 1."""
    out, start = [], 0
    for bit in range(leaf_count.bit_length() - 1, -1, -1):
        if leaf_count >> bit & 1:
            out.append((1 << bit, start, start + (1 << bit) - 1))
            start += 1 << bit
    return out


def summary(mtl: pd.DataFrame, direct: pd.DataFrame) -> dict:
    """The few numbers worth keeping in summary.json."""
    cost = update_cost(mtl, direct)
    cov = coverage_table(mtl)
    return {"checks_passed": checks_passed(mtl, direct),
            "update_cost": cost.to_dict("records"),
            "coverage": cov.to_dict("records"),
            "stale_min_share": {f"{ds}/k={k}": float(np.nanmin(g.share)) for (ds, k), g in
                                stale_by_round(mtl).groupby(["dataset", "k"]) if g.share.notna().any()}}
