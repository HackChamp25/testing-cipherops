"""What this machine can prove: the newest finished runs, the headline figures, and the PS-036 deliverables checklist.

Pure functions over files on disk, no Streamlit and no Docker. Every number comes from a run folder and carries the run
id; with no run, the functions return nothing and the home page shows an empty state instead of example figures.

Two kinds of run exist and are never merged:

- **offline** (``results/runs/<id>/``): the pinned single-core harness. Primary evidence for signing time, verification
  time and signature sizes.
- **live** (``ecosystem/results/suites/<id>/``): the Docker resolver lab. Byte counts and truncation are measured;
  timings are indicative.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import pandas as pd
import yaml

from cipherops import results, stats
from live_lab import compare, compare_hub, terms

ROOT = Path(__file__).resolve().parents[2]
RESULTS_DIR = ROOT / "results"
SUITES_DIR = ROOT / "ecosystem" / "results" / "suites"
LAB_RESULTS_DIR = ROOT / "ecosystem" / "results"

FOUND, PARTIAL, MISSING = "found", "partial", "missing"
STATE_TEXT = {FOUND: "Evidence found", PARTIAL: "Partial", MISSING: "Not found on this machine"}
RANK = {FOUND: 2, PARTIAL: 1, MISSING: 0}
# Where the interval of a median over trials first reaches 95% (methodology section 6.2).
TRIALS_FOR_95 = 6


@dataclass(frozen=True)
class Run:
    source: str            # "offline" or "live"
    id: str
    path: Path
    when: str              # human date from the run id
    trials: int | None
    sizes: tuple = ()      # dataset names (offline) or name counts (live)


@dataclass
class Card:
    key: str
    title: str
    value: str
    detail: str
    badges: list[str]       # one kind of number per card
    run: Run
    ci: str = ""
    note: str = ""
    report: Path | None = None
    proof: list[Path] = field(default_factory=list)


@dataclass
class Row:
    key: str
    requirement: str
    state: str
    detail: str
    run_id: str = ""
    proof: list[Path] = field(default_factory=list)
    tile: str = "compare"
    missing: str = ""


# ─────────────────────────── finding runs ───────────────────────────

def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _when(stamp: str, fmt: str, fallback: Path) -> str:
    try:
        return datetime.strptime(stamp, fmt).strftime("%d %b %Y, %H:%M UTC" if "Z" in fmt else "%d %b %Y, %H:%M")
    except ValueError:
        return datetime.fromtimestamp(fallback.stat().st_mtime).strftime("%d %b %Y, %H:%M")


def offline_runs(results_dir: Path = RESULTS_DIR) -> list[Run]:
    """Finished offline runs, newest first. Finished = summary.json and the trials table exist."""
    root = Path(results_dir) / "runs"
    out = []
    if not root.is_dir():
        return out
    for p in sorted(root.iterdir(), reverse=True):
        if not (p / "summary.json").is_file() or not ((p / "trials.parquet").is_file() or (p / "trials.csv").is_file()):
            continue
        try:
            cfg = yaml.safe_load((p / "config.yaml").read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError):
            continue
        out.append(Run("offline", p.name, p, _when(p.name.split("-", 1)[0], "%Y%m%dT%H%M%SZ", p),
                       int(cfg["trials"]) if cfg.get("trials") else None,
                       tuple(d["name"] for d in cfg.get("datasets", []))))
    return out


def live_runs(suites_dir: Path = SUITES_DIR) -> list[Run]:
    """Finished live-lab benchmarks, newest first. Finished = suite.json exists."""
    root = Path(suites_dir)
    out = []
    if not root.is_dir():
        return out
    for p in root.iterdir():
        suite = _read_json(p / "suite.json") if p.is_dir() else {}
        if not suite:
            continue
        params = _read_json(p / "params.json")
        out.append(Run("live", p.name, p, _when(params.get("stamp", ""), "%Y%m%d-%H%M%S", p),
                       suite.get("trials"), tuple(suite.get("sizes") or ())))
    return sorted(out, key=lambda r: r.path.stat().st_mtime, reverse=True)


def captures(lab_results_dir: Path = LAB_RESULTS_DIR) -> list[Path]:
    """Packet captures from the Demonstrate tile, newest first."""
    root = Path(lab_results_dir)
    if not root.is_dir():
        return []
    return sorted(root.glob("*/live-dashboard/*.pcap"), key=lambda p: p.stat().st_mtime, reverse=True)


def fingerprint(results_dir: Path = RESULTS_DIR, suites_dir: Path = SUITES_DIR,
                lab_results_dir: Path = LAB_RESULTS_DIR) -> tuple:
    """Cheap change key for caching: modification times only, nothing is parsed."""
    key = []
    for d in (Path(results_dir) / "runs", Path(suites_dir), Path(lab_results_dir)):
        try:
            key.append((str(d), d.stat().st_mtime, tuple(sorted(
                (c.name, c.stat().st_mtime) for c in d.iterdir() if c.is_dir()))))
        except OSError:
            key.append((str(d), 0.0, ()))
    return tuple(key)


# ─────────────────────────── headline figures ───────────────────────────

def _fit_share(responses: pd.DataFrame, dataset: str, mode: str) -> float | None:
    f = results.fit_table(responses)
    f = f[(f.dataset == dataset) & (f["mode"] == mode) & (f.record_class != "apex")]
    if f.empty:
        return None
    return float((f.fit_pct * f.responses).sum() / f.responses.sum())


def offline_cards(run: Run) -> list[Card]:
    """Four cards for the newest offline run. Every value is read from the run's files and labelled Measured, except
    a whole-zone time that had to be scaled from a sample, which is labelled Extrapolated and never mixed with a
    measured one in the same card."""
    data = results.load(run.path)
    F = data.frames
    if not {"trials", "responses"} <= set(F):
        return []
    trials, order = F["trials"], data.dataset_order
    if not {"slh-dsa", "slh-dsa-mtl"} <= set(trials["mode"]):
        return []
    timing = results.timing_table(trials).set_index(["dataset", "mode"])
    paired = results.paired_ratio_table(trials, "slh-dsa", "slh-dsa-mtl")
    n_trials = int(run.trials or 0)
    ci = stats.ci_label(n_trials) if n_trials else ""
    proof = [run.path / n for n in ("config.yaml", "environment.json", "preflight.json") if (run.path / n).is_file()]
    report = run.path / "report.html" if (run.path / "report.html").is_file() else None
    big = order[-1]
    # the largest dataset on which plain SLH-DSA was signed in full, so a measured MTL time meets a measured one
    full = [d for d in order if not bool(timing.loc[(d, "slh-dsa"), "limited"])]
    tds = full[-1] if full else big

    def card(key, title, value, detail, kind, note="", ds=big):
        label = terms.dataset_label(ds, rrsets=int(timing.loc[(ds, "slh-dsa-mtl"), "dataset_rrsets"]))
        return Card(key, title, value, f"{label}. {detail}".strip(), [kind], run, ci, note, report, proof)

    def ratio_text(ds, metric):
        r = paired[(paired.dataset == ds) & (paired.metric == metric)]
        if r.empty:
            return ""
        r = r.iloc[0]
        return f"MTL {compare_hub.fmt_x(r.ratio).replace('lower', 'less time')} " \
               f"{compare_hub._interval(r.ratio_lo, r.ratio_hi)} (per-trial ratio)"

    cards = []
    sizes = trials[trials.dataset == big].groupby("mode").signature_bytes_max.max()
    cards.append(card("signature_bytes", "Signature bytes per signed answer",
                      f"{results.fmt_bytes(sizes['slh-dsa-mtl'])} vs {results.fmt_bytes(sizes['slh-dsa'])}",
                      "SLH-DSA-MTL (largest condensed signature) against SLH-DSA.", "measured"))
    sign_kind = "extrapolated" if tds not in full else "measured"
    s_mtl, s_dir = timing.loc[(tds, "slh-dsa-mtl")], timing.loc[(tds, "slh-dsa")]
    note = ""
    if sign_kind == "extrapolated":
        note = ("Plain SLH-DSA signed only a sample of this zone; its whole-zone figure is scaled up from the sample, "
                "which is why this card is labelled Extrapolated.")
    elif tds != big:
        note = (f"Plain SLH-DSA on the {terms.dataset_label(big)} dataset is signed only on a sample and scaled up. "
                f"This card uses {terms.dataset_label(tds)}, where both sides are fully measured; the report has "
                "the scaled figure, labelled Extrapolated.")
    cards.append(card("sign", "Whole-zone signing time",
                      f"{results.fmt_seconds(s_mtl.sign_total_ns)} vs {results.fmt_seconds(s_dir.sign_total_ns)}",
                      f"SLH-DSA-MTL against SLH-DSA. {ratio_text(tds, 'signing')}", sign_kind, note, ds=tds))
    cards.append(card("verify", "Warm verification, whole zone",
                      f"{results.fmt_seconds(s_mtl.verify_warm_total_ns)} vs "
                      f"{results.fmt_seconds(s_dir.verify_warm_total_ns)}",
                      f"Cached ladder. {ratio_text(tds, 'verification (warm)')}", sign_kind, note, ds=tds))
    fit_m, fit_d = _fit_share(F["responses"], big, "slh-dsa-mtl"), _fit_share(F["responses"], big, "slh-dsa")
    if fit_m is not None and fit_d is not None:
        cards.append(card("fit", "Answers that fit a 1,232-byte UDP buffer",
                          f"{fit_m:.0f}% vs {fit_d:.0f}%",
                          "SLH-DSA-MTL against SLH-DSA, positive and negative answers at the message level.",
                          "measured"))
    return cards


def live_cards(run: Run) -> tuple[list[Card], list[str]]:
    """Resolver-level figures from a live-lab benchmark, plus any failed-lookup warnings (never hidden)."""
    sd = compare.load_suite(run.path)
    if not sd or not sd["datasets"]:
        return [], []
    ds = sd["datasets"][-1]
    summary = sd["bench"].get(ds)
    if summary is None or summary.empty:
        return [], []
    profiles = [str(p) for p in summary["profile"].dropna().unique()] if "profile" in summary else []
    profile = "lan" if "lan" in profiles else (profiles[0] if profiles else None)
    udps = [int(u) for u in summary["udp_limit"].dropna().unique()] if "udp_limit" in summary else []
    udp = udps[0] if udps else None
    df = compare_hub.live_frame(compare.suite_frame(sd, ds, profile, udp)).set_index("key")
    proof = [run.path / "suite.json"]
    report = next((run.path / n for n in ("report.html",) if (run.path / n).is_file()), None)
    where = f"{terms.dataset_label('', n_names=ds).lstrip(' ·')}; network {profile or '—'}, UDP {udp or '—'}"
    trials = int(run.trials or 0)
    ci = stats.ci_label(trials) if trials else ""
    if not {"mtl", "slh-dsa"} <= set(df.index):
        return [], compare.lookup_problems(summary)

    def pair(col, fmt, unit_kind, title, key, detail):
        a, b = df.loc["mtl", col], df.loc["slh-dsa", col]
        if pd.isna(a) or pd.isna(b):
            return None
        return Card(key, title, f"{fmt(a)} vs {fmt(b)}", f"{where}. {detail}", [unit_kind], run, ci, "", report, proof)

    cards = [c for c in (
        pair("wire_bytes", results.fmt_bytes, "measured", "Resolver to authoritative bytes, cold pass", "live_bytes",
             "SLH-DSA-MTL against SLH-DSA, counted from the packet capture."),
        pair("truncations", lambda v: f"{v:,.0f}", "measured", "Truncated responses, cold pass", "live_trunc",
             "SLH-DSA-MTL against SLH-DSA."),
        pair("cold_ms", lambda v: f"{v:,.1f} ms", "indicative", "Median lookup time, cold cache", "live_cold",
             "Containers share the host CPUs, so read the ratio, not the milliseconds."),
    ) if c is not None]
    return cards, compare.lookup_problems(summary)


# ─────────────────────────── the PS-036 deliverables checklist ───────────────────────────

REQUIREMENTS = [
    ("environment", "Pinned benchmark environment", "compare"),
    ("harness", "Benchmark harness", "compare"),
    ("configs", "MTL and non-MTL workload configurations", "compare"),
    ("sizes", "Three dataset-size test cases", "compare"),
    ("trials", "Repeated-trial measurements", "compare"),
    ("performance", "Signing and verification performance results", "compare"),
    ("bytes", "Transmitted-byte comparison", "compare"),
    ("cache", "Cache-use measurements and analytical estimates", "compare"),
    ("report", "Reproducible results report", "compare"),
    ("demo", "Technical demonstration", "live"),
]


def _csv(path: Path, **kw) -> pd.DataFrame:
    try:
        return pd.read_csv(path, **kw)
    except (OSError, ValueError, pd.errors.EmptyDataError):
        return pd.DataFrame()


def _offline_rule(key: str, run: Run) -> Row | None:
    p = run.path
    cfg = yaml.safe_load((p / "config.yaml").read_text(encoding="utf-8")) or {}
    env, pre = _read_json(p / "environment.json"), _read_json(p / "preflight.json")
    tile = "compare"
    base = dict(run_id=run.id, tile=tile)
    if key == "environment":
        sw, hw = env.get("software", {}), env.get("hardware", {})
        image = str(env.get("host_image_id") or "")
        ok = image not in ("", "unknown") and sw.get("mtl_reference_commit") and hw.get("cpu_affinity")
        if not env:
            return None
        return Row(key, "", FOUND if ok else PARTIAL,
                   f"image {image[:19]}…, MTL {str(sw.get('mtl_reference_commit', '—'))[:10]}, "
                   f"core {hw.get('cpu_affinity', '—')}, stack {env.get('stack', '—')}" if ok else
                   "environment.json is present but does not record the image, MTL commit and CPU affinity",
                   proof=[p / "environment.json"], **base)
    if key == "harness":
        if not pre:
            return None
        verdict = str(pre.get("verdict", ""))
        return Row(key, "", FOUND if verdict.startswith("GO") else PARTIAL,
                   f"go/no-go gate: {verdict} ({len(pre.get('checks', []))} checks)", proof=[p / "preflight.json"], **base)
    if key == "configs":
        modes = set(cfg.get("modes", []))
        both = {"slh-dsa-mtl", "slh-dsa"} <= modes
        return Row(key, "", FOUND if both else PARTIAL,
                   "algorithms: " + ", ".join(terms.algorithm_label(m, short=True) for m in cfg.get("modes", [])),
                   proof=[p / "config.yaml"], **base)
    if key == "sizes":
        ds = cfg.get("datasets", [])
        counts = _csv(p / "datasets.csv")
        rr = dict(zip(counts.get("dataset", []), counts.get("rrsets", []))) if len(counts) else {}
        label = "; ".join(terms.dataset_label(d["name"], d["n_names"], rr.get(d["name"])) for d in ds)
        return Row(key, "", FOUND if len(ds) >= 3 else PARTIAL, label, proof=[p / "config.yaml"], **base)
    if key == "trials":
        n = int(cfg.get("trials") or 0)
        state = FOUND if n >= TRIALS_FOR_95 else (PARTIAL if n >= 2 else MISSING)
        return Row(key, "", state, f"{n} trials · {stats.ci_label(n) if n >= 2 else 'too few for an interval'}",
                   proof=[p / "config.yaml"], **base)
    if key == "performance":
        t = _csv(p / "trials.csv", usecols=lambda c: c in ("mode", "sign_total_ns", "verify_warm_total_ns"))
        if t.empty or not {"mode", "sign_total_ns", "verify_warm_total_ns"} <= set(t.columns):
            return None
        have = set(t.dropna(subset=["sign_total_ns", "verify_warm_total_ns"])["mode"])
        both = {"slh-dsa-mtl", "slh-dsa"} <= have
        return Row(key, "", FOUND if both else PARTIAL, f"trials.csv: {len(t)} rows for {len(set(t['mode']))} algorithms",
                   proof=[p / "trials.csv"], **base)
    if key == "bytes":
        r = _csv(p / "responses.csv", usecols=lambda c: c in ("mode", "response_bytes"))
        if r.empty or "mode" not in r.columns:
            return None
        both = {"slh-dsa-mtl", "slh-dsa"} <= set(r["mode"])
        return Row(key, "", FOUND if both else PARTIAL, f"responses.csv: {len(r):,} measured DNS answers",
                   proof=[p / "responses.csv"], **base)
    if key == "cache":
        c = _csv(p / "cache.csv", usecols=lambda x: x in ("kind", "scope"))
        if c.empty or "kind" not in c.columns:
            return None
        kinds = c["kind"].value_counts().to_dict()
        both = {"measured", "analytical"} <= set(kinds)
        return Row(key, "", FOUND if both else PARTIAL,
                   ", ".join(f"{n} {k} rows" for k, n in sorted(kinds.items())), proof=[p / "cache.csv"], **base)
    if key == "report":
        rep = p / "report.html"
        return Row(key, "", FOUND, "report.html in the run folder", proof=[rep], **base) if rep.is_file() else None
    return None


def _live_rule(key: str, run: Run) -> Row | None:
    p = run.path
    suite = _read_json(p / "suite.json")
    base = dict(run_id=run.id, tile="compare")
    scen = set(suite.get("scenarios") or [])
    if key == "environment":
        imgs = (suite.get("provenance") or {}).get("images") or {}
        ok = bool(imgs) and all(v.get("id") for v in imgs.values())
        pins = (suite.get("provenance") or {}).get("stack_pins") or {}
        return Row(key, "", FOUND if ok else PARTIAL,
                   f"{len(imgs)} lab images recorded, MTL {str(pins.get('MTL_COMMIT', '—'))[:10]}, "
                   f"stack {(suite.get('provenance') or {}).get('stack', '—')} (live lab, not core-pinned)",
                   proof=[p / "suite.json"], **base)
    if key == "configs":
        both = {"mtl", "slh-dsa"} <= scen
        return Row(key, "", FOUND if both else PARTIAL,
                   "algorithms: " + ", ".join(terms.algorithm_label(s, short=True) for s in sorted(scen)),
                   proof=[p / "suite.json"], **base)
    if key == "sizes":
        sizes = suite.get("sizes") or []
        return Row(key, "", FOUND if len(sizes) >= 3 else PARTIAL,
                   "; ".join(terms.dataset_label("", n_names=n).lstrip(" ·") for n in sizes), proof=[p / "suite.json"], **base)
    if key == "trials":
        n = int(suite.get("trials") or 0)
        state = FOUND if n >= TRIALS_FOR_95 else (PARTIAL if n >= 2 else MISSING)
        return Row(key, "", state, f"{n} measurement trials · {stats.ci_label(n) if n >= 2 else 'too few for an interval'}",
                   proof=[p / "suite.json"], **base)
    if key == "performance":
        if not any(p.glob("signing_trials_*.csv")) or not {"mtl", "slh-dsa"} <= scen:
            return None
        return Row(key, "", PARTIAL, "live-lab signing trials only; timings are indicative, not core-pinned",
                   proof=[p / "suite.json"], **base)
    if key == "bytes":
        sd = compare.load_suite(p)
        for ds, df in (sd or {}).get("bench", {}).items():
            if not df.empty and {"mtl", "slh-dsa"} <= set(df["scenario"]):
                return Row(key, "", FOUND, "packet-capture byte counts for both algorithms", proof=[p / "suite.json"], **base)
        return None
    if key == "report":
        rep = p / "report.html"
        return Row(key, "", FOUND, "report.html in the benchmark folder", proof=[rep], **base) if rep.is_file() else None
    return None


def checklist(offline: list[Run], live: list[Run], caps: list[Path], lab: dict | None = None,
              limit: int = 5) -> list[Row]:
    """One row per PS-036 expected outcome, with the best evidence on this machine.

    Status is evidence-based: Evidence found only when the proving file exists and passes its rule; Partial names what
    is missing; Not found means no evidence here, not that the feature is missing."""
    lab = lab or {}
    rows = []
    for key, requirement, tile in REQUIREMENTS:
        best = Row(key, requirement, MISSING, "No run on this machine contains this evidence yet.", tile=tile)
        if key == "demo":
            if caps:
                best = Row(key, requirement, FOUND, f"newest capture: {caps[0].name}", proof=[caps[0]], tile="live")
            elif lab.get("prepared") and lab.get("running"):
                best = Row(key, requirement, FOUND, "the lab is signed and running", tile="live")
            elif lab.get("prepared"):
                best = Row(key, requirement, PARTIAL, "zones are signed but the lab is not running", tile="live")
        else:
            for run in list(offline[:limit]) + list(live[:limit]):
                try:
                    row = (_offline_rule if run.source == "offline" else _live_rule)(key, run)
                except (OSError, ValueError, KeyError, yaml.YAMLError):
                    row = None
                if row is not None and RANK[row.state] > RANK[best.state]:
                    best = row
        best.requirement, best.tile = requirement, tile
        if best.state != FOUND:
            best.missing = _missing(key, best)
        rows.append(best)
    return rows


def _missing(key: str, row: Row) -> str:
    if row.state == MISSING:
        return {"harness": "no run has a preflight.json; start a run with `bash scripts/run_benchmark.sh`",
                "demo": "no capture yet: run a lookup in Demonstrate, or sign the zones and start the lab in Setup",
                }.get(key, "run `bash scripts/run_benchmark.sh configs/quick.yaml` for an offline run")
    return {"trials": f"{TRIALS_FOR_95} or more trials give a 95% interval; the default full run uses 10",
            "sizes": "a run with three dataset sizes",
            "performance": "an offline run gives pinned-core timings",
            "cache": "needs both measured and analytical rows",
            "harness": "the go/no-go gate did not report GO"}.get(key, "see the detail above")


def checklist_markdown(rows: list[Row], generated: str, root: Path = ROOT) -> str:
    """The checklist as Markdown with run ids and file paths, for an evaluator's notes."""
    out = ["# CipherOps evidence summary\n", f"Generated {generated}. Status reflects files on this machine. "
           "*Not found* means no evidence here, not that the feature is missing.\n",
           "| PS-036 expected outcome | Status | Evidence | Run | Proof |", "|---|---|---|---|---|"]
    for r in rows:
        proof = ", ".join(f"`{_rel(p, root)}`" for p in r.proof) or "—"
        detail = r.detail + (f" *(missing: {r.missing})*" if r.missing else "")
        out.append(f"| {r.requirement} | {STATE_TEXT[r.state]} | {detail} | {r.run_id or '—'} | {proof} |")
    return "\n".join(out) + "\n"


def _rel(p: Path, root: Path) -> str:
    try:
        return str(Path(p).relative_to(root))
    except ValueError:
        return str(p)


# ─────────────────────────── what to do next ───────────────────────────

def next_step(visitor: str, ready: dict, runs: dict) -> dict:
    """The one next action for a visitor. ``ready``: images/prepared/running/docker; ``runs``: offline/live counts.

    An evaluator with a run on disk is never sent to Setup, and with no run and no Docker is told how to get one."""
    has_run = bool(runs.get("offline") or runs.get("live"))
    if visitor == "evaluator":
        if has_run:
            return {"tile": "compare", "label": "Open Results", "text": "Start with the headline results below, then "
                    "open the newest run's report. Nothing needs to be built.", "settings": {
                        "cmp_view": "algorithms", "cmp_src": "offline" if runs.get("offline") else "live"}}
        return {"tile": None, "label": "", "text": "No run is stored on this machine. Run "
                "`bash scripts/run_benchmark.sh configs/quick.yaml` (about 20 minutes, needs Docker), or copy a "
                "finished run folder into `results/runs/`."}
    if visitor == "presenter":
        if not ready.get("docker", True):
            return {"tile": "setup", "label": "Open Setup", "text": "Docker is not reachable. Start Docker, then reload."}
        if ready.get("images") and ready.get("prepared") and ready.get("running"):
            return {"tile": "live", "label": "Open Demonstrate", "text": "The lab is ready. Send the first lookup."}
        if not ready.get("images"):
            return {"tile": "setup", "label": "Open Setup", "text": "Build the images first (Setup, step 1)."}
        return {"tile": "setup", "label": "Open Setup", "text": "Sign the zones and start the lab (Setup, steps 2 and 3)."}
    if visitor == "reproducer":
        if not ready.get("docker", True):
            return {"tile": None, "label": "", "text": "Docker is not reachable. Start Docker, then reload."}
        return {"tile": "offline", "label": "Open Offline benchmark", "text": "Run `bash scripts/run_benchmark.sh "
                "preflight`, then the quick or full config, here or in a terminal. The run folder lands in "
                "`results/runs/`."}
    return {"tile": "learn", "label": "Open Learn", "text": "Six short scenes, no setup needed."}


VISITORS = {
    "evaluator": "Check the PS-036 deliverables",
    "presenter": "Watch the demonstration",
    "reproducer": "Reproduce the benchmark",
    "explainer": "Understand MTL first",
}
