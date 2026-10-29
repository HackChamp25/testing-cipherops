"""The Offline benchmark tile's logic, as pure functions: what runs exist, what to type, what the job runs.

The offline harness is the primary measurement path (one pinned core, no network). Everything here reads files or builds
strings; the background job that actually runs it is ``offline_job``. Nothing in this module is a result: run rows are
read from ``results/runs/<id>/`` and show the run's own settings.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path

import yaml

from cipherops import stats
from live_lab import compare_hub

ROOT = Path(__file__).resolve().parents[2]
CONFIGS_DIR = ROOT / "configs"
RESULTS_DIR = ROOT / "results"
# The software stack each path defaults to is a design decision (docs/design-decisions.md): the offline harness needs
# the stack whose liboqs has the FIPS 205 names, so it defaults to `latest`.
DEFAULT_STACK = "latest"
DEFAULT_CPUSET = "2"
QUICK_CONFIG = "configs/quick.yaml"
FULL_CONFIG = "configs/scenarios.yaml"
FULL_RUN_NOTE = ("The full run takes several hours, and more than an hour even with the fewest trials, because plain "
                 "SLH-DSA signs thousands of RRsets one by one. Use the quick run for a demonstration.")


# ─────────────────────────── runs on disk ───────────────────────────

def _date(run_id: str) -> str:
    try:
        return datetime.strptime(run_id.split("-", 1)[0], "%Y%m%dT%H%M%SZ").strftime("%d %b %Y, %H:%M UTC")
    except ValueError:
        return "—"


def _verdict(path: Path) -> str:
    try:
        v = str(json.loads((path / "preflight.json").read_text(encoding="utf-8")).get("verdict", ""))
    except (OSError, json.JSONDecodeError):
        return "missing"
    return "GO" if v.startswith("GO") else ("NO-GO" if v else "missing")


def _rrsets(path: Path) -> dict[str, int]:
    """RRset count per dataset name from the run's datasets.csv ({} if absent)."""
    try:
        import pandas as pd

        d = pd.read_csv(path / "datasets.csv", usecols=["dataset", "rrsets"])
        return {str(a): int(b) for a, b in zip(d["dataset"], d["rrsets"])}
    except (OSError, ValueError, KeyError):
        return {}


def run_rows(results_dir: Path = RESULTS_DIR) -> list[dict]:
    """Finished offline runs, newest first, one dict per run for the table.

    Reuses ``compare_hub.offline_catalogue`` for the run's settings and adds the date, the dataset sizes with their
    RRset counts, the trial count with the real interval label, the MTL commit and the go/no-go verdict. The report
    path is set only when ``report.html`` exists.
    """
    rows = []
    for e in compare_hub.offline_catalogue(Path(results_dir)):
        path, facts = Path(e["path"]), e["facts"]
        trials = int(e["trials"]) if e.get("trials") else 0
        counts = _rrsets(path)
        cfg = yaml.safe_load((path / "config.yaml").read_text(encoding="utf-8")) or {}
        sizes = [f"{d['name'].capitalize()} · {int(d['n_names']):,} names"
                 + (f" · {counts[d['name']]:,} RRsets" if d["name"] in counts else "") for d in cfg.get("datasets", [])]
        report = path / "report.html"
        rows.append({
            "id": e["id"], "path": path, "date": _date(e["id"]), "sizes": sizes, "trials": trials,
            "interval": stats.ci_label(trials) if trials >= 2 else "too few trials for an interval",
            "mtl_commit": facts.get("MTL commit", "—"), "stack": facts.get("Stack profile", "—"),
            "verdict": _verdict(path), "report": report if report.is_file() else None,
        })
    return rows


# ─────────────────────────── what to type, and what the job runs ───────────────────────────

def config_choices(configs_dir: Path = CONFIGS_DIR) -> list[dict]:
    """The run configurations available, quick and full first. Settings are read from the file, never assumed."""
    out = []
    for p in sorted(Path(configs_dir).glob("*.yaml")):
        try:
            cfg = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError):
            continue
        if not {"datasets", "modes"} <= set(cfg):
            continue
        rel = f"configs/{p.name}"
        label = {QUICK_CONFIG: "Quick run", FULL_CONFIG: "Full run"}.get(rel, p.stem)
        out.append({"path": rel, "label": label, "trials": cfg.get("trials"),
                    "sizes": [f"{d['name']} ({int(d['n_names']):,} names)" for d in cfg["datasets"]]})
    order = {FULL_CONFIG: 1, QUICK_CONFIG: 0}
    return sorted(out, key=lambda c: (order.get(c["path"], 2), c["path"]))


def commands(stack: str = DEFAULT_STACK) -> list[dict]:
    """The three commands, as typed in a terminal at the repository root."""
    prefix = "" if stack == DEFAULT_STACK else f"CIPHEROPS_STACK={stack} "
    return [
        {"label": "Go/no-go gate only", "command": f"{prefix}bash scripts/run_benchmark.sh preflight",
         "note": "Builds the pinned image and checks the reference library. No numbers are produced."},
        {"label": "Quick run", "command": f"{prefix}bash scripts/run_benchmark.sh {QUICK_CONFIG}",
         "note": "A short demonstration run with small zones and few trials."},
        {"label": "Full run", "command": f"{prefix}bash scripts/run_benchmark.sh", "note": FULL_RUN_NOTE},
    ]


def build_command(kind: str, config: str, cpuset: str, stack: str, os_name: str = "posix") -> tuple[list[str], dict]:
    """The process the job starts and the environment it adds. ``kind``: ``run`` or ``preflight``."""
    if kind not in ("run", "preflight"):
        raise ValueError(f"unknown kind {kind!r}")
    if os_name == "nt":
        cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", r"scripts\run_benchmark.ps1",
               "-Cpuset", str(cpuset), "-Stack", stack]
        cmd += ["-Command", "preflight"] if kind == "preflight" else ["-Config", config]
        return cmd, {}
    cmd = ["bash", "scripts/run_benchmark.sh"] + (["preflight"] if kind == "preflight" else [config])
    cmd += [str(cpuset)]
    return cmd, {"CIPHEROPS_STACK": stack}


_CPUSET = re.compile(r"^\d+([,-]\d+)*$")


def valid_cpuset(text: str) -> bool:
    """A core list as docker accepts it: '2', '2,3' or '2-3'. Anything else would reach a shell script, so refuse it."""
    return bool(_CPUSET.match(str(text).strip()))


_CONFIG = re.compile(r"^configs/[A-Za-z0-9_.-]+\.yaml$")


def valid_config(path: str) -> bool:
    """Only a file directly under configs/, so a crafted value cannot point the job elsewhere."""
    return bool(_CONFIG.match(str(path)))


def stop_container_command() -> list[str]:
    """Lists the running benchmark container, so cancelling stops it too (killing docker compose leaves it running)."""
    return ["docker", "ps", "-q", "--filter", "label=com.docker.compose.project=cipherops",
            "--filter", "label=com.docker.compose.service=bench"]


# ─────────────────────────── reading the log ───────────────────────────

_STEP = re.compile(r"^\s*STEP (\d+)/(\d+)\s+(.*?)\s*$", re.M)
_TRIAL = re.compile(r"trial (\d+)/(\d+)\s+(\S+)\s+(\S+)")
_RUN_FOLDER = re.compile(r"(?:run folder:|Results in)\s+(\S*results/runs/\S+)")


def parse_run_folder(log: str) -> str | None:
    """The run id the harness printed ('run folder: results/runs/<id>'), or None before it has started."""
    found = _RUN_FOLDER.findall(log)
    return Path(found[-1].rstrip("/.")).name if found else None


def parse_progress(log: str) -> dict:
    """Where a run is: the current stage and, in the measuring stage, the trial number."""
    steps = _STEP.findall(log)
    out: dict = {"step": None, "steps": None, "title": "", "trial": None, "trials": None}
    if steps:
        n, total, title = steps[-1]
        out.update(step=int(n), steps=int(total), title=title)
    trial = _TRIAL.findall(log)
    if trial:
        out.update(trial=int(trial[-1][0]), trials=int(trial[-1][1]))
    return out


def progress_text(log: str) -> str:
    p = parse_progress(log)
    if p["step"] is None:
        return "Building the pinned image and starting the harness"
    text = f"Stage {p['step']} of {p['steps']}: {p['title']}"
    if p["trial"] and p["step"] == 4:
        text += f" · trial {p['trial']} of {p['trials']}"
    return text


def outcome(returncode: int, kind: str) -> tuple[str, str]:
    """(state, message) for a finished worker. The harness exits 3 when the go/no-go gate says NO-GO."""
    if returncode == 0:
        return "done", ""
    if returncode == 3:
        return "failed", "The go/no-go gate reported NO-GO, so no numbers were produced (PS-036: defer)."
    if returncode == 1:
        return "failed", "The run finished but some checks failed; see the log and the report."
    return "failed", f"The benchmark exited with code {returncode}."
