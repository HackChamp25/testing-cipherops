"""Benchmark suite: the PS-036 benchmark run end to end from a handful of parameters.

For every dataset size the suite builds a private hierarchy of that size, signs it with each chosen
scenario (timed), repeats signing and verification on a sample leaf zone (several trials), starts the
lab, replays the same seeded workload with repeated cold and warm trials, and stops the lab again.
It needs only the built images: no Setup, Prepare or running lab. Everything a reader needs to repeat
or audit the run is stored in ``ecosystem/results/suites/<id>/``.

It runs as a detached process (``python -m live_lab.suite params.json``) so a long run survives a
browser refresh, and writes ``status.json`` and ``progress.log`` for the dashboard to poll.
"""

from __future__ import annotations

import csv
import json
import os
import platform
import subprocess
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path

from live_lab import driver

SUITES = driver.ECO / "results" / "suites"
BENCH_SIZES = (50, 500, 5000)         # data names in the dataset, as in the main Cipherops benchmark
SMOKE_SIZE = 20                       # quick check that the pipeline works
DEFAULT_SIGN_TRIALS = 3
DEFAULT_SAMPLE_NAMES = 100
STEPS_PER_SIZE = 5


def bench_shape(n_names: int) -> dict:
    """Same hierarchy for every size (one TLD, up to four leaf zones, one leaf server); only names change."""
    zones = max(1, min(4, int(n_names)))
    base, rem = divmod(int(n_names), zones)
    return {
        "label": f"{n_names} names", "name": f"eco-bench-{n_names}", "tlds": ["test"], "sld_count": zones,
        "sld_sizes": [base + (1 if i < rem else 0) for i in range(zones)], "sld_servers": 1,
        "n_queries_default": 500,
    }


def sample_sizes(n_names: int, sample_names: int) -> list[int]:
    """Two sample zone sizes: the chosen one (capped by the dataset) and a quarter of it."""
    big = max(1, min(int(n_names), int(sample_names)))
    small = max(2, big // 4)
    return [big] if small >= big else [big, small]


def estimate_seconds(sizes: list[int], scenarios: list[str], jobs: int = 2, sign_trials: int = 0,
                     sample_names: int = DEFAULT_SAMPLE_NAMES) -> float:
    """Rough signing wall time (the model in driver.shape_stats) plus the sign trials; measuring adds a few
    minutes per size on top. Only meant to warn about long runs."""
    total = 0.0
    for n in sizes:
        total += driver.shape_stats(bench_shape(n), scenarios, jobs)["est_prepare_s"]
        rr = sum(driver.RRSIG_PER_NAME * s + driver.RRSIG_PER_ZONE for s in sample_sizes(n, sample_names))
        total += sign_trials * rr * sum(driver.SIGN_SECONDS_PER_RRSIG.get(s, 0.01) for s in scenarios)
    return total


# ─────────────────────────── status files ───────────────────────────

def _read(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _pid_alive(pid: int | None) -> bool:
    if not pid:
        return False
    if os.name == "nt":
        cp = subprocess.run(["tasklist", "/FI", f"PID eq {int(pid)}", "/NH"], capture_output=True, text=True,
                            creationflags=driver.NO_WINDOW)
        return str(int(pid)) in cp.stdout
    try:
        os.kill(int(pid), 0)
    except OSError:
        return False
    return True


def status(suite_id: str) -> dict:
    """Current status; a run whose process vanished without finishing is reported as 'stopped'."""
    st = _read(SUITES / suite_id / "status.json")
    if st.get("state") == "running" and not _pid_alive(st.get("pid")):
        st["state"] = "stopped"
        st["error"] = st.get("error") or "The benchmark process ended before finishing."
    return st


def list_suites() -> list[dict]:
    """Saved suites, newest first, with their parameters and status."""
    out = []
    if not SUITES.is_dir():
        return out
    for d in SUITES.iterdir():
        if not d.is_dir() or not (d / "params.json").is_file():
            continue
        params = _read(d / "params.json")
        st = status(d.name)
        try:
            when = datetime.strptime(params.get("stamp", ""), "%Y%m%d-%H%M%S").strftime("%d %b %Y, %H:%M")
        except ValueError:
            when = datetime.fromtimestamp(d.stat().st_mtime).strftime("%d %b %Y, %H:%M")
        label = params.get("label") or ""
        out.append({"id": d.name, "path": d, "params": params, "state": st.get("state", "unknown"), "when": when,
                    "label": label, "title": f"{label or 'benchmark'} - {when}",
                    "complete": st.get("state") == "done" and (d / "suite.json").is_file(),
                    "mtime": d.stat().st_mtime})
    return sorted(out, key=lambda s: s["mtime"], reverse=True)


def running_suite() -> dict | None:
    return next((s for s in list_suites() if s["state"] == "running"), None)


def start(params: dict) -> str:
    """Write the parameters and launch the suite as a detached process. Returns the suite id."""
    stamp = time.strftime("%Y%m%d-%H%M%S")
    label = driver.sanitize_label(params.get("label"))[:30]
    suite_id = f"{stamp}_{label}" if label else stamp
    d = SUITES / suite_id
    d.mkdir(parents=True, exist_ok=False)
    params = {**params, "suite_id": suite_id, "stamp": stamp, "label": label}
    (d / "params.json").write_text(json.dumps(params, indent=2), encoding="utf-8")
    (d / "status.json").write_text(json.dumps({"state": "starting", "step": "starting", "done": 0,
                                               "total": len(params["sizes"]) * STEPS_PER_SIZE}), encoding="utf-8")
    log = open(d / "progress.log", "ab")
    subprocess.Popen([sys.executable, "-m", "live_lab.suite", str(d / "params.json")],
                     cwd=Path(__file__).resolve().parents[1], stdout=log, stderr=subprocess.STDOUT,
                     stdin=subprocess.DEVNULL, env={**os.environ, "PYTHONIOENCODING": "utf-8"},
                     **driver.background_process_kwargs())
    return suite_id


def cancel(suite_id: str) -> str:
    """Stop the suite process and take down the lab it was running."""
    st = _read(SUITES / suite_id / "status.json")
    pid = st.get("pid")
    if _pid_alive(pid):
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(int(pid)), "/T", "/F"], capture_output=True,
                           creationflags=driver.NO_WINDOW)
        else:
            os.kill(int(pid), 15)
    if st.get("config"):
        try:
            driver.down(driver.LabHandle(config=st["config"], stack=st.get("stack", driver.DEFAULT_STACK)))
        except Exception:  # noqa: BLE001
            pass
    st.update(state="cancelled", step="cancelled by the user", updated=time.time())
    (SUITES / suite_id / "status.json").write_text(json.dumps(st), encoding="utf-8")
    return "cancelled"


# ─────────────────────────── the run itself ───────────────────────────

class _Run:
    def __init__(self, params: dict):
        self.p = params
        self.dir = SUITES / params["suite_id"]
        self.t0 = time.time()
        self.st = {"state": "running", "pid": os.getpid(), "started": self.t0, "done": 0,
                   "total": len(params["sizes"]) * STEPS_PER_SIZE, "step": "starting", "size": None}

    def log(self, msg: str) -> None:
        print(f"{time.strftime('%H:%M:%S')}  {msg}", flush=True)

    def step(self, msg: str, **extra) -> None:
        self.st.update(step=msg, updated=time.time(), **extra)
        self.write()
        self.log(msg)

    def tick(self) -> None:
        self.st["done"] += 1
        self.write()

    def write(self) -> None:
        (self.dir / "status.json").write_text(json.dumps(self.st), encoding="utf-8")


def _signing_rows(h: driver.LabHandle, size: int) -> list[dict]:
    rows = driver.manifest_rows(h)
    return [{"size": size, **{k: r.get(k) for k in ("scenario", "origin", "tier", "algorithm", "n_names",
             "rrsig_count", "signed_bytes", "sign_seconds", "verify_seconds")}} for r in rows]


def _write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def run_suite(p: dict) -> None:
    r = _Run(p)
    sizes, scenarios = [int(n) for n in p["sizes"]], list(p["scenarios"])
    trials, udp = int(p["trials"]), int(p["udp"])
    networks = list(p["networks"])
    detail: dict[str, dict] = {}
    full_rows: list[dict] = []
    try:
        for i, n in enumerate(sizes, 1):
            tag = f"[{i}/{len(sizes)}] {n} names"
            cfgpath = driver.write_ui_config(
                shape=bench_shape(n), scenarios=scenarios, n_queries=int(p["n_queries"]), trials=trials,
                network_run=networks, udp_limits=[udp], workload=p.get("workload"), profiles=p.get("profiles"),
                out_config=f"configs/_bench-{n}.yaml")
            h = driver.LabHandle(config=cfgpath, stack=p["stack"])
            r.st.update(size=n, config=cfgpath, stack=p["stack"])

            r.step(f"{tag}: signing every zone with {', '.join(scenarios)}")
            r.log(driver.prepare(h, jobs=int(p.get("jobs", 1)), scenarios=scenarios)[-1500:])
            r.tick()

            sample = sample_sizes(n, int(p["sample_names"]))
            r.step(f"{tag}: repeating sign and verify {p['sign_trials']} times on samples of "
                   f"{' and '.join(str(s) for s in sample)} names")
            out = f"/eco/results/suites/{p['suite_id']}/signing_trials_{n}.csv"
            r.log(driver.sign_trials(h, scenarios, int(p["sign_trials"]), sample, out)[-1500:])
            r.tick()

            r.step(f"{tag}: starting the lab")
            driver.up(h)
            r.tick()

            r.step(f"{tag}: measuring {trials} trial(s) of {p['n_queries']} lookups per scenario and network")
            label = driver.sanitize_label(f"{p.get('label') or 'bench'}-n{n}")
            r.log(driver.run_benchmark(h, scenarios=scenarios, profiles=networks, trials=trials, udp=udp,
                                       run_label=label)[-1500:])
            newest = driver.list_runs(h)
            if not newest:
                raise RuntimeError(f"no benchmark run was saved for {n} names")
            full_rows += _signing_rows(h, n)
            detail[str(n)] = {"tag": h.tag, "run_folder": newest[0]["folder"], "names": n,
                              "zones": 1 + 1 + bench_shape(n)["sld_count"], "config": cfgpath}
            r.tick()

            r.step(f"{tag}: stopping the lab")
            driver.down(h)
            r.tick()

        _write_csv(r.dir / "signing_full.csv", full_rows)
        suite = {**p, "finished": time.strftime("%Y%m%d-%H%M%S"), "seconds": round(time.time() - r.t0),
                 "sizes_detail": detail,
                 "host": {"platform": platform.platform(), "cpus": os.cpu_count(), "python": platform.python_version()}}
        (r.dir / "suite.json").write_text(json.dumps(suite, indent=2), encoding="utf-8")
        try:
            from live_lab import suite_report
            report = suite_report.write(r.dir)
            r.log(f"report: {report}")
        except Exception as e:  # noqa: BLE001 — measurements already saved; report is additive
            r.log(f"report generation failed: {e}")
        r.st.update(state="done", step="finished", updated=time.time())
        r.write()
        r.log(f"suite finished in {suite['seconds']} s")
    except Exception as e:  # noqa: BLE001
        r.st.update(state="failed", step="failed", error=str(e)[-1500:], updated=time.time())
        r.write()
        r.log("FAILED\n" + traceback.format_exc())
        try:
            if r.st.get("config"):
                driver.down(driver.LabHandle(config=r.st["config"], stack=p["stack"]))
        except Exception:  # noqa: BLE001
            pass
        raise SystemExit(1)


def main(argv: list[str] | None = None) -> None:
    argv = argv if argv is not None else sys.argv[1:]
    run_suite(json.loads(Path(argv[0]).read_text(encoding="utf-8")))


if __name__ == "__main__":
    main()
