"""Run the offline benchmark as a background job, so the dashboard stays usable and shows the log as it grows.

Same pattern as ``build_job``: a detached worker runs ``scripts/run_benchmark.sh`` (or the PowerShell script) and the page
polls two small files.

    ecosystem/jobs/_offline/
        params.json    kind (run | preflight), config, cpuset, stack
        status.json    state: starting | running | done | failed | cancelled | stopped, and the run id once printed
        progress.log   the script's output, line by line

Only one benchmark runs at a time across both benchmark tiles (``benchmark_lock``). The job is started on the host, and
the harness itself runs in the pinned image on one dedicated core, exactly as on the command line.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from live_lab import benchmark_lock, driver, offline_bench

ACTIVE_STATES = driver.ACTIVE_STATES
ROOT = offline_bench.ROOT


def job_dir() -> Path:
    return benchmark_lock.job_dir()


def _write_status(st: dict) -> None:
    d = job_dir()
    tmp = d / f"status.json.{os.getpid()}.tmp"
    tmp.write_text(json.dumps(st), encoding="utf-8")
    os.replace(tmp, d / "status.json")  # the page polls this file, so never leave it half-written


def status() -> dict:
    return benchmark_lock.offline_status()


def is_running() -> bool:
    return status().get("state") in ACTIVE_STATES


def log_text(tail: int = 6000) -> str:
    try:
        return (job_dir() / "progress.log").read_text(encoding="utf-8", errors="replace")[-tail:]
    except OSError:
        return ""


def mark_handled() -> None:
    st = driver._read_json(job_dir() / "status.json")
    if st:
        st["handled"] = True
        _write_status(st)


def start(kind: str, config: str, cpuset: str = offline_bench.DEFAULT_CPUSET,
          stack: str = offline_bench.DEFAULT_STACK) -> None:
    """Launch the job as a detached worker. Returns at once. Raises ``driver.LabBusy`` if anything else is running."""
    if not offline_bench.valid_cpuset(cpuset):
        raise ValueError(f"invalid CPU core {cpuset!r}: use a number such as 2")
    if kind == "run" and not (offline_bench.valid_config(config) and (ROOT / config).is_file()):
        raise RuntimeError(f"missing config {config}")
    if not (driver.ECO / "stacks" / f"{stack}.env").is_file():
        raise RuntimeError(f"unknown software stack {stack}")
    with benchmark_lock.start_lock():
        benchmark_lock.require_free("offline")
        d = job_dir()
        d.mkdir(parents=True, exist_ok=True)
        (d / "progress.log").write_text("", encoding="utf-8")
        params = {"kind": kind, "config": config, "cpuset": str(cpuset), "stack": stack, "started": time.time(),
                  "title": "go/no-go gate" if kind == "preflight" else Path(config).name}
        (d / "params.json").write_text(json.dumps(params), encoding="utf-8")
        _write_status({"state": "starting", **params})
        subprocess.Popen([sys.executable, "-m", "live_lab.offline_job", str(d / "params.json")],
                         cwd=Path(__file__).resolve().parents[1], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                         env={**os.environ, "PYTHONIOENCODING": "utf-8"}, **driver.background_process_kwargs())


def _stop_container(run=None) -> None:
    """The harness runs in a container that outlives the docker client, so stop it explicitly."""
    run = run or subprocess.run
    try:
        ids = run(offline_bench.stop_container_command(), capture_output=True, text=True, timeout=20,
                  creationflags=driver.NO_WINDOW).stdout.split()
        if ids:
            run(["docker", "stop", *ids], capture_output=True, text=True, timeout=60, creationflags=driver.NO_WINDOW)
    except (OSError, subprocess.SubprocessError):
        pass


def cancel() -> None:
    """Stop the worker, the script it started and the benchmark container."""
    st = driver._read_json(job_dir() / "status.json")
    pid = st.get("pid")
    if driver.pid_alive(pid):
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(int(pid)), "/T", "/F"], capture_output=True,
                           creationflags=driver.NO_WINDOW)
        else:
            os.kill(int(pid), signal.SIGTERM)  # the worker stops its child and records the result
            deadline = time.time() + 10
            while driver.pid_alive(pid) and time.time() < deadline:
                time.sleep(0.1)
    _stop_container()
    st = driver._read_json(job_dir() / "status.json") or st
    st.update(state="cancelled", finished=time.time(), handled=True)
    _write_status(st)


# ───────────────────────────── worker ─────────────────────────────

def run(params: dict, *, popen=subprocess.Popen) -> int:
    d = job_dir()
    st = {"state": "running", "pid": os.getpid(), **{k: params[k] for k in ("kind", "config", "cpuset", "stack",
                                                                           "started", "title")}}
    _write_status(st)
    cmd, extra_env = offline_bench.build_command(params["kind"], params["config"], params["cpuset"], params["stack"],
                                                  os.name)
    proc = None

    def stop(*_):
        if proc is not None and proc.poll() is None:
            proc.terminate()
        raise SystemExit(143)

    if os.name != "nt":
        signal.signal(signal.SIGTERM, stop)
    tail: list[str] = []
    seen = False
    try:
        with open(d / "progress.log", "a", encoding="utf-8", errors="replace") as log:
            log.write("$ " + " ".join(f"{k}={v}" for k, v in extra_env.items()) + (" " if extra_env else "")
                      + " ".join(cmd) + "\n")
            log.flush()
            proc = popen(cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace",
                         env={**os.environ, **extra_env}, creationflags=driver.NO_WINDOW)
            for line in proc.stdout:
                log.write(line)
                log.flush()
                tail = (tail + [line])[-40:]
                if not seen:
                    run_id = offline_bench.parse_run_folder(line)
                    if run_id:
                        seen = True
                        st["run_id"] = run_id
                        _write_status(st)
            code = proc.wait()
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        st.update(state="failed", error=str(e)[-1500:], finished=time.time())
        _write_status(st)
        return 1
    state, message = offline_bench.outcome(code, params["kind"])
    st.update(state=state, finished=time.time(), returncode=code)
    if state != "done":
        st["error"] = (message + "\n" + "".join(tail)[-1200:]).strip()
    _write_status(st)
    return 0 if code == 0 else 1


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    return run(json.loads(Path(argv[0]).read_text(encoding="utf-8")))


if __name__ == "__main__":
    sys.exit(main())
