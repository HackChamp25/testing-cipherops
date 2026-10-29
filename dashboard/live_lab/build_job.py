"""Build the lab images as a background job, so the dashboard stays usable and shows the log as it grows.

A first build compiles OpenSSL, liboqs and MTL from source and takes tens of minutes. Running it inside the
page blocked everything and showed no output until the end, so the Build button looked idle and was easy to
press twice. The job runs ``docker compose build`` in a detached worker instead:

    ecosystem/jobs/_build/
        params.json    which stack
        status.json    state: starting | running | done | failed | cancelled | stopped
        progress.log   the build output, line by line

Only one build runs at a time (any stack): two would fight over the same CPU and layer cache.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from live_lab import benchmark_lock, driver

ACTIVE_STATES = driver.ACTIVE_STATES


def job_dir() -> Path:
    return driver.jobs_dir() / "_build"


def _write_status(st: dict) -> None:
    d = job_dir()
    tmp = d / f"status.json.{os.getpid()}.tmp"
    tmp.write_text(json.dumps(st), encoding="utf-8")
    os.replace(tmp, d / "status.json")  # the page polls this file, so never leave it half-written


def status() -> dict:
    return driver.build_status()


def is_running() -> bool:
    return driver.active_build_stack() is not None


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


def start(stack: str) -> None:
    """Launch the build as a detached worker. Returns at once."""
    driver.require_no_suite()
    benchmark_lock.require_free("build")  # an offline benchmark must not share the CPU with a compile
    live = driver.active_build_stack()
    if live:
        raise driver.LabBusy(f"Images for {live} are already being built. Wait for them to finish or cancel first.")
    env_file = driver.ECO / "stacks" / f"{stack}.env"
    if not env_file.is_file():
        raise RuntimeError(f"missing stack env {env_file}")
    d = job_dir()
    d.mkdir(parents=True, exist_ok=True)
    (d / "progress.log").write_text("", encoding="utf-8")
    params = {"stack": stack, "started": time.time()}
    (d / "params.json").write_text(json.dumps(params), encoding="utf-8")
    _write_status({"state": "starting", "stack": stack, "started": params["started"]})
    subprocess.Popen([sys.executable, "-m", "live_lab.build_job", str(d / "params.json")],
                     cwd=Path(__file__).resolve().parents[1], stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                     env={**os.environ, "PYTHONIOENCODING": "utf-8"}, **driver.background_process_kwargs())


def cancel() -> None:
    """Stop the worker and the docker build it started."""
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
    st = driver._read_json(job_dir() / "status.json") or st
    st.update(state="cancelled", finished=time.time(), handled=True)
    _write_status(st)


# ───────────────────────────── worker ─────────────────────────────

def run(params: dict, *, popen=subprocess.Popen) -> int:
    stack = params["stack"]
    d = job_dir()
    st = {"state": "running", "pid": os.getpid(), "stack": stack, "started": params["started"]}
    _write_status(st)
    cmd = driver.build_command(stack)
    env = {**os.environ, "BUILDKIT_PROGRESS": "plain"}
    proc = None

    def stop(*_):
        if proc is not None and proc.poll() is None:
            proc.terminate()
        raise SystemExit(143)

    if os.name != "nt":
        signal.signal(signal.SIGTERM, stop)
    tail: list[str] = []
    try:
        with open(d / "progress.log", "a", encoding="utf-8", errors="replace") as log:
            log.write("$ " + " ".join(cmd) + "\n")
            log.flush()
            proc = popen(cmd, cwd=driver.ECO, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                         errors="replace", env=env, creationflags=driver.NO_WINDOW)
            for line in proc.stdout:
                log.write(line)
                log.flush()
                tail = (tail + [line])[-40:]
            code = proc.wait()
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        st.update(state="failed", error=str(e)[-1500:], finished=time.time())
        _write_status(st)
        return 1
    if code == 0:
        st.update(state="done", finished=time.time(), returncode=0)
    else:
        st.update(state="failed", finished=time.time(), returncode=code,
                  error=f"docker compose build exited with {code}\n{''.join(tail)[-1500:]}")
    _write_status(st)
    return 0 if code == 0 else 1


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    return run(json.loads(Path(argv[0]).read_text(encoding="utf-8")))


if __name__ == "__main__":
    sys.exit(main())
