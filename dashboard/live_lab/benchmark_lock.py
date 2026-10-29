"""One benchmark at a time, across the Offline benchmark and Live-lab benchmark tiles.

Two benchmarks on one machine compete for the CPU and distort each other's timings, and an image build or a signing job
does the same. ``refusal`` is the whole rule and is pure: given what is running, may this kind of job start? The
functions that read the machine's job files, and the lock that makes "check nothing runs, then start" atomic, are thin
wrappers around it.

Kinds: ``offline`` (an offline benchmark run or its go/no-go gate), ``live`` (a live-lab benchmark), ``build`` (an image
build), ``sign`` (signing zones for the live lab).
"""

from __future__ import annotations

import contextlib
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from live_lab import driver

OFFLINE_JOB_DIR_NAME = "_offline"

# What a running job is called in a refusal, and what starting each kind would disturb.
NAME = {"offline": "An offline benchmark run", "live": "A live-lab benchmark", "build": "An image build",
        "sign": "Signing zones"}
BLOCKED_BY = {
    "offline": ("offline", "live", "build", "sign"),
    "live": ("offline", "live", "build", "sign"),
    "build": ("offline", "live", "build"),
    "sign": ("offline", "live", "build", "sign"),
}


@dataclass(frozen=True)
class Running:
    kind: str
    ident: str = ""
    state: str = "running"

    def describe(self) -> str:
        return f"{NAME[self.kind]}{f' ({self.ident})' if self.ident else ''} is already {self.state}"


def refusal(kind: str, running: list[Running]) -> str | None:
    """Why a job of ``kind`` may not start now, in plain words, or None when it may."""
    for r in running:
        if r.kind in BLOCKED_BY[kind]:
            return (f"{r.describe()}. Two jobs would share the CPU and distort the timings. "
                    f"Wait for it to finish, or cancel it first.")
    return None


def job_dir() -> Path:
    return driver.jobs_dir() / OFFLINE_JOB_DIR_NAME


def offline_status() -> dict:
    """Status of the offline job ({} if none ever ran); a worker that vanished reads as 'stopped'."""
    return driver.effective_job_state(driver._read_json(job_dir() / "status.json"))


def running() -> list[Running]:
    """Everything that is starting or running on this machine right now."""
    out: list[Running] = []
    off = offline_status()
    if off.get("state") in driver.ACTIVE_STATES:
        out.append(Running("offline", str(off.get("title") or off.get("config") or ""), off["state"]))
    suite = driver.active_suite_id()
    if suite:
        out.append(Running("live", suite))
    build = driver.active_build_stack()
    if build:
        out.append(Running("build", build))
    for tag in driver.active_prepare_tags():
        out.append(Running("sign", tag))
    return out


def require_free(kind: str) -> None:
    """Raise ``driver.LabBusy`` with the reason if a job of ``kind`` may not start."""
    rs = running()
    if owned_by_this_process():  # the live-lab suite's own process is that benchmark, not a competitor
        rs = [r for r in rs if r.kind != "live"]
    why = refusal(kind, rs)
    if why:
        raise driver.LabBusy(why)


@contextlib.contextmanager
def start_lock(timeout_s: float = 10.0):
    """Make 'check nothing is running, then launch' atomic across dashboard sessions and the command line."""
    root = driver.jobs_dir()
    root.mkdir(parents=True, exist_ok=True)
    lock = root / ".benchmark.lock"
    deadline = time.time() + timeout_s
    while True:
        try:
            lock.mkdir()
            break
        except FileExistsError:
            try:
                if time.time() - lock.stat().st_mtime > 30:  # left behind by a crashed launcher
                    shutil.rmtree(lock, ignore_errors=True)
                    continue
            except OSError:
                continue
            if time.time() > deadline:
                raise driver.LabBusy("Another benchmark is being started. Try again in a moment.")
            time.sleep(0.1)
    try:
        yield
    finally:
        shutil.rmtree(lock, ignore_errors=True)


def owned_by_this_process() -> bool:
    """True inside the live-lab suite's own process, which must not be refused by its own record."""
    return bool(os.environ.get(driver.SUITE_OWNER_ENV))
