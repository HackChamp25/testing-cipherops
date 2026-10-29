"""One benchmark at a time across the Offline benchmark and Live-lab benchmark tiles."""

import json
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "dashboard"), str(ROOT / "src"), str(ROOT / "ecosystem" / "src")]

from live_lab import benchmark_lock as lock  # noqa: E402
from live_lab import build_job, driver, offline_job, suite  # noqa: E402
from live_lab.benchmark_lock import Running  # noqa: E402


@pytest.fixture
def eco(tmp_path, monkeypatch):
    monkeypatch.setattr(driver, "ECO", tmp_path)
    monkeypatch.setattr(driver, "SUITES_DIR", tmp_path / "results" / "suites")
    monkeypatch.setattr(suite, "SUITES", tmp_path / "results" / "suites")
    monkeypatch.delenv(driver.SUITE_OWNER_ENV, raising=False)
    monkeypatch.setattr(driver, "pid_alive", lambda pid: bool(pid) and pid != 999999)
    (tmp_path / "stacks").mkdir()
    (tmp_path / "stacks" / "latest.env").write_text("STACK=latest\n")
    return tmp_path


def _offline_status(root, **st):
    d = root / "jobs" / "_offline"
    d.mkdir(parents=True, exist_ok=True)
    (d / "status.json").write_text(json.dumps(st))


def _suite_status(root, sid, **st):
    d = root / "results" / "suites" / sid
    d.mkdir(parents=True)
    (d / "status.json").write_text(json.dumps(st))
    (d / "params.json").write_text("{}")


# ─────────────────────────── the rule itself (pure) ───────────────────────────

def test_nothing_running_means_anything_may_start():
    for kind in ("offline", "live", "build", "sign"):
        assert lock.refusal(kind, []) is None


@pytest.mark.parametrize("starting,running,refused", [
    ("offline", "offline", True), ("offline", "live", True), ("live", "offline", True), ("live", "live", True),
    ("offline", "build", True), ("offline", "sign", True), ("build", "offline", True), ("sign", "offline", True),
    ("build", "live", True), ("live", "build", True)])
def test_every_pair_of_jobs_that_share_the_cpu_is_refused(starting, running, refused):
    why = lock.refusal(starting, [Running(running, "x")])
    assert bool(why) is refused
    assert "already" in why and "Wait for it to finish, or cancel it first" in why and "CPU" in why


def test_the_message_names_what_is_running():
    off = lock.refusal("live", [Running("offline", "quick.yaml", "running")])
    assert "An offline benchmark run (quick.yaml) is already running" in off
    assert "A live-lab benchmark (s1)" in lock.refusal("offline", [Running("live", "s1")])


# ─────────────────────────── reading what is running ───────────────────────────

def test_idle_machine(eco):
    assert lock.running() == [] and lock.offline_status() == {}


def test_a_running_offline_job_is_seen_and_a_dead_worker_is_not(eco):
    _offline_status(eco, state="running", pid=4242, started=time.time(), title="quick.yaml")
    assert [r.kind for r in lock.running()] == ["offline"] and lock.running()[0].ident == "quick.yaml"
    _offline_status(eco, state="running", pid=999999, started=time.time(), title="quick.yaml")
    assert lock.running() == [] and lock.offline_status()["state"] == "stopped"
    _offline_status(eco, state="done", pid=4242, started=time.time())
    assert lock.running() == []


def test_a_starting_offline_job_counts_while_it_has_no_pid_yet(eco):
    _offline_status(eco, state="starting", started=time.time(), title="x")
    assert [r.kind for r in lock.running()] == ["offline"]
    _offline_status(eco, state="starting", started=time.time() - 3600)  # never started: ages out
    assert lock.running() == []


def test_live_suite_build_and_signing_are_seen_too(eco):
    _suite_status(eco, "s1", state="running", pid=1, started=time.time())
    assert [r.kind for r in lock.running()] == ["live"]


def test_require_free_raises_with_the_reason(eco):
    lock.require_free("offline")
    _suite_status(eco, "s1", state="running", pid=1, started=time.time())
    with pytest.raises(driver.LabBusy, match="live-lab benchmark"):
        lock.require_free("offline")


def test_the_suite_process_is_not_refused_by_its_own_record(eco, monkeypatch):
    _suite_status(eco, "s1", state="running", pid=1, started=time.time())
    monkeypatch.setenv(driver.SUITE_OWNER_ENV, "s1")
    lock.require_free("sign")  # no raise: the live benchmark itself is the owner
    _offline_status(eco, state="running", pid=4242, started=time.time())
    with pytest.raises(driver.LabBusy):
        lock.require_free("sign")  # but an offline run still blocks it


# ─────────────────────────── the launchers honour it ───────────────────────────

def test_offline_start_is_refused_while_a_live_benchmark_runs(eco, monkeypatch):
    _suite_status(eco, "s1", state="running", pid=1, started=time.time())
    launched = []
    monkeypatch.setattr(offline_job.subprocess, "Popen", lambda *a, **k: launched.append(a))
    with pytest.raises(driver.LabBusy, match="live-lab benchmark"):
        offline_job.start("run", "configs/quick.yaml", "2", "latest")
    assert launched == [] and not (eco / "jobs" / "_offline" / "status.json").exists()


def test_live_suite_create_is_refused_while_an_offline_run_runs(eco):
    _offline_status(eco, state="running", pid=4242, started=time.time(), title="quick.yaml")
    with pytest.raises(driver.LabBusy, match="offline benchmark run"):
        suite.create({"sizes": [20], "label": "a"})
    assert not (eco / "results" / "suites").exists() or not any((eco / "results" / "suites").glob("2*"))


def test_image_build_is_refused_while_an_offline_run_runs(eco):
    _offline_status(eco, state="running", pid=4242, started=time.time(), title="quick.yaml")
    with pytest.raises(driver.LabBusy, match="offline benchmark run"):
        build_job.start("latest")


def test_a_second_offline_run_is_refused(eco, monkeypatch):
    (eco.parent / "configs").mkdir(exist_ok=True)
    _offline_status(eco, state="running", pid=4242, started=time.time(), title="quick.yaml")
    monkeypatch.setattr(offline_job.subprocess, "Popen", lambda *a, **k: pytest.fail("must not launch"))
    with pytest.raises(driver.LabBusy, match="already running"):
        offline_job.start("run", "configs/quick.yaml", "2", "latest")


def test_a_free_machine_starts_the_job_and_records_it(eco, monkeypatch):
    launched = []
    monkeypatch.setattr(offline_job.subprocess, "Popen", lambda cmd, **k: launched.append(cmd))
    offline_job.start("run", "configs/quick.yaml", "2", "latest")
    st = json.loads((eco / "jobs" / "_offline" / "status.json").read_text())
    assert st["state"] == "starting" and st["config"] == "configs/quick.yaml" and st["title"] == "quick.yaml"
    assert len(launched) == 1 and launched[0][-1].endswith("params.json")
    assert [r.kind for r in lock.running()] == ["offline"]  # the 'starting' window already counts


def test_two_launchers_cannot_check_at_the_same_time(eco):
    with lock.start_lock():
        with pytest.raises(driver.LabBusy, match="being started"):
            with lock.start_lock(timeout_s=0.3):
                pass
    with lock.start_lock():  # released afterwards
        pass


def test_a_stale_launch_lock_is_cleared(eco):
    stale = eco / "jobs" / ".benchmark.lock"
    stale.mkdir(parents=True)
    old = time.time() - 120
    import os

    os.utime(stale, (old, old))
    with lock.start_lock(timeout_s=1):
        pass
