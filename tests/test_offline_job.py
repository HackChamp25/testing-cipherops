"""The offline-harness background job: command, progress parsing, result pickup and exclusion. No Docker."""

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "dashboard"))

from live_lab import driver, offline_job as oj  # noqa: E402


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    monkeypatch.setattr(driver, "ECO", tmp_path / "eco")
    monkeypatch.setattr(oj, "RESULTS", tmp_path / "results")
    monkeypatch.setattr(oj, "ROOT", tmp_path)
    (tmp_path / "eco" / "stacks").mkdir(parents=True)
    (tmp_path / "eco" / "stacks" / "latest.env").write_text("STACK=latest\n", encoding="utf-8")
    oj.job_dir().mkdir(parents=True)
    return tmp_path


class FakeProc:
    def __init__(self, lines, code=0):
        self.stdout, self.code = iter(lines), code

    def wait(self):
        return self.code

    def poll(self):
        return self.code


def _run(sandbox, monkeypatch, outputs, **params):
    calls = []

    def popen(cmd, **kw):
        calls.append(cmd)
        if len(calls) == 2:  # the harness run creates its results folder
            (sandbox / "results" / "runs" / "20261030T000000Z-quick-demo").mkdir(parents=True)
        return FakeProc(*outputs[len(calls) - 1])

    monkeypatch.setattr(oj, "run_environment", lambda stack: {"CIPHEROPS_GIT_SHA": "abc"})
    code = oj.run({"preset": "quick", "stack": "latest", "started": 1.0, **params}, popen=popen)
    return code, calls, json.loads((oj.job_dir() / "status.json").read_text())


def test_harness_command_matches_the_shell_script():
    assert oj.harness_command("quick", None) == "python3 -m cipherops.runner run --config configs/quick.yaml"
    assert oj.harness_command("full", 4).endswith("--config configs/scenarios.yaml --trials 4")


def test_successful_run_records_progress_and_run_id(sandbox, monkeypatch):
    (sandbox / "results" / "runs").mkdir(parents=True)
    out = [(["building\n"], 0), ([" STEP 3/7  Timing\n", "done\n"], 0)]
    code, calls, st = _run(sandbox, monkeypatch, out)
    assert code == 0 and st["state"] == "done"
    assert st["run_id"] == "20261030T000000Z-quick-demo" and st["total"] == 7 and st["done"] == 2
    assert calls[0][-1] == "build" and oj.CONTAINER in calls[1]
    assert calls[1][-1].startswith("python3 -m cipherops.runner run")


def test_failed_build_stops_before_the_harness(sandbox, monkeypatch):
    (sandbox / "results" / "runs").mkdir(parents=True)
    code, calls, st = _run(sandbox, monkeypatch, [(["boom\n"], 1)])
    assert code == 1 and st["state"] == "failed" and len(calls) == 1 and "boom" in st["error"]


def test_a_running_offline_job_blocks_other_work(sandbox):
    (oj.job_dir() / "status.json").write_text(json.dumps({"state": "running", "pid": None, "started": 9e12}))
    assert driver.active_offline()
    with pytest.raises(driver.LabBusy):
        driver.require_no_offline()
    with pytest.raises(driver.LabBusy):
        oj.start("quick")


def test_unknown_preset_is_refused(sandbox):
    with pytest.raises(RuntimeError):
        oj.start("nope")
