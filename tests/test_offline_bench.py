"""The Offline benchmark tile: the run listing, the commands, the job's process and the log it reads."""

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "dashboard"), str(ROOT / "src"), str(ROOT / "ecosystem" / "src"), str(ROOT / "tests")]

from fixtures_home import make_offline_run  # noqa: E402
from live_lab import driver, offline_bench as ob, offline_job  # noqa: E402


# ─────────────────────────── the run listing ───────────────────────────

def test_no_runs_gives_an_empty_listing(tmp_path):
    assert ob.run_rows(tmp_path / "results") == []


def test_runs_are_listed_newest_first_with_what_the_table_shows(tmp_path):
    results = tmp_path / "results"
    make_offline_run(results, "20261001T120000Z-old", trials=3)
    make_offline_run(results, "20261003T093000Z-new", trials=10)
    rows = ob.run_rows(results)
    assert [r["id"] for r in rows] == ["20261003T093000Z-new", "20261001T120000Z-old"]
    new = rows[0]
    assert new["date"] == "03 Oct 2026, 09:30 UTC"
    assert new["sizes"] == ["Small · 20 names · 45 RRsets", "Medium · 60 names · 125 RRsets", "Large · 200 names · 405 RRsets"]
    assert new["trials"] == 10 and "CI of the median over 10 trials" in new["interval"]
    assert new["mtl_commit"] == "7cef0191da" and new["stack"] == "latest" and new["verdict"] == "GO"
    assert new["report"] == results / "runs" / "20261003T093000Z-new" / "report.html"
    assert "below the 95% target" in rows[1]["interval"] or "3 trials" in rows[1]["interval"]


def test_verdict_and_report_reflect_the_files(tmp_path):
    results = tmp_path / "results"
    make_offline_run(results, "20261001T000000Z-a", preflight=False, report=False)
    row = ob.run_rows(results)[0]
    assert row["verdict"] == "missing" and row["report"] is None
    p = make_offline_run(results, "20261002T000000Z-b")
    (p / "preflight.json").write_text(json.dumps({"verdict": "NO-GO (defer per PS-036)", "checks": []}))
    assert ob.run_rows(results)[0]["verdict"] == "NO-GO"


def test_a_run_without_datasets_csv_still_lists_its_sizes(tmp_path):
    p = make_offline_run(tmp_path / "results")
    (p / "datasets.csv").unlink()
    assert ob.run_rows(tmp_path / "results")[0]["sizes"][0] == "Small · 20 names"


def test_unfinished_runs_are_not_listed(tmp_path):
    (tmp_path / "results" / "runs" / "20261001T000000Z-half").mkdir(parents=True)
    assert ob.run_rows(tmp_path / "results") == []


def test_one_trial_has_no_interval_to_report(tmp_path):
    make_offline_run(tmp_path / "results", trials=1)
    assert ob.run_rows(tmp_path / "results")[0]["interval"] == "too few trials for an interval"


# ─────────────────────────── configurations and commands ───────────────────────────

def test_config_choices_read_the_files_and_put_quick_and_full_first(tmp_path):
    d = tmp_path / "configs"
    d.mkdir()
    base = "seed: 1\nmodes: [a]\n"
    (d / "scenarios.yaml").write_text(base + "trials: 10\ndatasets: [{name: small, n_names: 50}]\n")
    (d / "quick.yaml").write_text(base + "trials: 3\ndatasets: [{name: small, n_names: 20}, {name: large, n_names: 200}]\n")
    (d / "custom.yaml").write_text(base + "trials: 7\ndatasets: [{name: small, n_names: 5}]\n")
    (d / "not_a_run.yaml").write_text("something: else\n")
    got = ob.config_choices(d)
    assert [c["path"] for c in got] == ["configs/quick.yaml", "configs/scenarios.yaml", "configs/custom.yaml"]
    assert [c["label"] for c in got] == ["Quick run", "Full run", "custom"]
    assert got[0]["trials"] == 3 and got[0]["sizes"] == ["small (20 names)", "large (200 names)"]


def test_the_real_configs_are_offered():
    paths = [c["path"] for c in ob.config_choices()]
    assert paths[:2] == ["configs/quick.yaml", "configs/scenarios.yaml"]


def test_commands_and_the_long_run_note():
    cmds = ob.commands()
    assert [c["label"] for c in cmds] == ["Go/no-go gate only", "Quick run", "Full run"]
    assert cmds[0]["command"] == "bash scripts/run_benchmark.sh preflight"
    assert cmds[1]["command"] == "bash scripts/run_benchmark.sh configs/quick.yaml"
    assert cmds[2]["command"] == "bash scripts/run_benchmark.sh"
    assert "more than an hour" in cmds[2]["note"] and "several hours" in cmds[2]["note"]
    assert ob.commands("draft06")[1]["command"].startswith("CIPHEROPS_STACK=draft06 bash scripts/run_benchmark.sh")


def test_the_job_runs_the_same_script_as_the_command_line():
    cmd, env = ob.build_command("run", "configs/quick.yaml", "2", "latest")
    assert cmd == ["bash", "scripts/run_benchmark.sh", "configs/quick.yaml", "2"] and env == {"CIPHEROPS_STACK": "latest"}
    cmd, _ = ob.build_command("preflight", "ignored", "3", "latest")
    assert cmd == ["bash", "scripts/run_benchmark.sh", "preflight", "3"]
    cmd, env = ob.build_command("run", "configs/quick.yaml", "2", "latest", "nt")
    assert cmd[:6] == ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", r"scripts\run_benchmark.ps1"]
    assert cmd[-2:] == ["-Config", "configs/quick.yaml"] and env == {}
    assert ob.build_command("preflight", "x", "2", "latest", "nt")[0][-2:] == ["-Command", "preflight"]
    with pytest.raises(ValueError):
        ob.build_command("rm", "x", "2", "latest")


@pytest.mark.parametrize("text,ok", [("2", True), ("2,3", True), ("2-3", True), (" 2 ", True), ("", False),
                                     ("2;rm", False), ("$(id)", False), ("-1", False), ("a", False)])
def test_cpuset_is_validated(text, ok):
    assert ob.valid_cpuset(text) is ok


@pytest.mark.parametrize("path,ok", [("configs/quick.yaml", True), ("configs/my-run_2.yaml", True),
                                     ("../configs/quick.yaml", False), ("/etc/passwd", False),
                                     ("configs/../x.yaml", False), ("configs/a/b.yaml", False), ("quick.yaml", False)])
def test_config_path_is_confined_to_configs(path, ok):
    assert ob.valid_config(path) is ok


# ─────────────────────────── reading the log ───────────────────────────

LOG = """$ CIPHEROPS_STACK=latest bash scripts/run_benchmark.sh configs/quick.yaml 2
[19:00:01] run folder: results/runs/20261029T190001Z-quick-demo

==============================================================================
 STEP 3/7  Build zones and RFC 4034 signing inputs
==============================================================================
 STEP 4/7  Sign and verify every RRset, repeated trials
[19:01:10] trial 2/3 small   slh-dsa-mtl  signed=45 sign=0.7s
"""


def test_run_folder_is_read_from_the_harness_output():
    assert ob.parse_run_folder("nothing yet") is None
    assert ob.parse_run_folder(LOG) == "20261029T190001Z-quick-demo"
    assert ob.parse_run_folder("DONE. 54 trials. Results in results/runs/20261029T192326Z-quick-demo\n") == "20261029T192326Z-quick-demo"
    assert ob.parse_run_folder("run folder: /work/results/runs/20261029T190001Z-x/") == "20261029T190001Z-x"


def test_progress_reads_the_stage_and_the_trial():
    p = ob.parse_progress(LOG)
    assert (p["step"], p["steps"], p["trial"], p["trials"]) == (4, 7, 2, 3) and "repeated trials" in p["title"]
    assert ob.progress_text(LOG) == "Stage 4 of 7: Sign and verify every RRset, repeated trials · trial 2 of 3"
    assert ob.progress_text("") == "Building the pinned image and starting the harness"
    assert ob.progress_text(" STEP 6/7  Statistics\n").startswith("Stage 6 of 7: Statistics")
    assert "trial" not in ob.progress_text(" STEP 6/7  Statistics\ntrial 2/3 small mode\n")


def test_exit_codes_become_plain_outcomes():
    assert ob.outcome(0, "run") == ("done", "")
    state, msg = ob.outcome(3, "preflight")
    assert state == "failed" and "NO-GO" in msg
    assert ob.outcome(1, "run")[0] == "failed" and "checks failed" in ob.outcome(1, "run")[1]
    assert "code 137" in ob.outcome(137, "run")[1]


# ─────────────────────────── the worker ───────────────────────────

class _Proc:
    def __init__(self, lines, code):
        self.stdout, self._code = iter(lines), code

    def wait(self):
        return self._code

    def poll(self):
        return self._code

    def terminate(self):
        pass


@pytest.fixture
def eco(tmp_path, monkeypatch):
    monkeypatch.setattr(driver, "ECO", tmp_path)
    return tmp_path


def _params():
    return {"kind": "run", "config": "configs/quick.yaml", "cpuset": "2", "stack": "latest", "started": 1.0,
            "title": "quick.yaml"}


def _status(eco):
    return json.loads((eco / "jobs" / "_offline" / "status.json").read_text())


def test_worker_streams_the_log_records_the_run_and_finishes(eco):
    (eco / "jobs" / "_offline").mkdir(parents=True)
    seen = {}

    def popen(cmd, **kw):
        seen["cmd"], seen["env"], seen["cwd"] = cmd, kw["env"], kw["cwd"]
        return _Proc(LOG.splitlines(keepends=True), 0)

    assert offline_job.run(_params(), popen=popen) == 0
    st = _status(eco)
    assert st["state"] == "done" and st["run_id"] == "20261029T190001Z-quick-demo" and st["returncode"] == 0
    assert seen["cmd"] == ["bash", "scripts/run_benchmark.sh", "configs/quick.yaml", "2"]
    assert seen["env"]["CIPHEROPS_STACK"] == "latest" and seen["cwd"] == offline_job.ROOT
    log = (eco / "jobs" / "_offline" / "progress.log").read_text()
    assert log.startswith("$ CIPHEROPS_STACK=latest bash scripts/run_benchmark.sh") and "STEP 4/7" in log


def test_a_no_go_gate_is_a_failure_with_its_reason(eco):
    (eco / "jobs" / "_offline").mkdir(parents=True)
    code = offline_job.run({**_params(), "kind": "preflight"}, popen=lambda cmd, **kw: _Proc(["verdict: NO-GO\n"], 3))
    st = _status(eco)
    assert code == 1 and st["state"] == "failed" and "NO-GO" in st["error"] and "verdict: NO-GO" in st["error"]


def test_a_script_that_cannot_start_is_reported_not_raised(eco):
    (eco / "jobs" / "_offline").mkdir(parents=True)

    def popen(cmd, **kw):
        raise FileNotFoundError("bash")

    assert offline_job.run(_params(), popen=popen) == 1
    assert _status(eco)["state"] == "failed" and "bash" in _status(eco)["error"]


def test_cancel_stops_the_benchmark_container_too(eco, monkeypatch):
    (eco / "jobs" / "_offline").mkdir(parents=True)
    (eco / "jobs" / "_offline" / "status.json").write_text(json.dumps({"state": "running", "pid": None}))
    calls = []

    class R:
        stdout = "abc123\ndef456\n"

    monkeypatch.setattr(offline_job.subprocess, "run", lambda cmd, **kw: calls.append(cmd) or R())
    offline_job.cancel()
    assert calls[0] == ob.stop_container_command() and calls[1] == ["docker", "stop", "abc123", "def456"]
    st = _status(eco)
    assert st["state"] == "cancelled" and st["handled"] is True


def test_start_refuses_bad_input_before_launching(eco, monkeypatch):
    (eco / "stacks").mkdir()
    (eco / "stacks" / "latest.env").write_text("STACK=latest\n")
    monkeypatch.setattr(offline_job.subprocess, "Popen", lambda *a, **k: pytest.fail("must not launch"))
    with pytest.raises(ValueError, match="CPU core"):
        offline_job.start("run", "configs/quick.yaml", "2;rm -rf /", "latest")
    with pytest.raises(RuntimeError, match="missing config"):
        offline_job.start("run", "../../etc/passwd", "2", "latest")
    with pytest.raises(RuntimeError, match="unknown software stack"):
        offline_job.start("run", "configs/quick.yaml", "2", "nope")
