"""Tests for the benchmark suite's command line: parameter handling and the --reuse safeguard.
No Docker and no Streamlit."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "dashboard"))
sys.path.insert(0, str(ROOT / "ecosystem" / "src"))

from live_lab import suite  # noqa: E402

CSV_HEAD = "size,scenario,origin,tier,algorithm,n_names,rrsig_count,signed_bytes,sign_seconds,verify_seconds\n"


def _old_run(tmp_path, rows, trials=True):
    d = tmp_path / "old"
    d.mkdir()
    (d / "signing_full.csv").write_text(CSV_HEAD + "".join(
        f"20,{s},{o},sld,alg,10,27,1000,{t},0.1\n" for s, o, t in rows), encoding="utf-8")
    if trials:
        (d / "signing_trials_20.csv").write_text("scenario,trial\n", encoding="utf-8")
    return d


def _setup(monkeypatch, tmp_path, on_disk, trials=True):
    monkeypatch.setattr(suite, "SUITES", tmp_path)
    monkeypatch.setattr(suite.driver, "load_manifest", lambda h, s: {} if s in {r[0] for r in on_disk} else None)
    monkeypatch.setattr(suite, "_signing_rows", lambda h, n: [
        {"scenario": s, "origin": o, "sign_seconds": t} for s, o, t in on_disk])
    return _old_run(tmp_path, [("mtl", "zone00.test.", 1.234)], trials)


def test_reuse_accepts_the_zones_the_old_run_signed(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path, [("mtl", "zone00.test.", 1.234)])
    assert suite._check_reusable(None, 20, ["mtl"], "old").name == "signing_trials_20.csv"


def test_reuse_refuses_zones_that_were_signed_again(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path, [("mtl", "zone00.test.", 1.9)])
    with pytest.raises(RuntimeError, match="signed again"):
        suite._check_reusable(None, 20, ["mtl"], "old")


def test_reuse_refuses_when_a_scenario_was_never_signed(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path, [("mtl", "zone00.test.", 1.234)])
    with pytest.raises(RuntimeError, match="no signed zones for ecdsa"):
        suite._check_reusable(None, 20, ["mtl", "ecdsa"], "old")


def test_reuse_refuses_when_the_old_run_has_no_signing_trials(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path, [("mtl", "zone00.test.", 1.234)], trials=False)
    with pytest.raises(RuntimeError, match="signing files"):
        suite._check_reusable(None, 20, ["mtl"], "old")


@pytest.mark.parametrize("argv, message", [
    (["--sizes", "0"], "1 or more"),
    (["--scenarios", "nope"], "unknown scenario"),
    (["--networks", "nope"], "unknown network"),
    (["--reuse", "does-not-exist"], "no finished run"),
    (["--sizes", "20000000"], "--yes"),
])
def test_cli_rejects_bad_input_before_doing_anything(argv, message):
    with pytest.raises(SystemExit) as e:
        suite.main(argv)
    assert message in str(e.value)


def test_plan_prints_and_creates_nothing(capsys):
    before = set(suite.SUITES.iterdir()) if suite.SUITES.is_dir() else set()
    suite.main(["--sizes", "50", "--plan"])
    assert "Benchmark: sizes [50]" in capsys.readouterr().out
    assert (set(suite.SUITES.iterdir()) if suite.SUITES.is_dir() else set()) == before
