"""The evidence readers behind the home page: finished runs, headline cards, the PS-036 checklist, next step."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "dashboard"), str(ROOT / "src"), str(ROOT / "tests")]

from fixtures_home import make_live_suite, make_offline_run  # noqa: E402
from live_lab import compare, evidence  # noqa: E402


def _rows(offline, live, caps=(), lab=None):
    return {r.key: r for r in evidence.checklist(offline, live, list(caps), lab)}


def _setup(tmp_path, monkeypatch, offline=None, live=None):
    results = tmp_path / "results"
    eco = tmp_path / "eco"
    suites = eco / "results" / "suites"
    monkeypatch.setattr(compare, "ECO", eco)
    if offline is not None:
        make_offline_run(results, **offline)
    if live is not None:
        make_live_suite(suites, eco / "results", **live)
    return evidence.offline_runs(results), evidence.live_runs(suites)


def test_empty_machine_has_no_evidence_and_says_how_to_get_it(tmp_path, monkeypatch):
    off, live = _setup(tmp_path, monkeypatch)
    assert off == [] and live == []
    rows = _rows(off, live)
    assert set(r.state for r in rows.values()) == {evidence.MISSING}
    assert "run_benchmark.sh" in rows["environment"].missing and len(rows) == 10


def test_only_finished_runs_count(tmp_path, monkeypatch):
    results = tmp_path / "results"
    (results / "runs" / "20261001T000000Z-half").mkdir(parents=True)
    (results / "runs" / "20261001T000000Z-half" / "config.yaml").write_text("trials: 3\n")
    assert evidence.offline_runs(results) == []
    make_offline_run(results, "20261002T000000Z-ok")
    assert [r.id for r in evidence.offline_runs(results)] == ["20261002T000000Z-ok"]


def test_offline_run_gives_found_rows_with_proof_files(tmp_path, monkeypatch):
    off, live = _setup(tmp_path, monkeypatch, offline={})
    rows = _rows(off, live)
    for key in ("environment", "harness", "configs", "sizes", "trials", "performance", "bytes", "cache", "report"):
        assert rows[key].state == evidence.FOUND, key
        assert rows[key].run_id == off[0].id and rows[key].proof and rows[key].proof[0].is_file()
    assert "7cef0191da" in rows["environment"].detail and "core [2]" in rows["environment"].detail
    assert "Large · 200 names · 405 RRsets" in rows["sizes"].detail
    assert "2 measured rows" in rows["cache"].detail and "1 analytical rows" in rows["cache"].detail


@pytest.mark.parametrize("n,state", [(1, evidence.MISSING), (2, evidence.PARTIAL), (5, evidence.PARTIAL),
                                     (6, evidence.FOUND), (10, evidence.FOUND)])
def test_trial_count_decides_the_trials_row(tmp_path, monkeypatch, n, state):
    off, live = _setup(tmp_path, monkeypatch, offline={"trials": n})
    row = _rows(off, live)["trials"]
    assert row.state == state
    if n >= 2:
        assert f"{n} trials" in row.detail and "CI of the median" in row.detail  # the real interval label
    if state != evidence.FOUND:
        assert row.missing


def test_missing_preflight_is_never_found(tmp_path, monkeypatch):
    off, live = _setup(tmp_path, monkeypatch, offline={"preflight": False})
    assert _rows(off, live)["harness"].state == evidence.MISSING


def test_one_algorithm_only_is_partial(tmp_path, monkeypatch):
    off, live = _setup(tmp_path, monkeypatch, offline={"modes": ("ed25519", "slh-dsa")})
    rows = _rows(off, live)
    assert rows["configs"].state == evidence.PARTIAL and rows["performance"].state == evidence.PARTIAL
    assert rows["bytes"].state == evidence.PARTIAL


def test_live_only_machine_gives_indicative_partial_for_timings(tmp_path, monkeypatch):
    off, live = _setup(tmp_path, monkeypatch, live={})
    assert off == [] and len(live) == 1 and live[0].trials == 5
    rows = _rows(off, live)
    assert rows["configs"].state == evidence.FOUND and rows["sizes"].state == evidence.FOUND
    assert rows["bytes"].state == evidence.FOUND and rows["environment"].state == evidence.FOUND
    assert rows["performance"].state == evidence.PARTIAL and "indicative" in rows["performance"].detail
    assert rows["harness"].state == evidence.MISSING  # the gate belongs to the offline run
    assert rows["report"].state == evidence.MISSING
    off2, live2 = _setup(tmp_path / "b", monkeypatch, live={"report": True})
    assert _rows(off2, live2)["report"].state == evidence.FOUND


def test_both_paths_prefer_the_stronger_evidence(tmp_path, monkeypatch):
    off, live = _setup(tmp_path, monkeypatch, offline={"trials": 3}, live={"trials": 8})
    rows = _rows(off, live)
    assert rows["trials"].state == evidence.FOUND and rows["trials"].run_id == live[0].id  # 8 live trials beat 3
    assert rows["performance"].state == evidence.FOUND and rows["performance"].run_id == off[0].id


def test_demonstration_evidence(tmp_path):
    cap = tmp_path / "live-1.pcap"
    cap.write_bytes(b"x")
    assert _rows([], [], [cap])["demo"].state == evidence.FOUND
    assert _rows([], [], [], {"prepared": True, "running": True})["demo"].state == evidence.FOUND
    assert _rows([], [], [], {"prepared": True, "running": False})["demo"].state == evidence.PARTIAL
    assert _rows([], [], [], {})["demo"].state == evidence.MISSING


def test_headline_cards_carry_run_trials_interval_and_one_badge(tmp_path, monkeypatch):
    off, _ = _setup(tmp_path, monkeypatch, offline={"trials": 6})
    cards = evidence.offline_cards(off[0])
    assert [c.key for c in cards] == ["signature_bytes", "sign", "verify", "fit"]
    for c in cards:
        assert c.run.id == off[0].id and c.run.trials == 6 and "CI of the median over 6 trials" in c.ci
        assert len(c.badges) == 1 and c.badges[0] == "measured"
        assert c.proof and c.report and c.report.name == "report.html"
    assert cards[0].value == "156 B vs 7.86 KB"
    assert "less time" in cards[1].detail and cards[3].value == "100% vs 0%"


def test_a_scaled_direct_time_is_labelled_extrapolated_and_never_mixed(tmp_path, monkeypatch):
    off, _ = _setup(tmp_path, monkeypatch, offline={"limited_direct": True})
    by = {c.key: c for c in evidence.offline_cards(off[0])}
    assert by["sign"].badges == ["extrapolated"] and by["verify"].badges == ["extrapolated"]
    assert by["signature_bytes"].badges == ["measured"]
    assert "scaled" in by["sign"].note or "sample" in by["sign"].note


def test_no_cards_without_the_two_algorithms(tmp_path, monkeypatch):
    off, _ = _setup(tmp_path, monkeypatch, offline={"modes": ("ed25519",)})
    assert evidence.offline_cards(off[0]) == []


def test_live_cards_are_measured_bytes_and_indicative_timing(tmp_path, monkeypatch):
    _, live = _setup(tmp_path, monkeypatch, live={})
    cards, notes = evidence.live_cards(live[0])
    assert notes == [] and [c.key for c in cards] == ["live_bytes", "live_trunc", "live_cold"]
    assert [c.badges for c in cards] == [["measured"], ["measured"], ["indicative"]]
    assert all(c.run.id == live[0].id and "CI of the median over 5 trials" in c.ci for c in cards)


def test_failed_lookups_are_reported_not_hidden(tmp_path, monkeypatch):
    import pandas as pd

    _, live = _setup(tmp_path, monkeypatch, live={})
    f = tmp_path / "eco" / "results" / "tag" / "run5000" / "summary.csv"
    df = pd.read_csv(f)
    df.loc[(df.scenario == "slh-dsa") & (df["pass"] == "cold"), ["failed", "servfail", "valid_trials"]] = [30, 30, 0]
    df.to_csv(f, index=False)
    _, notes = evidence.live_cards(live[0])
    assert any("slh-dsa" in n and "SERVFAIL 30" in n for n in notes)


def test_next_step_never_sends_an_evaluator_with_runs_to_setup():
    for ready in ({}, {"docker": False}, {"images": False, "docker": True}):
        s = evidence.next_step("evaluator", ready, {"offline": 1, "live": 0})
        assert s["tile"] == "compare" and s["settings"]["cmp_src"] == "offline"
    s = evidence.next_step("evaluator", {}, {"offline": 0, "live": 2})
    assert s["tile"] == "compare" and s["settings"]["cmp_src"] == "live"


def test_next_step_with_no_runs_says_how_to_get_one():
    s = evidence.next_step("evaluator", {"docker": False}, {"offline": 0, "live": 0})
    assert s["tile"] is None and "run_benchmark.sh configs/quick.yaml" in s["text"]


def test_next_step_for_the_other_visitors():
    ready = {"images": True, "prepared": True, "running": True, "docker": True}
    assert evidence.next_step("presenter", ready, {})["tile"] == "live"
    assert evidence.next_step("presenter", {**ready, "running": False}, {})["tile"] == "setup"
    assert evidence.next_step("presenter", {**ready, "images": False}, {})["text"].startswith("Build the images")
    assert "Docker is not reachable" in evidence.next_step("presenter", {"docker": False}, {})["text"]
    assert "preflight" in evidence.next_step("reproducer", ready, {})["text"]
    assert evidence.next_step("explainer", {}, {})["tile"] == "learn"


def test_export_lists_run_ids_paths_and_the_not_found_sentence(tmp_path, monkeypatch):
    off, live = _setup(tmp_path, monkeypatch, offline={"trials": 3})
    rows = evidence.checklist(off, live, [], {})
    md = evidence.checklist_markdown(rows, "now", root=tmp_path)
    assert off[0].id in md and "results/runs/" in md and "preflight.json" in md
    assert "Not found" in md and "Partial" in md and "not that the feature is missing" in md
    assert md.count("\n|") >= 12


def test_fingerprint_changes_when_a_run_appears(tmp_path):
    results, suites, lab = tmp_path / "results", tmp_path / "suites", tmp_path / "lab"
    before = evidence.fingerprint(results, suites, lab)
    make_offline_run(results)
    assert evidence.fingerprint(results, suites, lab) != before
