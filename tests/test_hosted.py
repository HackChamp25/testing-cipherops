"""Hosted demo mode (CIPHEROPS_HOSTED=1): only some tiles, Small benchmarks only, and nothing changes when unset."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "dashboard" / "live_lab" / "app.py"
sys.path.insert(0, str(ROOT / "dashboard"))

from live_lab import driver, offline_job, suite  # noqa: E402

NOTICE = ("Hosted demo: Live, Compare, Learn and small benchmarks. "
          "Setup, larger benchmarks and Reset need a local install, see README.")
ALLOWED = ["live", "compare", "benchmark", "learn"]


def _app(tile=None, state=None):
    testing = pytest.importorskip("streamlit.testing.v1")
    at = testing.AppTest.from_file(str(APP), default_timeout=180)
    if tile:
        at.query_params["tile"] = tile
    for k, v in (state or {}).items():
        at.session_state[k] = v
    return at


@pytest.fixture
def hosted(monkeypatch):
    monkeypatch.setenv("CIPHEROPS_HOSTED", "1")


# ───────────── tile fallback ─────────────

@pytest.mark.parametrize("tile", ["setup", "reset", "no-such-tile"])
def test_hosted_refuses_other_tiles_and_falls_back_to_home(hosted, tile):
    at = _app(tile).run()
    assert not at.exception
    assert at.session_state["nav"] == "home"


@pytest.mark.parametrize("tile", ALLOWED)
def test_hosted_allows_its_tiles(hosted, tile):
    at = _app(tile).run()
    assert not at.exception
    assert at.session_state["nav"] == tile


@pytest.mark.parametrize("stale", ["setup", "reset"])
def test_hosted_refuses_a_hidden_tile_already_in_the_session(hosted, stale):
    # not only at page load: a session that somehow holds a hidden tile is sent home on the next run
    at = _app(state={"nav": stale}).run()
    assert not at.exception
    assert at.session_state["nav"] == "home"


def test_hosted_home_shows_only_the_allowed_tiles_and_the_notice(hosted):
    at = _app().run()
    assert not at.exception
    opened = {b.key for b in at.button if b.key and b.key.startswith("open_")}
    assert opened == {f"open_{m}" for m in ALLOWED}
    assert NOTICE in [i.value for i in at.info]


def test_unset_changes_nothing(monkeypatch):
    monkeypatch.delenv("CIPHEROPS_HOSTED", raising=False)
    at = _app("setup").run()
    assert not at.exception
    assert at.session_state["nav"] == "setup"
    assert NOTICE not in [i.value for i in at.info]
    home = _app().run()
    opened = {b.key for b in home.button if b.key and b.key.startswith("open_")}
    assert opened == {f"open_{m}" for m in ("setup", "live", "benchmark", "compare", "learn", "reset")}


# ───────────── Small-only benchmarks ─────────────

def test_hosted_benchmark_selector_is_disabled_and_small(hosted):
    at = _app("benchmark", {"cfg": {"bench_sizes": [5000]}}).run()
    assert not at.exception
    sel = at.sidebar.multiselect(key="hosted_bench_sizes")
    assert sel.disabled and sel.value == list(suite.HOSTED_SIZES)
    assert at.session_state["cfg"]["bench_sizes"] == list(suite.HOSTED_SIZES)


def test_hosted_launcher_refuses_other_sizes(hosted):
    for sizes in ([50], [5000], [20, 500], [], None):
        with pytest.raises(ValueError):
            suite.enforce_hosted_sizes(sizes)
        with pytest.raises(ValueError):
            suite.start({"sizes": sizes, "scenarios": ["mtl"]})  # refused before anything is created or started
    suite.enforce_hosted_sizes([suite.SMOKE_SIZE])  # Small is accepted


def test_launcher_accepts_any_size_when_unset(monkeypatch):
    monkeypatch.delenv("CIPHEROPS_HOSTED", raising=False)
    suite.enforce_hosted_sizes([5000])
    assert not driver.hosted()


def test_hosted_offline_run_is_refused(hosted):
    with pytest.raises(driver.LabBusy):
        offline_job.start("quick")
