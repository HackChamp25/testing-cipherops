"""Headless smoke test of the Streamlit lab dashboard: every tile renders without an exception."""

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "dashboard" / "live_lab" / "app.py"


@pytest.mark.parametrize("tile", [None, "setup", "live", "benchmark", "compare", "learn", "reset"])
def test_tile_renders_without_exceptions(tile):
    testing = pytest.importorskip("streamlit.testing.v1")
    at = testing.AppTest.from_file(str(APP), default_timeout=180)
    if tile:
        at.query_params["tile"] = tile
    at.run()
    assert not at.exception, [e.message for e in at.exception]
