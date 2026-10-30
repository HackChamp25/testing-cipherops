"""Pass validity and summary for the live-lab benchmark: failed lookups must not look like fast answers."""

import sys
from pathlib import Path

import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "ecosystem" / "src"))

run = pytest.importorskip("ecolab.run", reason="needs the docker SDK used by ecolab.control")


def _rows(spec):
    """spec: list of (rcode, latency_ms, timeout)."""
    return [{"rcode": r, "latency_ms": ms, "timeout": t, "ad": r == "NOERROR", "tc": False, "query_bytes": 40,
             "response_bytes": 100, "tcp_query_bytes": 0, "tcp_response_bytes": 0} for r, ms, t in spec]


def test_servfail_and_timeouts_are_not_latency():
    row = run._pass_row(_rows([("NOERROR", 10.0, False), ("NXDOMAIN", 20.0, False), ("SERVFAIL", 0.1, False),
                               ("TIMEOUT", 2000.0, True)]))
    assert row["median_ms"] == 15.0 and row["answered"] == 2 and row["failed"] == 2
    assert row["valid"] is False and row["servfail"] == 1 and row["timeouts"] == 1


def test_a_clean_pass_is_valid():
    row = run._pass_row(_rows([("NOERROR", 4.0, False), ("NXDOMAIN", 6.0, False)]))
    assert row["valid"] is True and row["failed"] == 0 and row["median_ms"] == 5.0


def test_summary_ignores_invalid_passes_but_still_counts_their_failures(tmp_path):
    passes = pd.DataFrame([
        {"scenario": "mtl", "udp_limit": 1232, "profile": "lan", "pass": "cold", "trial": t, "median_ms": ms,
         "total_ms": ms * 10, "upstream_bytes": 1000, "valid": ok, "failed": 0 if ok else 3, "servfail": 0 if ok else 3,
         "timeouts": 0}
        for t, (ms, ok) in enumerate([(5.0, True), (6.0, True), (0.2, False), (7.0, True)])])
    passes.to_csv(tmp_path / "passes.csv", index=False)
    s = run.summarize(tmp_path).iloc[0]
    assert s["trials"] == 4 and s["valid_trials"] == 3
    assert s["median_ms"] == 6.0          # the 0.2 ms SERVFAIL pass is not in it
    assert s["failed"] == 3 and s["servfail"] == 3
