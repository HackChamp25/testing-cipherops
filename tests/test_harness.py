"""Correctness gates on the compiled harness + reference library (run in Docker)."""

import os
import shutil

import pytest

from cipherops import analytical, crossverify
from cipherops.codepoints import MODES, MTL_TYPE_CONDENSED, SLH_DSA_SHA2_128S_SIG_BYTES
from cipherops.harness import HARNESS, load_signatures, run_trial
from cipherops.workload import build_zone, read_blob_set, signing_messages, write_messages

pytestmark = [
    pytest.mark.harness,
    pytest.mark.skipif(not os.path.exists(HARNESS), reason="mtlbench not built (run inside Docker)"),
]


@pytest.fixture(scope="module")
def zone():
    return build_zone("gate", 20, 99)


def _run(zone, key, tmp_path, full_verify=8):
    mode = MODES[key]
    msgs, _ = signing_messages(zone, mode)
    path = tmp_path / f"{key}.bin"
    write_messages(path, msgs)
    return msgs, run_trial(mode, path, tmp_path / key, full_verify)


@pytest.mark.parametrize("key", list(MODES))
def test_every_signature_verifies_and_tampering_is_rejected(zone, key, tmp_path):
    msgs, res = _run(zone, key, tmp_path)
    assert res["exit_code"] == 0, res["stderr_tail"]
    assert res["n_messages"] == len(msgs)
    assert sum(res["failures"].values()) == 0
    assert all(res["tamper"].values())


def test_direct_signature_length(zone, tmp_path):
    _, res = _run(zone, "slh-dsa", tmp_path)
    assert set(res["signature_bytes"]) == {SLH_DSA_SHA2_128S_SIG_BYTES}


def test_mtl_sizes_against_draft_formulas(zone, tmp_path):
    msgs, res = _run(zone, "slh-dsa-mtl", tmp_path)
    n = len(msgs)
    assert max(res["condensed_bytes"]) <= analytical.max_condensed_signature(16, n)
    assert res["signed_ladder_bytes"] > SLH_DSA_SHA2_128S_SIG_BYTES
    assert res["signed_ladder_bytes"] <= analytical.max_signed_ladder(16, n, SLH_DSA_SHA2_128S_SIG_BYTES)


@pytest.mark.parametrize("key", list(MODES))
def test_public_key_matches_dnskey_field_length(zone, key, tmp_path):
    _, res = _run(zone, key, tmp_path)
    assert res["public_key_bytes"] == MODES[key].public_key_len


def test_artifacts_round_trip(zone, tmp_path):
    msgs, res = _run(zone, "slh-dsa-mtl", tmp_path)
    sigs = load_signatures(MODES["slh-dsa-mtl"], tmp_path / "slh-dsa-mtl", False)
    assert len(sigs.sigs) == len(msgs)
    assert len(sigs.signed_ladder) == res["signed_ladder_bytes"]
    assert sigs.rrsig_field(0)[0] == MTL_TYPE_CONDENSED
    assert [len(s) for s in read_blob_set(tmp_path / "slh-dsa-mtl" / "condensed.bin")] == res["condensed_bytes"]


NEGATIVE_CHECKS = {
    "slh-dsa-mtl": {"message_rejected", "signature_rejected", "ladder_rejected", "cross_message_rejected",
                    "truncated_signature_rejected", "series_id_rejected", "wrong_key_rejected",
                    "full_signature_rejected"},
    "slh-dsa": {"message_rejected", "signature_rejected", "cross_message_rejected",
                "truncated_signature_rejected", "wrong_key_rejected"},
}
NEGATIVE_CHECKS.update({k: NEGATIVE_CHECKS["slh-dsa"] for k in ("ed25519", "ecdsa-p256", "rsa-2048")})


@pytest.mark.parametrize("key", list(MODES))
def test_every_negative_check_runs_and_is_rejected(zone, key, tmp_path):
    """Signature for message i must not verify another message; truncated, damaged and wrong-key input fails."""
    _, res = _run(zone, key, tmp_path)
    assert set(res["tamper"]) == NEGATIVE_CHECKS[key]
    assert all(res["tamper"].values()), res["tamper"]


def test_ecdsa_wire_format_verifies(zone, tmp_path):
    """ECDSA goes on the wire as r||s; converting it back must verify, not only the DER form that was signed."""
    _, res = _run(zone, "ecdsa-p256", tmp_path)
    assert res["failures"] == {"verify": 0, "verify_wire": 0}
    assert set(res["signature_bytes"]) == {64}


def test_mtl_reports_unauthenticated_header_bytes(zone, tmp_path):
    """The reference library ignores the first two condensed-signature bytes; this is recorded, not hidden."""
    _, res = _run(zone, "slh-dsa-mtl", tmp_path)
    assert res["observations"]["condensed_header_bytes_unauthenticated"] in (0, 1, 2)


@pytest.mark.skipif(shutil.which("mtlverify") is None, reason="mtlverify not installed")
def test_mtl_artifacts_verify_with_the_reference_tool():
    r = crossverify.mtl_with_reference_tool()
    assert r["harness_exit"] == 0 and r["checked"] > 0
    assert r["failed"] == [] and r["tampered_rejected"]


@pytest.mark.skipif(not crossverify.openssl_supports_slh_dsa(), reason="openssl without SLH-DSA")
def test_slh_dsa_signatures_verify_with_openssl():
    r = crossverify.slh_dsa_with_openssl()
    assert r["harness_exit"] == 0 and r["checked"] > 0
    assert r["failed"] == [] and r["tampered_rejected"]


def test_calibration_reports_a_plausible_clock_and_both_timings():
    from cipherops import timer
    from cipherops.harness import run_calibrate

    s = timer.summarise(run_calibrate(MODES["slh-dsa-mtl"].harness_algo))
    er = s["empty_region"]
    assert 0 < er["median_ns"] < 5_000 and er["min_ns"] <= er["median_ns"] <= er["p99_ns"]
    assert set(s["operations"]) == {"ed25519_verify", "mtl_condensed_verify"}
    for op in s["operations"].values():
        assert op["calls"] == 1000 and op["per_call_median_ns"] > 0 and op["batch_per_call_median_ns"] > 0
