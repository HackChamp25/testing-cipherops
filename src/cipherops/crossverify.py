"""Independent verification of the bytes the benchmark counts as transmitted.

mtlbench verifies its own signatures with the same library that made them. These checks take the artifacts it
wrote (messages, signatures, public key) and verify them with a different program:

* MTL: the Verisign reference tool ``mtlverify``, which is separate from the harness code.
* Direct SLH-DSA: OpenSSL's SLH-DSA provider, a separate implementation from liboqs, which signed them.

Neither is a known-answer test against published vectors. They show that two implementations agree on the
exact signature bytes, and that a changed message is rejected by both.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from .codepoints import MODES
from .harness import load_signatures, run_trial
from .workload import build_zone, signing_messages, write_messages

# DER header of a SubjectPublicKeyInfo for id-slh-dsa-sha2-128s (2.16.840.1.101.3.4.3.20), raw key follows.
_SLH_DSA_SHA2_128S_SPKI = bytes.fromhex("3030300b0609608648016503040314032100")
_SLH_DSA_OPENSSL_NAME = "SLH-DSA-SHA2-128s"


def _run(cmd: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _flip(data: bytes) -> bytes:
    out = bytearray(data or b"\x00")
    out[len(out) // 2] ^= 0x01
    return bytes(out)


def mtl_with_reference_tool(n_names: int = 6, seed: int = 7, sample: int = 8) -> dict:
    """Verify mtlbench's condensed signatures + signed ladder with ``mtlverify``; a tampered message must fail."""
    mode = MODES["slh-dsa-mtl"]
    msgs, _ = signing_messages(build_zone("xverify", n_names, seed), mode)
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        write_messages(tdp / "m.bin", msgs)
        res = run_trial(mode, tdp / "m.bin", tdp / "out", full_verify=2)
        sigs = load_signatures(mode, tdp / "out", False)
        pub = tdp / "out" / "public_key.bin"
        (tdp / "ladder.bin").write_bytes(sigs.signed_ladder)
        failed, checked = [], 0
        for i in range(min(sample, len(msgs))):
            (tdp / "msg").write_bytes(msgs[i])
            (tdp / "sig").write_bytes(sigs.sigs[i])
            args = ["mtlverify", mode.harness_algo, str(pub), str(tdp / "msg"), str(tdp / "sig"), str(tdp / "ladder.bin")]
            checked += 1
            if _run(args).returncode != 0:
                failed.append(i)
        (tdp / "msg").write_bytes(_flip(msgs[0]))
        (tdp / "sig").write_bytes(sigs.sigs[0])
        tampered_rejected = _run(["mtlverify", mode.harness_algo, str(pub), str(tdp / "msg"), str(tdp / "sig"),
                                  str(tdp / "ladder.bin")]).returncode != 0
        header = (res.get("observations") or {}).get("condensed_header_bytes_unauthenticated")
    return {"checked": checked, "failed": failed, "tampered_rejected": tampered_rejected,
            "harness_exit": res["exit_code"], "unauthenticated_header_bytes": header}


def openssl_supports_slh_dsa() -> bool:
    exe = shutil.which("openssl")
    if exe is None:
        return False
    out = _run([exe, "list", "-signature-algorithms"])
    return out.returncode == 0 and _SLH_DSA_OPENSSL_NAME.lower() in out.stdout.lower()


def slh_dsa_with_openssl(n_names: int = 6, seed: int = 7, sample: int = 8) -> dict:
    """Verify liboqs SLH-DSA-SHA2-128s signatures (the non-MTL workload) with OpenSSL; a tampered message must fail."""
    mode = MODES["slh-dsa"]
    msgs, _ = signing_messages(build_zone("xverify", n_names, seed), mode)
    exe = shutil.which("openssl")
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        write_messages(tdp / "m.bin", msgs)
        res = run_trial(mode, tdp / "m.bin", tdp / "out", full_verify=0)
        sigs = load_signatures(mode, tdp / "out", False)
        pk = (tdp / "out" / "public_key.bin").read_bytes()
        (tdp / "pub.der").write_bytes(_SLH_DSA_SHA2_128S_SPKI + pk)

        def verify(message: bytes, sig: bytes) -> bool:
            (tdp / "msg").write_bytes(message)
            (tdp / "sig").write_bytes(sig)
            p = _run([exe, "pkeyutl", "-verify", "-pubin", "-keyform", "DER", "-inkey", str(tdp / "pub.der"),
                      "-in", str(tdp / "msg"), "-sigfile", str(tdp / "sig")])
            return p.returncode == 0

        failed = [i for i in range(min(sample, len(msgs))) if not verify(msgs[i], sigs.sigs[i])]
        tampered_rejected = not verify(_flip(msgs[0]), sigs.sigs[0])
    return {"checked": min(sample, len(msgs)), "failed": failed, "tampered_rejected": tampered_rejected,
            "harness_exit": res["exit_code"]}
