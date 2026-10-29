"""Fixture folders for the home page tests: a finished offline run and a finished live-lab benchmark on disk."""

import json
import sys
from pathlib import Path

import pandas as pd
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "dashboard"), str(ROOT / "src")]

DATASETS = [("small", 20), ("medium", 60), ("large", 200)]
RRSETS = {"small": 45, "medium": 125, "large": 405}


def make_offline_run(results_dir: Path, run_id: str = "20261001T120000Z-fixture", trials: int = 6, preflight: bool = True,
                     limited_direct: bool = False, report: bool = True, modes=("slh-dsa-mtl", "slh-dsa", "ed25519")) -> Path:
    p = Path(results_dir) / "runs" / run_id
    p.mkdir(parents=True)
    (p / "config.yaml").write_text(yaml.safe_dump({
        "run_name": "fixture", "seed": 1, "trials": trials, "modes": list(modes),
        "datasets": [{"name": n, "n_names": k} for n, k in DATASETS]}))
    (p / "environment.json").write_text(json.dumps({
        "host_image_id": "sha256:" + "ab" * 32, "stack": "latest", "git_sha": "abc",
        "hardware": {"cpu_model": "Test CPU", "cpu_affinity": [2]},
        "software": {"mtl_reference_commit": "7cef0191da0123", "liboqs_tag": "0.16.0", "openssl_tag": "openssl-3.6.0"}}))
    if preflight:
        (p / "preflight.json").write_text(json.dumps({"verdict": "GO", "checks": [{"name": "x", "ok": True}] * 3}))
    (p / "summary.json").write_text("{}")
    pd.DataFrame([{"dataset": n, "n_names": k, "rrsets": RRSETS[n]} for n, k in DATASETS]).to_csv(p / "datasets.csv", index=False)
    rows = []
    for ds, _ in DATASETS:
        for t in range(trials):
            for mode, sign, verify, sig_b in (("slh-dsa-mtl", 1.0, 0.1, 156), ("slh-dsa", 10.0, 1.0, 7856), ("ed25519", 0.01, 0.02, 64)):
                if mode not in modes:
                    continue
                limited = mode == "slh-dsa" and limited_direct
                row = {"dataset": ds, "mode": mode, "trial": t, "n_signed": 10 if limited else RRSETS[ds],
                       "dataset_rrsets": RRSETS[ds], "limited": limited, "exit_code": 0, "failures_total": 0,
                       "tamper_all_rejected": True, "keygen_ns": 1e6, "sign_total_ns": sign * 1e9 * (1 + 0.01 * t),
                       "verify_warm_total_ns": verify * 1e9, "sign_per_rrset_ns": 1e6, "verify_per_rrset_ns": 1e6,
                       "verify_full_median_ns": 1e5, "signature_bytes_median": sig_b, "signature_bytes_max": sig_b,
                       "signature_material_bytes": 1000}
                if limited:
                    row["sign_total_extrapolated_ns"] = row["sign_total_ns"] * 10
                    row["verify_warm_total_extrapolated_ns"] = verify * 1e10
                rows.append(row)
    trials_df = pd.DataFrame(rows)
    trials_df.to_csv(p / "trials.csv", index=False)
    trials_df.to_parquet(p / "trials.parquet")
    resp = pd.DataFrame([{"dataset": ds, "mode": m, "variant": "default", "udp_limit": 1232, "record_class": "small",
                          "response_bytes": 300 if m != "slh-dsa" else 8000, "fits_udp": m != "slh-dsa",
                          "rrsig_signature_bytes": 100} for ds, _ in DATASETS for m in modes])
    resp.to_csv(p / "responses.csv", index=False)
    resp.to_parquet(p / "responses.parquet")
    pd.DataFrame([{"dataset": "small", "mode": "slh-dsa-mtl", "scope": "resolver", "kind": k} for k in
                  ("measured", "measured", "analytical")]).to_csv(p / "cache.csv", index=False)
    if report:
        (p / "report.html").write_text("<html>report</html>")
    return p


def make_live_suite(suites_dir: Path, results_dir: Path, name: str = "suite-fixture", stack: str = "draft06",
                    sizes=(50, 500, 5000), trials: int = 5, scenarios=("slh-dsa", "mtl"), report: bool = False) -> Path:
    """A finished live-lab suite with one saved resolver run per size."""
    suites_dir, results_dir = Path(suites_dir), Path(results_dir)
    d = suites_dir / name
    d.mkdir(parents=True)
    (d / "params.json").write_text(json.dumps({"stamp": "20261002-101500"}))
    detail = {}
    for n in sizes:
        run = results_dir / "tag" / f"run{n}"
        run.mkdir(parents=True, exist_ok=True)
        summary = []
        for sc in scenarios:
            for pas, ms in (("cold", 9.0), ("warm", 1.0)):
                summary.append({"scenario": sc, "profile": "lan", "udp_limit": 1232, "pass": pas, "median_ms": ms,
                                "upstream_bytes": 3e5 if sc == "mtl" else 4e6, "upstream_queries": 10,
                                "upstream_truncated": 1 if sc == "mtl" else 30, "upstream_tcp_connections": 1,
                                "mem.cache.rrset": 1e5, "trials": trials, "valid_trials": trials, "failed": 0})
        pd.DataFrame(summary).to_csv(run / "summary.csv", index=False)
        detail[str(n)] = {"tag": "tag", "run_folder": f"run{n}"}
        rows = [{"scenario": sc, "trial": t, "names": 20, "rrsigs": 50, "sign_s": 1.0, "verify_s": 0.2, "algorithm": sc,
                 "signed_bytes": 1} for sc in scenarios for t in (1, 2)]
        pd.DataFrame(rows).to_csv(d / f"signing_trials_{n}.csv", index=False)
    pd.DataFrame([{"size": n, "scenario": sc, "rrsig_count": 64, "sign_seconds": 1.0, "verify_seconds": 0.2,
                   "signed_bytes": 9e5, "algorithm": sc, "origin": "z."} for n in sizes for sc in scenarios]).to_csv(
        d / "signing_full.csv", index=False)
    (d / "suite.json").write_text(json.dumps({
        "trials": trials, "sizes": list(sizes), "scenarios": list(scenarios), "stack": stack, "sizes_detail": detail,
        "sign_trials": 3, "sample_names": 100, "n_queries": 500, "networks": ["lan"], "udp": 1232, "jobs": 1,
        "workload": {}, "profiles": {}, "host": {},
        "provenance": {"stack": stack, "stack_pins": {"MTL_COMMIT": "93b05ef73dab"}, "images": {
            "cipherops-eco-nsd": {"id": "sha256:1"}, "cipherops-eco-unbound": {"id": "sha256:2"}}}}))
    if report:
        (d / "report.html").write_text("<html>suite report</html>")
    return d
