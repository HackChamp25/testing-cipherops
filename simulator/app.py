#!/usr/bin/env python3
"""
Visual simulator for the PQC DNSSEC lab.

A small local-only Flask dashboard that drives the existing docker compose
workflow (sign zones, start servers, query, verify, cache test) and shows
the results as simple charts. It does not replace build-images.sh or the
README workflow -- it just gives you buttons and graphs instead of typing
the same dig/docker commands by hand.

Run:
    pip install -r simulator/requirements.txt
    python3 simulator/app.py
Then open http://127.0.0.1:5500
"""
from __future__ import annotations

import csv
import io
import re
import subprocess
import threading
import time
import uuid
from pathlib import Path

from flask import Flask, jsonify, render_template, request

BASE_DIR = Path(__file__).resolve().parent.parent
ZONES_DIR = BASE_DIR / "zones"

ZONE_ALGO = {
    "ecdsa.lab": "ECDSAP256SHA256",
    "slh.lab": "SLH_DSA_PURE_SHA2_128S",
    "mtl.lab": "SLH-DSA-SHA2-128s-MTL-SHA2-128",
}
VALID_ZONES = set(ZONE_ALGO)

app = Flask(__name__)

# In-memory job tracker for long-running operations (signing can take
# minutes to hours depending on RECORDS). Each job is a dict with keys:
# status ("running"|"done"|"error"), output (str tail), result (dict|None).
_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()


def _run(cmd: list[str], timeout: int | None = None) -> subprocess.CompletedProcess:
    """Run a fixed-argument command (never shell=True) rooted at BASE_DIR."""
    return subprocess.run(
        cmd,
        cwd=BASE_DIR,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _start_job() -> str:
    job_id = uuid.uuid4().hex
    with _jobs_lock:
        _jobs[job_id] = {"status": "running", "output": "", "result": None}
    return job_id


def _finish_job(job_id: str, result: dict | None, error: str | None = None) -> None:
    with _jobs_lock:
        _jobs[job_id]["status"] = "error" if error else "done"
        _jobs[job_id]["output"] = error or _jobs[job_id]["output"]
        _jobs[job_id]["result"] = result


@app.get("/")
def index():
    return render_template("index.html", zones=list(ZONE_ALGO.items()))


@app.get("/api/status")
def status():
    """Which containers are up, and whether signed zones already exist."""
    out = {"nsd": False, "unbound": False, "client": False}
    try:
        cp = _run(["docker", "compose", "ps", "--format", "{{.Service}} {{.State}}"], timeout=15)
        for line in cp.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] in out:
                out[parts[0]] = parts[1].lower().startswith("running")
    except Exception as exc:  # noqa: BLE001 - surfaced to the UI as-is
        return jsonify({"error": str(exc)}), 500

    signed = {z: (ZONES_DIR / f"{z}.zone.signed").exists() for z in VALID_ZONES}
    return jsonify({"containers": out, "signed": signed})


def _do_sign(job_id: str, records: int) -> None:
    try:
        cp = _run(
            ["docker", "compose", "run", "--rm", "-e", f"RECORDS={records}", "signer"],
            timeout=None,  # plain SLH-DSA at high record counts can take hours
        )
        with _jobs_lock:
            _jobs[job_id]["output"] = (cp.stdout or "") + (cp.stderr or "")
        if cp.returncode != 0:
            _finish_job(job_id, None, error=f"signer exited {cp.returncode}")
            return

        csv_path = ZONES_DIR / "signing-times.csv"
        rows = []
        if csv_path.exists():
            with csv_path.open() as fh:
                rows = list(csv.DictReader(fh))
        _finish_job(job_id, {"rows": rows})
    except Exception as exc:  # noqa: BLE001
        _finish_job(job_id, None, error=str(exc))


@app.post("/api/sign")
def sign():
    data = request.get_json(force=True, silent=True) or {}
    try:
        records = int(data.get("records", 100))
    except (TypeError, ValueError):
        return jsonify({"error": "records must be an integer"}), 400
    if not (1 <= records <= 100000):
        return jsonify({"error": "records must be between 1 and 100000"}), 400

    job_id = _start_job()
    threading.Thread(target=_do_sign, args=(job_id, records), daemon=True).start()
    return jsonify({"job_id": job_id})


@app.get("/api/jobs/<job_id>")
def job_status(job_id):
    with _jobs_lock:
        job = _jobs.get(job_id)
    if job is None:
        return jsonify({"error": "unknown job"}), 404
    return jsonify(job)


@app.post("/api/servers/<action>")
def servers(action):
    if action not in ("start", "stop"):
        return jsonify({"error": "action must be start or stop"}), 400
    try:
        if action == "start":
            cp = _run(["docker", "compose", "up", "-d", "nsd", "unbound", "client"], timeout=60)
        else:
            cp = _run(["docker", "compose", "stop", "nsd", "unbound", "client"], timeout=60)
        return jsonify({"ok": cp.returncode == 0, "output": cp.stdout + cp.stderr})
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": str(exc)}), 500


_DIG_SIZE_RE = re.compile(r"MSG SIZE\s+rcvd:\s+(\d+)")
_DIG_STATUS_RE = re.compile(r"status:\s*(\w+)")
_DIG_FLAGS_RE = re.compile(r"flags:\s*([a-z ]+);")


def _parse_dig(output: str) -> dict:
    size = _DIG_SIZE_RE.search(output)
    status_m = _DIG_STATUS_RE.search(output)
    flags_m = _DIG_FLAGS_RE.search(output)
    return {
        "size": int(size.group(1)) if size else None,
        "status": status_m.group(1) if status_m else None,
        "flags": flags_m.group(1).strip() if flags_m else "",
        "truncated": "Truncated, retrying in TCP mode" in output,
        "ad": bool(flags_m and "ad" in flags_m.group(1).split()),
        "raw": output,
    }


@app.post("/api/query")
def query():
    data = request.get_json(force=True, silent=True) or {}
    zone = data.get("zone")
    if zone not in VALID_ZONES:
        return jsonify({"error": "unknown zone"}), 400
    validated = bool(data.get("validated"))
    full_sig = bool(data.get("full_sig"))
    port = "5302" if validated else "5301"

    cmd = ["dig", "@127.0.0.1", "-p", port, f"www.{zone}", "A", "+dnssec"]
    if full_sig:
        cmd.append("+ednsopt=65050")
    try:
        cp = _run(cmd, timeout=15)
        return jsonify(_parse_dig(cp.stdout))
    except subprocess.TimeoutExpired:
        return jsonify({"error": "dig timed out"}), 504
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": str(exc)}), 500


@app.post("/api/verify")
def verify():
    """Time ldns-verify-zone per zone -- pure crypto verification cost."""
    results = []
    for zone in ZONE_ALGO:
        signed = ZONES_DIR / f"{zone}.zone.signed"
        if not signed.exists():
            results.append({"zone": zone, "error": "not signed yet"})
            continue
        script = f"ldns-verify-zone /zones/{zone}.zone.signed"
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{ZONES_DIR}:/zones:ro,z",
            "pqc_ldns:latest",
            "bash", "-lc",
            f"start=$(date +%s%N); {script} >/tmp/out 2>&1; rc=$?; "
            f"end=$(date +%s%N); echo VERIFY_MS=$(( (end-start)/1000000 )); "
            f"echo RC=$rc; tail -3 /tmp/out",
        ]
        try:
            cp = _run(cmd, timeout=120)
            ms_m = re.search(r"VERIFY_MS=(\d+)", cp.stdout)
            rc_m = re.search(r"RC=(\d+)", cp.stdout)
            results.append({
                "zone": zone,
                "algorithm": ZONE_ALGO[zone],
                "verify_ms": int(ms_m.group(1)) if ms_m else None,
                "ok": rc_m is not None and rc_m.group(1) == "0",
                "raw": cp.stdout,
            })
        except Exception as exc:  # noqa: BLE001
            results.append({"zone": zone, "error": str(exc)})
    return jsonify({"results": results})


_STAT_RE = re.compile(r"total\.num\.(cachehits|cachemiss)=(\d+)")
_RECURSION_RE = re.compile(r"total\.recursion\.time\.avg=([\d.]+)")


def _unbound_control(*args: str, timeout: int = 15) -> str:
    cp = _run(
        ["docker", "compose", "exec", "-T", "unbound", "unbound-control",
         "-c", "/etc/lab/unbound.conf", *args],
        timeout=timeout,
    )
    return cp.stdout + cp.stderr


def _parse_stats(text: str) -> dict:
    hits = miss = 0
    recursion = None
    for m in _STAT_RE.finditer(text):
        if m.group(1) == "cachehits":
            hits = int(m.group(2))
        else:
            miss = int(m.group(2))
    rm = _RECURSION_RE.search(text)
    if rm:
        recursion = float(rm.group(1))
    return {"cachehits": hits, "cachemiss": miss, "recursion_time_avg": recursion}


@app.post("/api/cache-test")
def cache_test():
    data = request.get_json(force=True, silent=True) or {}
    zone = data.get("zone")
    if zone not in VALID_ZONES:
        return jsonify({"error": "unknown zone"}), 400

    try:
        _unbound_control("flush_zone", zone)
        _unbound_control("stats")  # reset counters

        cold_cp = _run(
            ["dig", "@127.0.0.1", "-p", "5302", f"www.{zone}", "A", "+dnssec"], timeout=15
        )
        cold_stats = _parse_stats(_unbound_control("stats_noreset"))

        for _ in range(3):
            _run(["dig", "@127.0.0.1", "-p", "5302", f"www.{zone}", "A", "+dnssec"], timeout=15)
        warm_stats = _parse_stats(_unbound_control("stats_noreset"))

        return jsonify({
            "cold": {**cold_stats, **_parse_dig(cold_cp.stdout)},
            "warm": warm_stats,
        })
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": str(exc)}), 500


if __name__ == "__main__":
    # Local-only: this executes fixed docker/dig commands, never user-supplied
    # shell strings, but it's still a control surface for your Docker daemon,
    # so don't bind it to anything but loopback.
    app.run(host="127.0.0.1", port=5500, debug=False)
