#!/usr/bin/env python3
"""Show what the demo-safety and protocol-check fixes change, by running old and new code side by side.

    python3 scripts/show_fixes.py                  # compare the working tree with origin/main
    python3 scripts/show_fixes.py --ref <git-ref>  # compare with another commit
    python3 scripts/show_fixes.py --skip-harness   # no Docker: only the dashboard checks

Everything runs from temporary copies, so it never touches the real lab, results or Docker containers.
The harness part needs the pinned image (bash scripts/run_benchmark.sh preflight).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
IMAGE = f"cipherops-bench:{os.environ.get('CIPHEROPS_STACK', 'latest')}"

DIG_ATTACKS = ["dig -f /etc/passwd", "dig -4f /etc/passwd", "dig -vf /etc/passwd", "dig -4k /etc/key",
               "dig -r -f /etc/hosts", "dig host000000.zone00.test A +dnssec"]

# Runs under either code tree (PYTHONPATH selects which) and prints one JSON object.
DASHBOARD_PROBE = r"""
import json, os, sys, time
from pathlib import Path
from live_lab import driver, suite

out = {"dig": {}}
for line in json.loads(sys.argv[1]):
    try:
        driver.dig_argv(line)
        out["dig"][line] = "accepted"
    except ValueError:
        out["dig"][line] = "rejected"

eco = Path(sys.argv[2])
driver.ECO = eco
driver.SUITES_DIR = eco / "results" / "suites"
suite.SUITES = driver.SUITES_DIR
(eco / "configs").mkdir(parents=True)
(eco / "configs" / "x.yaml").write_text("name: demo\n")
h = driver.LabHandle(config="configs/x.yaml", stack="draft06")
h.work.mkdir(parents=True)
h.compose.write_text("services: {}\n")
calls = []
driver._run = lambda cmd, **kw: calls.append(" ".join(cmd[:4])) or type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()

d = driver.SUITES_DIR / "s1"
d.mkdir(parents=True)
(d / "params.json").write_text("{}")
# A suite that has just been launched: no process id yet, state 'starting'.
(d / "status.json").write_text(json.dumps({"state": "starting", "started": time.time()}))
live = suite.running_suite()
out["starting_suite_seen_as_active"] = bool(live)

# A running suite; then someone presses Stop / Flush in another browser tab.
(d / "status.json").write_text(json.dumps({"state": "running", "pid": os.getpid(), "started": time.time()}))
for name, op in (("Stop", lambda: driver.down(h)), ("Flush cache", lambda: driver.flush(h))):
    calls.clear()
    try:
        op()
        out[name] = "went ahead: " + (calls[0] if calls else "no docker call")
    except Exception as e:
        out[name] = "refused (" + type(e).__name__ + ")"
print(json.dumps(out))
"""

# Runs inside the pinned image: builds both harnesses and runs the same messages through each.
HARNESS_PROBE = r"""
import json, subprocess, sys, tempfile
from pathlib import Path
from cipherops import harness
from cipherops.codepoints import MODES
from cipherops.workload import build_zone, signing_messages, write_messages

for tag in ("old", "new"):
    subprocess.run(["make", "-C", f"/tmp/cmp/{tag}"], check=True, capture_output=True)
zone = build_zone("show", 20, 99)
out = {}
for key, mode in MODES.items():
    msgs, _ = signing_messages(zone, mode)
    td = Path(tempfile.mkdtemp())
    write_messages(td / "m.bin", msgs)
    out[key] = {}
    for tag in ("old", "new"):
        harness.HARNESS = f"/tmp/cmp/{tag}/mtlbench"
        r = harness.run_trial(mode, td / "m.bin", None, 8)
        out[key][tag] = {"exit": r["exit_code"], "failures": r["failures"], "tamper": sorted(r["tamper"])}
print("@@" + json.dumps(out))
"""


def git_show(ref: str, path: str) -> bytes:
    return subprocess.run(["git", "show", f"{ref}:{path}"], cwd=REPO, check=True, capture_output=True).stdout


def extract_old_tree(ref: str, dest: Path) -> None:
    tar = subprocess.run(["git", "archive", ref, "dashboard/live_lab", "ecosystem/src"], cwd=REPO,
                         check=True, capture_output=True).stdout
    dest.mkdir(parents=True)
    subprocess.run(["tar", "-x", "-C", str(dest)], input=tar, check=True)


def copy_new_tree(dest: Path) -> None:
    for sub in ("dashboard/live_lab", "ecosystem/src"):
        shutil.copytree(REPO / sub, dest / sub, ignore=shutil.ignore_patterns("__pycache__", "assets"))


def probe_dashboard(tree: Path) -> dict:
    env = {"PYTHONPATH": f"{tree / 'dashboard'}:{tree / 'ecosystem' / 'src'}", "PATH": "/usr/bin:/bin"}
    eco = Path(tempfile.mkdtemp(prefix="eco-"))
    shutil.rmtree(eco)
    cp = subprocess.run([sys.executable, "-c", DASHBOARD_PROBE, json.dumps(DIG_ATTACKS), str(eco)],
                        capture_output=True, text=True, env=env)
    if cp.returncode != 0:
        raise SystemExit(f"probe failed:\n{cp.stderr[-1500:]}")
    shutil.rmtree(eco, ignore_errors=True)
    return json.loads(cp.stdout.strip().splitlines()[-1])


def probe_harness(ref: str, tmp: Path) -> dict | None:
    if subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True).returncode != 0:
        print(f"  (image {IMAGE} not found: build it with: bash scripts/run_benchmark.sh preflight)")
        return None
    for tag, data in (("old", git_show(ref, "harness/mtlbench.c")), ("new", (REPO / "harness/mtlbench.c").read_bytes())):
        (tmp / "cmp" / tag).mkdir(parents=True)
        (tmp / "cmp" / tag / "mtlbench.c").write_bytes(data)
        shutil.copy(REPO / "harness/Makefile", tmp / "cmp" / tag / "Makefile")
    cp = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "--entrypoint", "python3",
         "-v", f"{tmp / 'cmp'}:/cmp-src:ro,z", "-v", f"{REPO / 'src'}:/work/src:ro,z", "-e", "PYTHONPATH=/work/src",
         IMAGE, "-c", "import shutil; shutil.copytree('/cmp-src', '/tmp/cmp')\n" + HARNESS_PROBE],
        capture_output=True, text=True)
    lines = [ln for ln in cp.stdout.splitlines() if ln.startswith("@@")]
    if not lines:
        print(cp.stdout[-800:], cp.stderr[-1500:])
        return None
    return json.loads(lines[-1][2:])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ref", default="origin/main", help="the 'before' commit (default origin/main)")
    ap.add_argument("--skip-harness", action="store_true", help="skip the Docker part")
    args = ap.parse_args()
    sha = subprocess.run(["git", "rev-parse", "--short", args.ref], cwd=REPO, capture_output=True, text=True)
    if sha.returncode != 0:
        raise SystemExit(f"unknown git ref {args.ref}")
    tmp = Path(tempfile.mkdtemp(prefix="show-fixes-"))
    try:
        old_tree, new_tree = tmp / "old", tmp / "new"
        extract_old_tree(args.ref, old_tree)
        copy_new_tree(new_tree)
        old, new = probe_dashboard(old_tree), probe_dashboard(new_tree)

        print(f"\nBefore = {args.ref} ({sha.stdout.strip()})    After = working tree\n")
        print("1. A benchmark suite that has just been launched")
        print(f"   seen as active: before={old['starting_suite_seen_as_active']}  after={new['starting_suite_seen_as_active']}\n")
        print("2. Pressing a lab button while a benchmark suite is running")
        for name in ("Stop", "Flush cache"):
            print(f"   {name:<12} before: {old[name]}\n   {'':<12} after:  {new[name]}")
        print("\n3. dig input that tries to read files in the client container")
        for line in DIG_ATTACKS:
            print(f"   {line:<42} before: {old['dig'][line]:<9} after: {new['dig'][line]}")

        print("\n4. Negative checks the harness runs on every mode (all must be rejected)")
        if args.skip_harness:
            print("   skipped (--skip-harness)")
        else:
            res = probe_harness(args.ref, tmp)
            if res:
                for key, r in res.items():
                    added = sorted(set(r["new"]["tamper"]) - set(r["old"]["tamper"]))
                    print(f"   {key:<12} before {len(r['old']['tamper'])} checks, after {len(r['new']['tamper'])}"
                          f"  (exit {r['old']['exit']} -> {r['new']['exit']})")
                    if added:
                        print(f"   {'':<12} new: {', '.join(added)}")
        print("\nThe tests that guard these: tests/test_lab_guard.py (host) and tests/test_harness.py (Docker).")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
