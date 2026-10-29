#!/usr/bin/env bash
# Live mode on a finished run: real client, real NSD, tc-netem network profiles, pcaps (Linux/macOS host).
#   scripts/run_live.sh <run-folder>                          all profiles, both UDP sizes, 3 repeats
#   scripts/run_live.sh <run-folder> lan 1232 1               quick look
# Arguments: run folder name under results/runs/, profiles (default lan,wan,lossy),
#            UDP sizes (default 1232,4096), repeats (default 3), cpuset (default 2).
set -euo pipefail
cd "$(dirname "$0")/.."

run="${1:?usage: scripts/run_live.sh <run-folder> [profiles] [udp] [repeats] [cpuset]}"
profiles="${2:-lan,wan,lossy}"
udp="${3:-1232,4096}"
repeats="${4:-3}"
export CIPHEROPS_CPUSET="${5:-2}"
stack="${CIPHEROPS_STACK:-latest}"   # must match the stack the run was made with
env_file="ecosystem/stacks/${stack}.env"
[ -f "${env_file}" ] || { echo "unknown stack '${stack}': no ${env_file}" >&2; exit 1; }

[ -d "results/runs/${run}" ] || { echo "no such run: results/runs/${run}" >&2; exit 1; }
docker compose --env-file "${env_file}" -f docker/compose.yml run --rm live \
  "python3 -m cipherops.runner live --run results/runs/${run} --profiles ${profiles} --udp ${udp} --repeats ${repeats}"
