#!/bin/bash
# Builds Verisign's MTL-mode images from pinned commits.
# First build takes 20-40 minutes (OpenSSL + liboqs compile from source).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p vendor && cd vendor

# Pinned commits (tested together). Change only deliberately, and record it.
declare -A PIN=(
  [MTL]=7cef0191da55048111d252a567b7614672424ed3
  [mtl-mode-ldns]=1eea7b5aa8d963b6e5ac86978050bd8e32a23821
  [mtl-mode-nsd]=31153312a6551781a3668c8819c5dc0ba2ef6bd5
  [mtl-mode-unbound]=04eacb760af4fe0ead5dc72fa3a1f4542befceed
)

for repo in MTL mtl-mode-ldns mtl-mode-nsd mtl-mode-unbound; do
  [ -d "$repo" ] || git clone "https://github.com/verisign/$repo"
  git -C "$repo" fetch -q origin
  git -C "$repo" checkout -q --force "${PIN[$repo]}"
  git -C "$repo" reset -q --hard
  for p in ../patches/"$repo"-*.patch; do
    [ -e "$p" ] || continue
    git -C "$repo" apply "../$p" && echo "  applied $(basename "$p")"
  done
  echo "$repo @ ${PIN[$repo]}"
done

# Base layers: OpenSSL + liboqs, then the MTL library on top.
(cd MTL && docker compose build pqc-base && docker compose build mtl-mode)

# Applications that link against the MTL library.
docker build -t pqc_ldns:latest    -f mtl-mode-ldns/docker/Dockerfile    mtl-mode-ldns
docker build -t mtl-nsd:latest     -f mtl-mode-nsd/docker/Dockerfile     mtl-mode-nsd
docker build -t mtl-unbound:latest -f mtl-mode-unbound/docker/Dockerfile mtl-mode-unbound

echo
echo "Images ready:"
docker images --format '  {{.Repository}}:{{.Tag}}  {{.Size}}' | grep -E 'pqc_|mtl-'
