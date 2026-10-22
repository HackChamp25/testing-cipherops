#!/bin/bash
# Runs inside the signer container (Verisign mtl-mode-ldns image).
# Generates three zones with identical content, signs each with a different
# algorithm, and writes trust anchors for Unbound.
#
#   ecdsa.lab  ECDSAP256SHA256 (alg 13)           classical baseline
#   slh.lab    SLH-DSA-SHA2-128s (alg 246)        PQC, without MTL
#   mtl.lab    SLH-DSA-SHA2-128s-MTL-SHA2-128     PQC, with MTL (alg 130)
set -euo pipefail

RECORDS="${RECORDS:-100}"           # dataset size: try 100, 1000, 10000
OUT=/var/dns/zones                  # mounted from ./zones on the host
WORK=/var/dns/work
mkdir -p "$OUT" "$WORK"
rm -f "$OUT"/*.signed "$OUT"/trust-anchors.txt "$OUT"/signing-times.csv
rm -rf "$WORK"/*

declare -A ALG=(
  [ecdsa.lab]="ECDSAP256SHA256"
  [slh.lab]="SLH_DSA_PURE_SHA2_128S"
  [mtl.lab]="SLH-DSA-SHA2-128s-MTL-SHA2-128"
)

echo "zone,algorithm,records,sign_ms" > "$OUT/signing-times.csv"

for zone in ecdsa.lab slh.lab mtl.lab; do
  alg="${ALG[$zone]}"
  echo "== $zone  ($alg, $RECORDS records)"
  cd "$WORK"
  python3 /scripts/gen-zone.py "$zone" "$RECORDS" "$WORK/$zone.zone"

  # One combined signing key (KSK flag) per zone keeps the lab simple.
  key=$(ldns-keygen -a "$alg" -k "$zone")

  start=$(date +%s%N)
  ldns-signzone -o "$zone" -f "$OUT/$zone.zone.signed" "$WORK/$zone.zone" "$key"
  end=$(date +%s%N)
  echo "$zone,$alg,$RECORDS,$(( (end - start) / 1000000 ))" >> "$OUT/signing-times.csv"

  # DS record becomes Unbound's trust anchor for this zone.
  ldns-key2ds -n "$key.key" >> "$OUT/trust-anchors.txt"
done

chmod 644 "$OUT"/*
echo
echo "Signed zones and trust anchors written to ./zones"
cat "$OUT/signing-times.csv"
