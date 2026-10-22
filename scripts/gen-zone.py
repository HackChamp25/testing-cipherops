#!/usr/bin/env python3
"""Generate a deterministic test zone with N host records.

usage: gen-zone.py <origin> <num_records> <outfile>
The same seed always produces the same zone, so MTL and non-MTL runs
sign byte-identical data.
"""
import random
import sys

origin, n, out = sys.argv[1].rstrip(".") + ".", int(sys.argv[2]), sys.argv[3]
rnd = random.Random(36)  # fixed seed -> reproducible datasets

lines = [
    f"$ORIGIN {origin}",
    "$TTL 3600",
    f"@   IN SOA ns1.{origin} hostmaster.{origin} 1 3600 900 604800 300",
    f"@   IN NS  ns1.{origin}",
    "ns1 IN A   172.30.0.53",
    "www IN A   10.0.0.10",
    'txt IN TXT "pqc dnssec lab"',
]
for i in range(n):
    ip = f"10.{rnd.randint(1, 254)}.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}"
    lines.append(f"host{i:05d} IN A {ip}")

with open(out, "w") as f:
    f.write("\n".join(lines) + "\n")
print(f"wrote {out}: {origin} with {n} host records")
