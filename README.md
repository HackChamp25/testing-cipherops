# PQC DNSSEC Lab: ECDSA vs SLH-DSA vs SLH-DSA-MTL

A local Docker lab built on Verisign's open-source MTL mode stack. Three zones
with identical content are each signed with a different algorithm, served by
an MTL-aware NSD, and validated by an MTL-aware Unbound. You can `dig` them
from your shell or from a client container and capture everything in Wireshark.

| Zone | Algorithm | DNSSEC alg # | Role |
|---|---|---|---|
| `ecdsa.lab` | ECDSAP256SHA256 | 13 | Classical baseline |
| `slh.lab` | SLH-DSA-SHA2-128s | 246 | PQC **without** MTL |
| `mtl.lab` | SLH-DSA-SHA2-128s-MTL-SHA2-128 | 130 | PQC **with** MTL |

```
 your shell ──5301──► nsd      172.30.0.53   authoritative (ecdsa/slh/mtl.lab)
            ──5302──► unbound  172.30.0.54   validating resolver ──► nsd
                      client   172.30.0.60   dig + tcpdump
            all on Docker bridge "pqclab0" (172.30.0.0/24)
```

Nothing here touches your system DNS. Everything is reached on ports 5301 and
5302 only.

## 1. Build the images (once, 20–40 min)

```bash
./build-images.sh
```

This clones Verisign's `MTL`, `mtl-mode-ldns`, `mtl-mode-nsd` and
`mtl-mode-unbound` at pinned commits, applies the two patches in `patches/`,
and builds their Dockerfiles. OpenSSL and liboqs compile from source, so the
first build is slow.

### Why there are two patches

Testing the pinned commits end to end turned up two bugs. Both are small and
worth reporting to your mentor (and upstream to Verisign):

1. **`mtl-mode-unbound-slh-dsa-pure.patch`**: Unbound verifies algorithm 246
   with liboqs `SPHINCS+-SHA2-128s-simple`, but ldns signs it with
   `SLH_DSA_PURE_SHA2_128S` (FIPS 205), and liboqs 0.16 no longer ships
   SPHINCS+ at all. Without the patch every plain SLH-DSA answer is SERVFAIL,
   so you'd have no non-MTL baseline. The patch maps 246/247 to the FIPS 205
   names.
2. **`mtl-mode-nsd-condensed-default.patch`**: the latest NSD commit
   ("align with draft-kaizer…") always expands condensed MTL signatures to full
   ones, and the 65050 option became a no-op. That makes every MTL answer
   ~8 KB and hides MTL's benefit. The patch restores the previous behaviour:
   condensed by default, full only when the query carries EDNS option 65050.
   Unbound sends 65050 itself when it needs a ladder, so validation works.

If your mentor gives you different "mentor-tested" commits, change the pins in
`build-images.sh` and check whether these patches are still needed.

## 2. Sign the zones

```bash
docker compose run --rm signer                 # 100 records per zone
RECORDS=1000  docker compose run --rm signer   # dataset size 2
RECORDS=10000 docker compose run --rm signer   # dataset size 3
```

Output lands in `./zones/`: the signed zones, `trust-anchors.txt` (DS records
Unbound trusts) and `signing-times.csv`. Re-signing creates new keys, so
restart the servers afterwards (`docker compose restart nsd unbound`).

**Plan for signing time.** Plain SLH-DSA-128s signs every RRset separately and
is slow. On a 2-core machine, 100 records took about 2.3 minutes, so expect
roughly 20+ minutes for 1,000 and several hours for 10,000. MTL signs the
ladder once, so it took 1.3 s for 100 records. That gap *is* one of your
benchmark results, but run the 10,000-record SLH-DSA signing overnight.

## 3. Start the servers

```bash
docker compose up -d nsd unbound client
docker compose logs unbound | tail      # should show no errors
```

## 4. Query

**From your shell:**

```bash
# Straight to the authoritative server (no validation)
dig @127.0.0.1 -p 5301 www.ecdsa.lab A +dnssec
dig @127.0.0.1 -p 5301 www.slh.lab   A +dnssec
dig @127.0.0.1 -p 5301 www.mtl.lab   A +dnssec               # condensed MTL signature
dig @127.0.0.1 -p 5301 www.mtl.lab   A +dnssec +ednsopt=65050 # full MTL signature

# Through the validating resolver: look for the "ad" flag
dig @127.0.0.1 -p 5302 www.mtl.lab A +dnssec
```

**From the client container** (traffic stays inside the Docker network):

```bash
docker compose exec client dig @172.30.0.54 www.slh.lab A +dnssec
docker compose exec client dig @172.30.0.53 www.mtl.lab A +dnssec
```

What a test run of this lab looked like (100 records, `www` A query):

| Query | Response | Transport |
|---|---|---|
| ECDSA, direct to NSD | 407 B | UDP |
| SLH-DSA, direct to NSD | 23,775 B | truncated → TCP |
| **SLH-DSA-MTL condensed**, direct to NSD | **630 B** | **UDP** |
| SLH-DSA-MTL with `+ednsopt=65050` (full) | 8,654 B | truncated → TCP |
| All three via Unbound | `ad` flag set | validated |

Stored signature sizes in the MTL zone: condensed 93–189 B per RRset, full
8,213 B only on SOA and DNSKEY. Plain SLH-DSA is 7,856 B on every RRset.

Things to compare:

- **`MSG SIZE rcvd`** at the bottom of dig output.
- **`;; Truncated, retrying in TCP mode`**: SLH-DSA answers exceed 1232 bytes
  and fall back to TCP. MTL condensed answers fit in UDP.
- **`ad` flag** from Unbound: validation succeeded.
- **Option 65050**: asks NSD for the full MTL signature (condensed + signed
  ladder). A validator needs it once per ladder; after that, condensed
  answers are enough.

## 5. Capture in Wireshark

**Linux host:** start Wireshark and capture on the **`pqclab0`** interface. It
sees client→Unbound, Unbound→NSD and host→container traffic (port-mapped
queries arrive via the bridge). Display filter: `dns`.

**Mac / Windows (Docker Desktop):** the bridge lives inside Docker's VM, so use
the capture sidecars:

```bash
docker compose --profile capture up -d
# ... run your digs ...
docker compose --profile capture stop capture-nsd capture-unbound
# open ./captures/nsd.pcap and ./captures/unbound.pcap in Wireshark
```

Or stream live into Wireshark (Linux/Mac):

```bash
docker compose exec -T client tcpdump -i eth0 -U -w - port 53 | wireshark -k -i -
```

**Useful Wireshark filters**

| Filter | Shows |
|---|---|
| `dns.rr.type == 46` | RRSIG records |
| `dns.rrsig.algorithm == 130` | SLH-DSA-MTL signatures |
| `dns.rrsig.algorithm == 246` | SLH-DSA signatures (no MTL) |
| `dns.flags.truncated == 1` | Responses too big for UDP |
| `tcp.port == 53` | TCP fallback traffic |
| `dns.opt.code == 65050` | Queries asking for full MTL signatures |
| `ip.frag_offset > 0` | IP fragments (if you raise the EDNS size) |

Wireshark doesn't know algorithms 130/246 by name, so it shows the number.
That's expected.

**Measuring bytes:** Statistics → Conversations, or
`tshark -r captures/unbound.pcap -q -z io,stat,0,"SUM(frame.len)frame.len"`.
Run the same query set against each zone and compare totals.

## 6. Cache behaviour (for "measured" cache numbers)

```bash
docker compose exec unbound unbound-control -c /etc/lab/unbound.conf stats_noreset | grep -E 'total.num|cache|mem'
docker compose exec unbound unbound-control -c /etc/lab/unbound.conf flush_zone mtl.lab   # cold cache again
```

With MTL, the ladder is fetched once and cached. In a capture of Unbound→NSD
traffic from a cold cache, querying four `mtl.lab` names showed:

1. The A answer arrives condensed (672 B, UDP).
2. Unbound re-queries DNSKEY with option 65050. The full answer is truncated
   over UDP and comes over TCP (~17 kB for the exchange).
3. Every later answer is condensed (774 B, UDP), with no more full fetches.

To reproduce, filter `dns.opt.code == 65050` in Wireshark after a
`flush_zone mtl.lab`. This is your "directly measured" cache data. The
analytical estimate is the formula in your report.

## Experiment knobs

- `RECORDS=` dataset size when signing.
- `edns-buffer-size` / `max-udp-size` in `config/unbound.conf`: raise to 4096
  to see IP fragmentation instead of TCP fallback.
- `cache-max-ttl: 0` in `config/unbound.conf` to make every query hit NSD.

## 7. Visual simulator (optional)

A small local web dashboard that drives the same docker compose workflow
with buttons instead of typing commands, and charts the results (sign time,
verify time, response size/transport, cache hits).

```bash
pip install -r simulator/requirements.txt
python3 simulator/app.py
# open http://127.0.0.1:5500
```

It runs `docker compose` and `dig` under the hood with fixed arguments (no
shell injection from form input) and only binds to localhost. Signing is
run as a background job since plain SLH-DSA at high `RECORDS` can take
hours; the page polls until it's done.

## Clean up

```bash
docker compose --profile capture --profile sign down
```

No host config is changed, so that's all there is to undo.
