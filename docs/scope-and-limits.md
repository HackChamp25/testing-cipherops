# Scope and limits

What CipherOps claims, what it does not, and how the requirements of the problem statement (PS-036) are covered.

## Scope

- Empirical timings and wire sizes on pinned stacks. This is **not** a security proof and **not** a production DNSSEC
  product. It calls published libraries and adds no cryptography.
- Two measurement paths that answer different questions:

  | | Offline harness | Simulated lab |
  | --- | --- | --- |
  | What it is | a C harness (`harness/mtlbench.c`) times each library call; DNS messages are built and counted in Python | a root → TLD → leaf hierarchy of unmodified NSD servers behind a validating Unbound, in Docker |
  | Best for | signing and verification time, signature and response sizes, cache arithmetic, zone updates | what a resolver does: bytes per hop from packet captures, truncation, TCP retry, Unbound's cache counters |
  | Environment | one pinned image, one dedicated core, no network | three images per stack; containers share all host CPUs |
  | Start it | `scripts/run_benchmark.sh`, or **Benchmark → Offline** | **Benchmark → Simulated** |

  The two are never drawn on one chart: they use different libraries and versions.

## Limits

- **Profiles are not interchangeable.** Offline results are FIPS 205 SLH-DSA (`latest`); simulated results on `draft06`
  are the pre-standard SPHINCS+ form with the same sizes. Each run records its profile.
- **Simulated timings are indicative.** Containers are not pinned to cores and the CPU governor is recorded, not
  changed. Byte counts and relative comparisons are more reliable than absolute milliseconds.
- **Fixtures.** The reference library's known-answer vectors cover ML-DSA, not SLH-DSA. SLH-DSA is checked by round
  trips, negative cases and agreement between independent implementations (liboqs and OpenSSL, plus Verisign's
  `mtlverify`). That is an interoperability check, not a NIST known-answer test
  ([methodology §3](methodology.md#3-gono-go-gate)).
- **Few trials give wide intervals.** The full run uses 10 trials (the interval of the median covers 98%); the quick
  run uses 3 (75%) ([methodology §6.2](methodology.md#62-statistics)).
- **Synthetic zones and updates.** Zones are generated; the zone-update experiment applies same-size random changes
  with one signer and one resolver.
- **Placeholders, not assignments.** DNSSEC algorithm numbers and the `mtl-mode-full` EDNS option are lab values, not
  IANA assignments. Nothing here is for the Internet.
- **The drafts are drafts.** MTL mode and its DNSSEC profiles are individual Internet-Drafts, not RFCs. Status:
  [Learn: where the IETF stands](learn/README.md#where-the-ietf-stands).

## Software stacks

Every version lives in one file per **stack profile**, [`ecosystem/stacks/<profile>.env`](../ecosystem/stacks). The
offline image and the lab images are both built from that file, so a version cannot differ by accident, and every
report names its profile. Both use a Fedora 42 base and OpenSSL 3.6.0.

| Profile | MTL / liboqs | Signature primitive | Default for | Resolver validates plain SLH-DSA |
| --- | --- | --- | --- | --- |
| `latest` | `7cef019` / 0.16.0 | FIPS 205 SLH-DSA, one library call for MTL and the plain baseline | **offline harness** | **no** (SERVFAIL) |
| `draft06` | 1.2.0 `93b05ef` / 0.14.0 | SPHINCS+-SHA2-128s-simple, the pre-standard form (same sizes) | **simulated lab** | yes |

The harness uses `latest` so that MTL and the baseline are the same FIPS 205 primitive; on `draft06` its gate reports
NO-GO. The lab uses `draft06` because only there does a resolver validate all three algorithms. On `latest` the
Unbound binary still names a SPHINCS+ algorithm that liboqs 0.16 removed, which points to an upstream mismatch; this is
not confirmed from source and not yet reported upstream. Evidence and rejected alternatives:
[design decisions](design-decisions.md).

## PS-036 coverage

| Requirement | Where it is met |
| --- | --- |
| One supported PQC algorithm | SLH-DSA-SHA2-128s |
| One MTL reference implementation | Verisign MTL, pinned by commit (stack profile) |
| Three dataset sizes | 50 / 500 / 5,000 names by default; quick run 20 / 60 / 200 |
| With and without MTL | `slh-dsa-mtl` vs `slh-dsa`, plus classical references |
| Repeated trials, pinned environment | pinned image, dedicated core, seeded order, discarded warm-up (offline); the simulated lab is not core-pinned |
| Signing time, verification time, transmitted bytes | `trials.csv`, `responses.csv`, `workload.csv`; simulated-lab captures |
| MTL on a changing zone (beyond the minimum) | `evolution.csv` and the dashboard's **Zone updates** view |
| Record configuration and workload parameters | `config.yaml`, `environment.json`, `suite.json` in each run |
| Cache: measured vs analytical, kept apart | `cache.csv` has a `kind` column; the report never mixes them |
| Defer if implementation or fixtures are missing | the go/no-go gate (`preflight`) blocks the run |
| No new cryptography, resolver or deployment | the harness only calls libraries; the lab uses stock servers |
