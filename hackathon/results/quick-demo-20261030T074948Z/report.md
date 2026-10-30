# Benchmarking MTL Mode for Post-Quantum DNSSEC Signatures
### PS-036 · PQC DNSSEC MTL Benchmark Using a Reference Implementation · AIORI Hackathon 3

Run `20261030T074948Z-quick-demo` · go/no-go gate: **GO** · 3 trials · seed 20261005 · stack `latest` · git `90ecbc1f20cc3139d070ac97d943f05ea97ec50e`

## Abstract

Post-quantum signatures such as SLH-DSA-SHA2-128s are 7,856 bytes long. A DNSSEC response that carries one no longer fits the 1232-byte UDP size recommended for DNS, so resolvers fall back to TCP. Merkle Tree Ladder (MTL) mode (draft-harvey-cfrg-mtl-mode) signs a whole zone with one PQC signature over a Merkle ladder. Each RRset then carries only a short authentication path. We benchmark signing time, verification time, transmitted bytes and cache usage for DNSSEC zones of three sizes, comparing classical algorithms, direct SLH-DSA-SHA2-128s and SLH-DSA-SHA2-128s in MTL mode. All cryptography comes from the supplied Verisign MTL reference library, liboqs and OpenSSL, in a pinned container.

**Key results** (directly measured unless marked *extrapolated*):

- **Signing (small zone, 45 RRsets, fully measured).** MTL signed the zone in 835.42 ms [834.38 ms–876.59 ms]; direct SLH-DSA took 36.55 s [33.87 s–37.40 s]. MTL was 43.8× [38.6×, 44.8×] faster (median of the per-trial ratios, interval in brackets).
- **Verification (small zone, warm).** MTL took 1.01 ms for every RRSIG in the zone; direct SLH-DSA took 37.60 ms.
- **Signing (large zone, 405 RRsets).** MTL measured 752.10 ms. Direct SLH-DSA signed 100 sampled RRsets at 785.65 ms each, which extrapolates to 318.19 s for the whole zone *(extrapolated)*.
- **Response size (large zone).** At a 1232-byte EDNS buffer, 78% of MTL responses fit in UDP, compared with 0% for direct SLH-DSA.
- **Transmitted bytes (large zone).** The lookup workload transmitted 88.89 KB with MTL and 1.52 MB with direct SLH-DSA. 106 truncation and TCP-retry events became 32, plus 1 full-signature fetch.

## 1. Problem statement

DNSSEC relies on UDP, and on responses that fit a single unfragmented datagram (1232 bytes since DNS Flag Day 2020). Post-quantum signature schemes standardised by NIST have signatures that are one to two orders of magnitude larger than RSA or ECDSA. PS-036 asks for a reproducible measurement of what MTL mode changes for DNSSEC, compared with using the same PQC algorithm directly, using a reference implementation rather than new cryptography.

## 2. Background

- **DNSSEC** (RFC 4033–4035) signs each RRset. The RRSIG signature covers the RRSIG RDATA and the canonical RRset (RFC 4034 §3.1.8.1). NSEC3 (RFC 5155) proves non-existence.
- **SLH-DSA-SHA2-128s** (FIPS 205) is a stateless hash-based signature: 32-byte public key, 7,856-byte signature.
- **MTL mode** (draft-harvey-cfrg-mtl-mode-09) appends each message to a Merkle node set:
  - A *ladder* of rungs covering all messages is signed once with the underlying scheme.
  - A *condensed signature* is a short authentication path from one message to a rung.
  - A *full signature* is the condensed signature plus the signed ladder.
  - A verifier that has cached a ladder checks only hashes.
- **DNSSEC MTL mode** (draft-fregly-dnsop-slh-dsa-mtl-dnssec) prefixes the RRSIG signature with an MTL-Type byte. Validators request full signatures with an EDNS option, preferably over TCP.

## 3. Objectives and scope

Compare equivalent DNSSEC signing workloads with and without MTL, on three dataset sizes, measuring signing time, verification time and transmitted bytes. Report cache usage, keeping direct measurements separate from analytical estimates. Classical algorithms are included as a reference point. Out of scope, per PS-036: new cryptography, a resolver implementation, Internet deployment and any security proof.

| PS-036 requirement | How it is met | Where |
|---|---|---|
| One supported PQC signature algorithm | SLH-DSA-SHA2-128s (FIPS 205) in every PQC mode | §2, §4 |
| One mentor-tested MTL reference implementation | Verisign MTL C library at a pinned commit; no own crypto | §4, Appendix A |
| Three dataset sizes | small / medium / large synthetic zones | §4.3, Table 2 |
| Equivalent workloads with and without MTL | byte-identical RRsets and RFC 4034 signing inputs for every mode | §4.3 |
| Repeated trials, pinned software and hardware | N trials, one process per trial, interleaved order, pinned image, cpuset | §4.1, §4.5 |
| Signing time | measured per library call, whole-zone totals with 95% CIs | §5.1 |
| Verification time | warm (cached ladder) and cold (full signature) | §5.2 |
| Transmitted bytes | real DNS messages, 1232/4096 B buffers, TC + TCP fallback | §5.3 |
| Record configuration and workload parameters | config.yaml, environment.json, datasets table | Appendix A–B |
| Separate measured cache usage from analytical estimates | separate tables, `kind` column | §5.4 |
| Defer if implementation and fixtures unavailable | go/no-go gate; run aborts with NO-GO | §4.2, Appendix C |
| No new crypto, resolver, Internet deployment, security proof | none built or claimed | §7 |

## 4. Methodology

### 4.1 Pinned environment

| Item | Value |
|---|---|
| CPU | Intel(R) Core(TM) Ultra 7 165H |
| CPU affinity (cpuset) | [2] |
| Memory | MemTotal:       65248288 kB |
| Kernel | 7.2.11-100.fc43.x86_64 |
| OS | NAME="Fedora Linux"; VERSION="42 (Container Image)"; RELEASE_TYPE=stable; ID=fedora |
| Compiler | gcc (GCC) 15.2.1 20260123 (Red Hat 15.2.1-7) |
| Stack profile | latest |
| SLH-DSA call (liboqs name) | SLH_DSA_PURE_SHA2_128S |
| OpenSSL | OpenSSL 3.6.0 1 Oct 2025 (Library: OpenSSL 3.6.0 1 Oct 2025) |
| liboqs | 0.16.0 |
| MTL reference commit | 7cef0191da55048111d252a567b7614672424ed3 |
| MTL compile flags | -fPIC -Wall -Wextra -O2 |
| Python | 3.13.13 |
| Container image | sha256:d05eeb6684c037f5c48afe348a1fe1cacb7c580e4810e2ed9ba9a71643253524 |
| Harness sha256 | 533ab957c8eca39f… |

### 4.2 Go/no-go gate

PS-036 requires deferring the project if the implementation or its fixtures are not available. Before any measurement, the runner checks:

1. The reference library is installed.
2. Its own unit tests and test vectors pass.
3. Its key-generation, signing and verification tools round-trip with SLH-DSA-SHA2-128s-MTL, and a tampered message is rejected.
4. Every harness mode verifies its own output and rejects tampering, wrong keys, truncated signatures and signatures presented for another message.
5. The harness output is verified by a different program: `mtlverify` for MTL and OpenSSL for the non-MTL SLH-DSA signatures (an interoperability check, not a known-answer test).

The run aborts with `NO-GO` otherwise. The outcome of each check is listed in Appendix C.

### 4.3 Workloads

Each dataset is a deterministic synthetic zone `bench.example.`:

- **small (60% of names):** one A or AAAA record
- **medium (30%):** three MX or four AAAA records
- **large (10%):** one 1–2 KB TXT record

The zone also has the apex SOA, NS, DNSKEY and NSEC3PARAM, and a complete NSEC3 chain (0 iterations, RFC 9276). Each RRset is one signing message. The RFC 4034 signing inputs are produced by dnspython; a test checks that dnspython's standard validator accepts signatures over these exact bytes. Every mode signs the same RRsets with fixed inception and expiration times. The only differences between modes are the RRSIG algorithm number, key tag and DNSKEY, which belong to the signed data.

| dataset | n_names | rrsets | apex | small | medium | large | nsec3 | signing_input_bytes |
|---|---|---|---|---|---|---|---|---|
| small | 20 | 45 | 4 | 14 | 3 | 3 | 21 | 9.31 KB |
| medium | 60 | 125 | 4 | 32 | 17 | 11 | 61 | 33.94 KB |
| large | 200 | 405 | 4 | 117 | 70 | 13 | 201 | 69.84 KB |

*Table 2: datasets.*

### 4.4 Modes

| Mode | Harness path | Library algorithm | DNSSEC alg # |
|---|---|---|---|
| RSA-2048/SHA-256 (alg 8) | classical | rsa-2048 | 8 |
| ECDSA P-256 (alg 13) | classical | ecdsa-p256 | 13 |
| Ed25519 (alg 15) | classical | ed25519 | 15 |
| SLH-DSA-SHA2-128s without MTL | direct | SLH_DSA_PURE_SHA2_128S | 249 |
| SLH-DSA-SHA2-128s with MTL | mtl | SLH-DSA-SHA2-128s-MTL-SHA2-128 | 50 |

The DNSSEC algorithm numbers for SLH-DSA (direct and MTL) and the EDNS option `mtl-mode-full` (code 65001) are lab placeholders.

### 4.5 Measurement procedure

- Each trial runs one harness process per mode and dataset. The process links the reference library, liboqs and OpenSSL, and times each library call with `CLOCK_MONOTONIC_RAW`.
- Modes run in a seeded random order inside each trial, after 1 warm-up trial(s). There are 3 measured trials.
- **MTL signing (whole zone)** = append every RRset + sign the ladder once + extract every condensed signature.
- **MTL warm verification** = verify the ladder once + verify every condensed signature against it. The verifier is built from the exported public key only.
- **MTL cold verification** = full signature without a cached ladder, on 16 RRsets.
- **Noise.** The clock's own cost and resolution are measured at the start of the run (Table 4d), and `ed25519` runs twice inside every trial as an A/A control (Table 4c).
- **Correctness.** A trial counts only if every signature verifies and tampered messages, signatures and ladders are rejected.
- **Statistics.** We report the median across trials with a distribution-free confidence interval of the median (order statistics). With 3 trials it is the 75% CI of the median over 3 trials (below the 95% target: too few trials).
- **Transmitted bytes.** Measured on real DNS messages encoded by dnspython, using the signatures from trial 0.

## 5. Results

### 5.1 Signing time


![Figure 1: whole-zone signing time (log scale)](figures/sign.png)

*Figure 1: whole-zone signing time (log scale)*

| dataset | mode | RRsets signed | sign zone, median [CI] | per RRset | zone total (extrapolated) | keygen |
|---|---|---|---|---|---|---|
| small | RSA-2048/SHA-256 (alg 8) | 45/45 | 49.74 ms [49.43 ms–49.81 ms] | 1.11 ms |  | 166.72 ms |
| small | ECDSA P-256 (alg 13) | 45/45 | 3.07 ms [2.63 ms–3.49 ms] | 68.3 µs |  | 2.96 ms |
| small | Ed25519 (alg 15) | 45/45 | 3.67 ms [3.11 ms–4.01 ms] | 81.6 µs |  | 2.89 ms |
| small | SLH-DSA-SHA2-128s without MTL | 45/45 | 36.55 s [33.87 s–37.40 s] | 812.33 ms |  | 112.91 ms |
| small | SLH-DSA-SHA2-128s with MTL | 45/45 | 835.42 ms [834.38 ms–876.59 ms] | 18.56 ms |  | 113.20 ms |
| medium | RSA-2048/SHA-256 (alg 8) | 125/125 | 133.42 ms [122.36 ms–135.77 ms] | 1.07 ms |  | 60.93 ms |
| medium | ECDSA P-256 (alg 13) | 125/125 | 6.63 ms [5.93 ms–7.09 ms] | 53.0 µs |  | 2.67 ms |
| medium | Ed25519 (alg 15) | 125/125 | 8.31 ms [7.82 ms–8.49 ms] | 66.5 µs |  | 2.74 ms |
| medium | SLH-DSA-SHA2-128s without MTL | 60/125 | 46.12 s [45.18 s–49.04 s] | 768.60 ms | 96.07 s | 110.35 ms |
| medium | SLH-DSA-SHA2-128s with MTL | 125/125 | 833.25 ms [745.89 ms–852.38 ms] | 6.67 ms |  | 112.75 ms |
| large | RSA-2048/SHA-256 (alg 8) | 405/405 | 402.44 ms [401.26 ms–434.95 ms] | 993.7 µs |  | 46.38 ms |
| large | ECDSA P-256 (alg 13) | 405/405 | 18.67 ms [17.68 ms–19.24 ms] | 46.1 µs |  | 2.81 ms |
| large | Ed25519 (alg 15) | 405/405 | 23.23 ms [22.44 ms–25.66 ms] | 57.4 µs |  | 2.92 ms |
| large | SLH-DSA-SHA2-128s without MTL | 100/405 | 78.57 s [78.29 s–82.78 s] | 785.65 ms | 318.19 s | 101.21 ms |
| large | SLH-DSA-SHA2-128s with MTL | 405/405 | 752.10 ms [743.84 ms–824.47 ms] | 1.86 ms |  | 100.16 ms |

*Table 3: signing time.*

MTL signing time breakdown (medians):

| dataset | append all RRsets | sign ladder (1 SLH-DSA) | extract condensed sigs |
|---|---|---|---|
| small | 342.8 µs | 835.06 ms | 19.0 µs |
| medium | 563.0 µs | 832.61 ms | 73.1 µs |
| large | 1.21 ms | 750.57 ms | 295.1 µs |

### 5.2 Verification time


![Figure 2: whole-zone verification time with a cached ladder (log scale)](figures/verify.png)

*Figure 2: whole-zone verification time with a cached ladder (log scale)*

| dataset | mode | verify zone (warm), median [CI] | per RRset (warm) | one signature, cold | checks passed |
|---|---|---|---|---|---|
| small | RSA-2048/SHA-256 (alg 8) | 1.45 ms [1.44 ms–2.01 ms] | 32.2 µs | 31.6 µs | yes |
| small | ECDSA P-256 (alg 13) | 6.86 ms [6.12 ms–7.03 ms] | 152.5 µs | 131.4 µs | yes |
| small | Ed25519 (alg 15) | 8.95 ms [8.63 ms–9.79 ms] | 198.9 µs | 173.0 µs | yes |
| small | SLH-DSA-SHA2-128s without MTL | 37.60 ms [36.88 ms–37.62 ms] | 835.5 µs | 756.7 µs | yes |
| small | SLH-DSA-SHA2-128s with MTL | 1.01 ms [992.8 µs–1.59 ms] | 22.3 µs | 776.4 µs | yes |
| medium | RSA-2048/SHA-256 (alg 8) | 4.02 ms [3.99 ms–4.12 ms] | 32.2 µs | 31.5 µs | yes |
| medium | ECDSA P-256 (alg 13) | 15.28 ms [14.98 ms–16.51 ms] | 122.2 µs | 118.5 µs | yes |
| medium | Ed25519 (alg 15) | 21.97 ms [21.34 ms–23.92 ms] | 175.7 µs | 170.7 µs | yes |
| medium | SLH-DSA-SHA2-128s without MTL | 45.01 ms [44.56 ms–46.28 ms] | 750.1 µs | 743.8 µs | yes |
| medium | SLH-DSA-SHA2-128s with MTL | 1.43 ms [1.39 ms–1.51 ms] | 11.4 µs | 767.4 µs | yes |
| large | RSA-2048/SHA-256 (alg 8) | 13.04 ms [12.97 ms–14.12 ms] | 32.2 µs | 31.5 µs | yes |
| large | ECDSA P-256 (alg 13) | 49.51 ms [48.75 ms–53.10 ms] | 122.2 µs | 117.9 µs | yes |
| large | Ed25519 (alg 15) | 69.63 ms [69.54 ms–76.39 ms] | 171.9 µs | 169.8 µs | yes |
| large | SLH-DSA-SHA2-128s without MTL | 75.91 ms [74.22 ms–81.40 ms] | 759.1 µs | 741.2 µs | yes |
| large | SLH-DSA-SHA2-128s with MTL | 3.38 ms [3.35 ms–3.91 ms] | 8.4 µs | 769.2 µs | yes |

*Table 4: verification time. For MTL, "cold" means a full signature verified without a cached ladder; for other modes it is the median single-signature verification.*

#### Paired ratios: direct SLH-DSA divided by MTL

Every mode runs inside each trial, so each trial gives one ratio. The table shows the median of those per-trial ratios and its distribution-free interval; it is what supports a statement such as "N times faster".

| dataset | metric | trials | ratio, median [interval] | interval covers | basis | against the A/A noise floor |
|---|---|---|---|---|---|---|
| small | signing | 3 | 43.8× [38.6×, 44.8×] | 75% | measured | clearly outside (±16.6%) |
| medium | signing | 3 | 123× [110×, 129×] | 75% | extrapolated direct total | clearly outside (±11.3%) |
| large | signing | 3 | 423× [407×, 426×] | 75% | extrapolated direct total | clearly outside (±1.9%) |
| small | verification (warm) | 3 | 37.4× [23.2×, 37.9×] | 75% | measured | clearly outside (±3.1%) |
| medium | verification (warm) | 3 | 67.0× [62.1×, 67.4×] | 75% | extrapolated direct total | clearly outside (±0.8%) |
| large | verification (warm) | 3 | 88.8× [84.4×, 91.7×] | 75% | extrapolated direct total | clearly outside (±1.2%) |

*Table 4b: paired per-trial ratios.*

#### Measurement noise: the A/A control

`ed25519` ran twice inside every trial, on the same input, as if it were two different modes. The true ratio is 1, so the table below is the measurement's own noise. A difference between two modes that is smaller than this band must not be reported as a difference.

| dataset | metric | trials | A/A ratio, median [interval] | noise band |
|---|---|---|---|---|
| small | signing | 3 | 1.006 [0.908, 1.166] | ±16.6% |
| medium | signing | 3 | 1.011 [0.887, 1.030] | ±11.3% |
| large | signing | 3 | 0.995 [0.981, 1.013] | ±1.9% |
| small | verification (warm) | 3 | 0.983 [0.969, 1.027] | ±3.1% |
| medium | verification (warm) | 3 | 1.005 [0.999, 1.008] | ±0.8% |
| large | verification (warm) | 3 | 0.994 [0.988, 1.006] | ±1.2% |

*Table 4c: A/A control (one mode against its own copy).*

#### Measurement noise: the timer

Every library call is timed with `CLOCK_MONOTONIC_RAW`. An empty timed region cost 29 ns (median; p99 38 ns), and the smallest step the clock was seen to take is 25 ns. The two fastest operations were timed both one call at a time (as in the benchmark) and as 1,000 calls in one region divided by 1,000:

| operation | per call, median | batch of 1,000, per call | difference | timer cost as share of the operation |
|---|---|---|---|---|
| ed25519 verify | 167.2 µs | 169.3 µs | -1.2% | 0.0% |
| mtl condensed verify | 1.2 µs | 1.1 µs | +0.3% | 2.5% |

*Table 4d: timer calibration.* Per-call timing is reliable for these operations (timer cost at most 5% of the operation).

### 5.3 Transmitted bytes

| dataset | mode | signature bytes (median / max) | signed ladder bytes | public key bytes |
|---|---|---|---|---|
| small | RSA-2048/SHA-256 (alg 8) | 256 / 256 |  | 260 |
| small | ECDSA P-256 (alg 13) | 64 / 64 |  | 64 |
| small | Ed25519 (alg 15) | 64 / 64 |  | 32 |
| small | SLH-DSA-SHA2-128s without MTL | 7,856 / 7,856 |  | 32 |
| small | SLH-DSA-SHA2-128s with MTL | 156 / 156 | 8,024 | 32 |
| medium | RSA-2048/SHA-256 (alg 8) | 256 / 256 |  | 260 |
| medium | ECDSA P-256 (alg 13) | 64 / 64 |  | 64 |
| medium | Ed25519 (alg 15) | 64 / 64 |  | 32 |
| medium | SLH-DSA-SHA2-128s without MTL | 7,856 / 7,856 |  | 32 |
| medium | SLH-DSA-SHA2-128s with MTL | 172 / 172 | 8,088 | 32 |
| large | RSA-2048/SHA-256 (alg 8) | 256 / 256 |  | 260 |
| large | ECDSA P-256 (alg 13) | 64 / 64 |  | 64 |
| large | Ed25519 (alg 15) | 64 / 64 |  | 32 |
| large | SLH-DSA-SHA2-128s without MTL | 7,856 / 7,856 |  | 32 |
| large | SLH-DSA-SHA2-128s with MTL | 204 / 204 | 8,056 | 32 |

*Table 5: signature sizes measured on library output. The MTL RRSIG field adds a 1-byte MTL-Type prefix.*


![Figure 3: DNS response sizes by record class, measured](figures/responses.png)

*Figure 3: DNS response sizes by record class, measured*

| dataset | record_class | RSA-2048/SHA-256 (alg 8) | ECDSA P-256 (alg 13) | Ed25519 (alg 15) | SLH-DSA-SHA2-128s without MTL | SLH-DSA-SHA2-128s with MTL |
|---|---|---|---|---|---|---|
| small | small | 100.0 | 100.0 | 100.0 | 0.0 | 100.0 |
| small | medium | 100.0 | 100.0 | 100.0 | 0.0 | 100.0 |
| small | large | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| small | nxdomain | 14.0 | 100.0 | 100.0 | 0.0 | 100.0 |
| medium | small | 100.0 | 100.0 | 100.0 | 0.0 | 100.0 |
| medium | medium | 100.0 | 100.0 | 100.0 | 0.0 | 100.0 |
| medium | large | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| medium | nxdomain | 4.0 | 100.0 | 100.0 | 0.0 | 100.0 |
| large | small | 100.0 | 100.0 | 100.0 | 0.0 | 100.0 |
| large | medium | 100.0 | 100.0 | 100.0 | 0.0 | 100.0 |
| large | large | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| large | nxdomain | 0.0 | 100.0 | 100.0 | 0.0 | 14.0 |

*Table 6: percentage of responses that fit a 1232-byte EDNS UDP buffer without truncation.*


![Figure 4: total DNS bytes for the lookup workload at a 1232-byte buffer](figures/workload.png)

*Figure 4: total DNS bytes for the lookup workload at a 1232-byte buffer*

| dataset | mode | UDP buffer | responses | DNS bytes | of which RRSIG sig bytes | TC → TCP | MTL full fetches | round trips (est.) |
|---|---|---|---|---|---|---|---|---|
| small | RSA-2048/SHA-256 (alg 8) | 1232 | 48 | 55.15 KB | 30.21 KB | 19 | 0 | 86 |
| small | RSA-2048/SHA-256 (alg 8) | 4096 | 48 | 52.93 KB | 30.21 KB | 0 | 0 | 48 |
| small | ECDSA P-256 (alg 13) | 1232 | 48 | 30.41 KB | 7.55 KB | 3 | 0 | 54 |
| small | ECDSA P-256 (alg 13) | 4096 | 48 | 30.08 KB | 7.55 KB | 0 | 0 | 48 |
| small | Ed25519 (alg 15) | 1232 | 48 | 30.38 KB | 7.55 KB | 3 | 0 | 54 |
| small | Ed25519 (alg 15) | 4096 | 48 | 30.05 KB | 7.55 KB | 0 | 0 | 48 |
| small | SLH-DSA-SHA2-128s without MTL | 1232 | 48 | 955.50 KB | 927.01 KB | 48 | 0 | 144 |
| small | SLH-DSA-SHA2-128s without MTL | 4096 | 48 | 955.50 KB | 927.01 KB | 48 | 0 | 144 |
| small | SLH-DSA-SHA2-128s with MTL | 1232 | 48 | 48.20 KB | 25.19 KB | 3 | 1 | 56 |
| small | SLH-DSA-SHA2-128s with MTL | 4096 | 48 | 47.87 KB | 25.19 KB | 0 | 1 | 50 |
| medium | RSA-2048/SHA-256 (alg 8) | 1232 | 74 | 86.69 KB | 39.17 KB | 36 | 0 | 146 |
| medium | RSA-2048/SHA-256 (alg 8) | 4096 | 74 | 82.53 KB | 39.17 KB | 0 | 0 | 74 |
| medium | ECDSA P-256 (alg 13) | 1232 | 74 | 54.17 KB | 9.79 KB | 11 | 0 | 96 |
| medium | ECDSA P-256 (alg 13) | 4096 | 74 | 52.96 KB | 9.79 KB | 0 | 0 | 74 |
| medium | Ed25519 (alg 15) | 1232 | 74 | 54.14 KB | 9.79 KB | 11 | 0 | 96 |
| medium | Ed25519 (alg 15) | 4096 | 74 | 52.93 KB | 9.79 KB | 0 | 0 | 74 |
| medium | SLH-DSA-SHA2-128s without MTL | 1232 | 74 | 1.25 MB | 1.20 MB | 74 | 0 | 222 |
| medium | SLH-DSA-SHA2-128s without MTL | 4096 | 74 | 1.25 MB | 1.20 MB | 74 | 0 | 222 |
| medium | SLH-DSA-SHA2-128s with MTL | 1232 | 74 | 77.32 KB | 32.79 KB | 11 | 1 | 98 |
| medium | SLH-DSA-SHA2-128s with MTL | 4096 | 74 | 76.11 KB | 32.79 KB | 0 | 1 | 76 |
| large | RSA-2048/SHA-256 (alg 8) | 1232 | 106 | 92.61 KB | 47.87 KB | 34 | 0 | 174 |
| large | RSA-2048/SHA-256 (alg 8) | 4096 | 106 | 88.65 KB | 47.87 KB | 0 | 0 | 106 |
| large | ECDSA P-256 (alg 13) | 1232 | 106 | 53.32 KB | 11.97 KB | 7 | 0 | 120 |
| large | ECDSA P-256 (alg 13) | 4096 | 106 | 52.55 KB | 11.97 KB | 0 | 0 | 106 |
| large | Ed25519 (alg 15) | 1232 | 106 | 53.29 KB | 11.97 KB | 7 | 0 | 120 |
| large | Ed25519 (alg 15) | 4096 | 106 | 52.52 KB | 11.97 KB | 0 | 0 | 106 |
| large | SLH-DSA-SHA2-128s without MTL | 1232 | 106 | 1.52 MB | 1.47 MB | 106 | 0 | 318 |
| large | SLH-DSA-SHA2-128s without MTL | 4096 | 106 | 1.52 MB | 1.47 MB | 106 | 0 | 318 |
| large | SLH-DSA-SHA2-128s with MTL | 1232 | 106 | 88.89 KB | 44.44 KB | 32 | 1 | 172 |
| large | SLH-DSA-SHA2-128s with MTL | 4096 | 106 | 85.17 KB | 44.44 KB | 0 | 1 | 108 |

*Table 7: workload accounting. Workload: 300 lookups following a Zipf(s=1.1) distribution, with 10% going to non-existent names. Assumptions:*

- *A cached answer is not re-sent.*
- *An oversize answer costs a UDP query, a TC=1 reply and a TCP retry.*
- *An MTL validator fetches one full signature over TCP on first contact.*

*Byte counts are measured; round-trip and packet counts are analytical.*

### 5.4 Cache usage: measured


![Figure 5: resolver cache signature material. Left: measured. Right: analytical.](figures/cache.png)

*Figure 5: resolver cache signature material. Left: measured. Right: analytical.*

| dataset | mode | cached responses | RRSIGs | wire bytes | signature bytes | ladder bytes | Python heap retained |
|---|---|---|---|---|---|---|---|
| small | RSA-2048/SHA-256 (alg 8) | 48 | 118 | 50.29 KB | 30.21 KB | 0 B | 435.68 KB |
| small | ECDSA P-256 (alg 13) | 48 | 118 | 27.44 KB | 7.55 KB | 0 B | 412.87 KB |
| small | Ed25519 (alg 15) | 48 | 118 | 27.41 KB | 7.55 KB | 0 B | 412.85 KB |
| small | SLH-DSA-SHA2-128s without MTL | 48 | 118 | 947.39 KB | 927.01 KB | 0 B | 1.39 MB |
| small | SLH-DSA-SHA2-128s with MTL | 48 | 118 | 36.86 KB | 17.01 KB | 8.02 KB | 484.44 KB |
| medium | RSA-2048/SHA-256 (alg 8) | 74 | 153 | 78.51 KB | 39.17 KB | 0 B | 611.15 KB |
| medium | ECDSA P-256 (alg 13) | 74 | 153 | 48.94 KB | 9.79 KB | 0 B | 581.63 KB |
| medium | Ed25519 (alg 15) | 74 | 153 | 48.91 KB | 9.79 KB | 0 B | 581.61 KB |
| medium | SLH-DSA-SHA2-128s without MTL | 74 | 153 | 1.24 MB | 1.20 MB | 0 B | 1.84 MB |
| medium | SLH-DSA-SHA2-128s with MTL | 74 | 153 | 63.65 KB | 24.53 KB | 8.09 KB | 665.97 KB |
| large | RSA-2048/SHA-256 (alg 8) | 106 | 187 | 82.94 KB | 47.87 KB | 0 B | 776.54 KB |
| large | ECDSA P-256 (alg 13) | 106 | 187 | 46.84 KB | 11.97 KB | 0 B | 740.47 KB |
| large | Ed25519 (alg 15) | 106 | 187 | 46.81 KB | 11.97 KB | 0 B | 740.46 KB |
| large | SLH-DSA-SHA2-128s without MTL | 106 | 187 | 1.50 MB | 1.47 MB | 0 B | 2.28 MB |
| large | SLH-DSA-SHA2-128s with MTL | 106 | 187 | 71.01 KB | 36.17 KB | 8.06 KB | 849.60 KB |

*Table 8: measured. The cached responses are those transmitted in Table 7, parsed from wire and stored in dnspython's `LRUCache`. Heap figures come from tracemalloc.*

| dataset | MTL signer RSS growth while appending | max RSS |
|---|---|---|
| small | 180.22 KB | 8.03 MB |
| medium | 188.42 KB | 8.25 MB |
| large | 212.99 KB | 8.03 MB |

*Table 9: measured signer state of the reference library process (`/proc/self/statm`, page-granular, so growth below a few pages is within measurement resolution).*

### 5.5 Cache usage: analytical estimates

| dataset | mode | RRSIGs | max bytes per signature | ladder bytes (max) | signature material |
|---|---|---|---|---|---|
| small | RSA-2048/SHA-256 (alg 8) | 118 | 256 | 0 B | 30.21 KB |
| small | ECDSA P-256 (alg 13) | 118 | 64 | 0 B | 7.55 KB |
| small | Ed25519 (alg 15) | 118 | 64 | 0 B | 7.55 KB |
| small | SLH-DSA-SHA2-128s without MTL | 118 | 7,856 | 0 B | 927.01 KB |
| small | SLH-DSA-SHA2-128s with MTL | 118 | 157 | 8.12 KB | 26.65 KB |
| medium | RSA-2048/SHA-256 (alg 8) | 153 | 256 | 0 B | 39.17 KB |
| medium | ECDSA P-256 (alg 13) | 153 | 64 | 0 B | 9.79 KB |
| medium | Ed25519 (alg 15) | 153 | 64 | 0 B | 9.79 KB |
| medium | SLH-DSA-SHA2-128s without MTL | 153 | 7,856 | 0 B | 1.20 MB |
| medium | SLH-DSA-SHA2-128s with MTL | 153 | 173 | 8.15 KB | 34.62 KB |
| large | RSA-2048/SHA-256 (alg 8) | 187 | 256 | 0 B | 47.87 KB |
| large | ECDSA P-256 (alg 13) | 187 | 64 | 0 B | 11.97 KB |
| large | Ed25519 (alg 15) | 187 | 64 | 0 B | 11.97 KB |
| large | SLH-DSA-SHA2-128s without MTL | 187 | 7,856 | 0 B | 1.47 MB |
| large | SLH-DSA-SHA2-128s with MTL | 187 | 205 | 8.22 KB | 46.55 KB |

| dataset | node-set hash storage (2N−1)·n + N·n |
|---|---|
| small | 2.14 KB |
| medium | 5.98 KB |
| large | 19.42 KB |

*Table 10: analytical estimates from the draft-harvey section 12 size formulas, for the same RRSIG counts as Table 8. These are estimates, not measurements.*

### 5.6 MTL sizes compared with the draft formulas

| dataset | quantity | kind | bytes |
|---|---|---|---|
| small | condensed_signature | measured_max | 156 |
| small | condensed_signature | analytical_max | 156 |
| small | signed_ladder | measured | 8,024 |
| small | signed_ladder | analytical_max | 8,120 |
| small | rungs | analytical | 4 |
| small | zone_signature_storage_mtl | analytical | 15,140 |
| small | zone_signature_storage_mtl | measured | 14,516 |
| small | zone_signature_storage_direct | analytical | 353,520 |
| small | zone_signature_storage_direct | measured | 353,520 |
| medium | condensed_signature | measured_max | 172 |
| medium | condensed_signature | analytical_max | 172 |
| medium | signed_ladder | measured | 8,088 |
| medium | signed_ladder | analytical_max | 8,152 |
| medium | rungs | analytical | 6 |
| medium | zone_signature_storage_mtl | analytical | 29,652 |
| medium | zone_signature_storage_mtl | measured | 27,828 |
| medium | zone_signature_storage_direct | analytical | 982,000 |
| medium | zone_signature_storage_direct | measured_per_sig_x_n | 982,000 |
| large | condensed_signature | measured_max | 204 |
| large | condensed_signature | analytical_max | 204 |
| large | signed_ladder | measured | 8,056 |
| large | signed_ladder | analytical_max | 8,216 |
| large | rungs | analytical | 5 |
| large | zone_signature_storage_mtl | analytical | 90,836 |
| large | zone_signature_storage_mtl | measured | 87,092 |
| large | zone_signature_storage_direct | analytical | 3,181,680 |
| large | zone_signature_storage_direct | measured_per_sig_x_n | 3,181,680 |

*Table 11: measured MTL sizes next to the section 12 maxima.*

### 5.7 Evolving zone: updates and cached ladders

MTL is built for a series that keeps growing, so a single signed zone is its best case. Here each series starts from the full dataset and runs rounds in which **k** RRsets change (k = 1, 10; 4, 4 rounds). Every change appends a new leaf, old leaves never leave the series, and each round signs one new ladder. The baseline signs every changed RRset with plain SLH-DSA. All figures in Tables 12 to 15 are measured with the reference library; an RRset 'change' is modelled as the same-size message with its last 8 bytes replaced, chosen uniformly at random, so the cost of an update is real but its content is synthetic.

#### Cost of one update round

| dataset | k | MTL: append k leaves + 1 ladder signature | direct: k signatures | direct ÷ MTL (per-trial, interval) | resolver verifies, MTL (1 ladder) | resolver verifies, direct (k signatures) |
|---|---|---|---|---|---|---|
| small | 1 | 832.37 ms [745.66 ms–834.21 ms] | 835.05 ms | 1.01× [1.00×, 1.05×] | 763.1 µs | 776.0 µs |
| small | 10 | 828.37 ms [748.29 ms–882.43 ms] | 8.31 s | 10.0× [9.4×, 10.1×] | 759.3 µs | 7.83 ms |
| medium | 1 | 748.03 ms [746.24 ms–833.65 ms] | 835.05 ms | 1.05× [1.01×, 1.12×] | 763.5 µs | 776.0 µs |
| medium | 10 | 746.77 ms [745.72 ms–836.18 ms] | 8.31 s | 10.2× [10.0×, 11.1×] | 739.9 µs | 7.83 ms |
| large | 1 | 825.66 ms [750.52 ms–830.55 ms] | 835.05 ms | 1.01× [1.00×, 1.05×] | 748.7 µs | 776.0 µs |
| large | 10 | 748.69 ms [741.78 ms–832.68 ms] | 8.31 s | 10.1× [10.0×, 11.2×] | 757.5 µs | 7.83 ms |

*Table 12: cost of one update round, median over rounds and trials. 'Resolver verifies' is the work to take in the update: one ladder signature against k signatures.*


![Figure 6: cost of one update round (left) and how long a cached ladder keeps covering the current answers (right)](figures/evolution.png)

*Figure 6: cost of one update round (left) and how long a cached ladder keeps covering the current answers (right)*

**Reading.** MTL is not faster at k = 1: it still signs one ladder per round, the same SLH-DSA signature direct signing needs for one changed RRset. As k grows, direct signing pays k signatures per round and MTL still pays one, so the advantage grows roughly with k. At small k, MTL's gain is in bytes and in verification, not in signing time.

#### How long a cached ladder stays useful

| dataset | k | ladder 1 round(s) old | ladder 2 round(s) old |
|---|---|---|---|
| small | 1 | 97.8% | 95.6% |
| small | 10 | 77.8% | 60.7% |
| medium | 1 | 99.2% | 98.4% |
| medium | 10 | 92.0% | 85.1% |
| large | 1 | 99.8% | 99.5% |
| large | 10 | 97.5% | 95.2% |

*Table 13: share of the current zone's RRsets whose condensed signature verifies against the cached ladder of that age (measured by the library, every RRset, every round in which that age exists). A leaf appended after the cached ladder was signed has no rung in it and is rejected; every other RRset verifies. The rejected share is therefore the share of RRsets changed since that ladder, and it is the share of answers that need a full signature (about 8 KB over TCP) from a resolver that does not refresh.*

#### Growth of the series

| dataset | k | rounds | leaves | rungs at the end | signed ladder | largest condensed signature | signer RSS |
|---|---|---|---|---|---|---|---|
| small | 1 | 4 | 45 → 49 | 3 | 8.02 KB → 7.99 KB | 156 B → 156 B | 7.94 MB |
| small | 10 | 4 | 45 → 85 | 4 | 8.02 KB → 8.02 KB | 156 B → 172 B | 8.18 MB |
| medium | 1 | 4 | 125 → 129 | 2 | 8.09 KB → 7.96 KB | 172 B → 188 B | 8.10 MB |
| medium | 10 | 4 | 125 → 165 | 4 | 8.09 KB → 8.02 KB | 172 B → 188 B | 8.37 MB |
| large | 1 | 4 | 405 → 409 | 5 | 8.06 KB → 8.06 KB | 204 B → 204 B | 8.31 MB |
| large | 10 | 4 | 405 → 445 | 7 | 8.06 KB → 8.12 KB | 204 B → 204 B | 8.56 MB |

*Table 14: the series only grows. Rungs follow the binary breakdown of the leaf count (11 leaves = 8 + 2 + 1), so the ladder size moves up and down while the leaf count rises; the condensed signature grows by 16 bytes whenever the leaf count reaches a power of two.*

#### Published signatures when the ladder changes

| dataset | k | lowest share still valid | rounds with any signature invalidated |
|---|---|---|---|
| small | 1 | 72.7% | 4 |
| small | 10 | 0.0% | 4 |
| medium | 1 | 0.0% | 4 |
| medium | 10 | 0.0% | 4 |
| large | 1 | 98.3% | 4 |
| large | 10 | 91.1% | 4 |

*Table 15: condensed signatures issued when a leaf was created, verified against the newest ladder. When rungs merge as the series grows, the path of an earlier signature no longer ends at a rung of the new ladder: it still verifies against the older ladder, but the signature has to be reissued for resolvers that hold the new one. At a power-of-two leaf count every earlier signature is affected.*

#### Signature bytes per answer, large zone (derived)

| k | ladder 1 old | ladder 2 old |
|---|---|---|
| 1 | 215 B | 235 B |
| 10 | 398 B | 589 B |

*Table 16: derived, not measured. Measured condensed size, plus the measured uncovered share times a full signature (condensed + ladder). It is an upper bound: it assumes every uncovered answer fetches a full signature, while a real resolver refreshes its ladder once and then covers the rest. Compare with 7,856 B for plain SLH-DSA.*

## 6. Discussion

- **Signing.** Direct SLH-DSA performs one expensive hash-based signature per RRset. MTL performs one per zone, for the ladder, plus hashing per RRset. The gap therefore grows with zone size.
- **Verification.** With a cached ladder, MTL checks only an authentication path for each RRset. The SLH-DSA verification is paid once per ladder.
- **Transmitted bytes.** Direct SLH-DSA responses never fit 1232 bytes, because one signature is 7,856 bytes. MTL condensed signatures grow with log2 of the number of RRsets in the series. The MTL responses that still truncate at 1232 bytes are:
  - small zone (condensed signature 156 B): below 100%: large 0%.
  - medium zone (condensed signature 172 B): below 100%: large 0%.
  - large zone (condensed signature 204 B): below 100%: large 0%, nxdomain 14%.
  - Large TXT answers exceed the limit even with classical signatures. An NXDOMAIN carries up to four RRSIGs (SOA and up to three NSEC3), so negative answers outgrow UDP first as the zone grows. Compact denial of existence, or splitting a zone into several MTL series, would reduce this; both are left as future work.
- **Cost of MTL.** It moves cost to first contact, where one full signature (the ladder) is fetched over TCP. A ladder covers a zone version: re-signing after a change produces a new ladder that validators must fetch again.

## 7. Limitations

- **Timing scope.** CPU timings are for one pinned core on the hardware recorded above, with the pinned library builds. They are not general performance claims. 
- **Transport model.** Transmitted bytes come from a message-level model, not a resolver or server. Real resolvers differ in caching, retries and EDNS behaviour.
- **Placeholder code points.** The algorithm numbers and the EDNS option code are not IANA-assigned.
- **Fixture coverage.** The reference library's bundled known-answer vectors cover the scheme named in Appendix C. SLH-DSA-SHA2-128s-MTL is validated by the tool round trip and the harness gates.
- **Compiler flags.** The MTL library is compiled with optimisation (see methodology). The as-shipped debug build is available as an ablation.
- **No security claims.** This work makes no security claims and no new cryptography is introduced.

## 8. Conclusion

On equivalent DNSSEC workloads and the same underlying PQC algorithm, MTL mode in the reference implementation replaces per-RRset SLH-DSA signatures with short authentication paths. In this environment it reduced zone signing time, warm verification time and transmitted bytes. In the large zone, the share of responses that fit a 1232-byte UDP buffer rose from 0% to 78%. The costs are one full-signature fetch per validator for each zone version, and negative answers that carry several condensed signatures grow with zone size. All figures are measured on the pinned environment, except those explicitly marked as extrapolated or analytical, and are reproducible with the commands below.

## 9. Reproducing this report

```bash
scripts/run_benchmark.sh preflight                     # build the image from the stack profile, go/no-go gate
scripts/run_benchmark.sh configs/scenarios.yaml        # full run -> results/runs/<id>/
python -m cipherops.runner report --run results/runs/20261030T074948Z-quick-demo
```

### Demonstration pseudocode

```python
# Signer: one MTL series per zone, built with the reference library
key = mtllib_key_new("SLH-DSA-SHA2-128s-MTL-SHA2-128")
for rrset in canonical_order(zone):                      # includes the NSEC3 chain
    data = rrsig_rdata_without_signature(rrset) + canonical_wire(rrset)  # RFC 4034 3.1.8.1
    leaf[rrset] = mtllib_sign_append(key, data)          # hashing only
ladder = mtllib_sign_get_signed_ladder(key)              # one SLH-DSA-SHA2-128s signature
for rrset in zone:
    rrsig[rrset].signature = MTL_TYPE_CONDENSED + mtllib_sign_get_condensed_sig(key, leaf[rrset])

# Validator
if ladder_cache is empty:                                # first contact only
    full = query(qname, qtype, edns=[MTL_MODE_FULL], over=TCP)
    mtllib_verify_signed_ladder(pubkey, full.ladder)     # one SLH-DSA verification
    ladder_cache = full.ladder
mtllib_verify(pubkey, data, condensed_signature, ladder_cache)   # hash path check
```

## Appendix A. Configuration

```yaml
run_name: quick-demo
seed: 20261005
trials: 3
warmup_trials: 1
modes:
- slh-dsa-mtl
- slh-dsa
- ed25519
- ecdsa-p256
- rsa-2048
control: ed25519
datasets:
- name: small
  n_names: 20
- name: medium
  n_names: 60
- name: large
  n_names: 200
full_verify_sample: 16
direct_sign_limit:
  small: null
  medium: 60
  large: 100
evolution:
  k:
  - 1
  - 10
  rounds:
  - 4
  - 4
  ages:
  - 0
  - 1
  - 2
wire:
  nx_sample: 50
  workload:
    n_queries: 300
    nx_fraction: 0.1
    zipf_s: 1.1
```

## Appendix B. Environment

```json
{
  "captured_at_utc": "2026-10-30T07:49:48.665652+00:00",
  "git_sha": "90ecbc1f20cc3139d070ac97d943f05ea97ec50e",
  "host_image_id": "sha256:d05eeb6684c037f5c48afe348a1fe1cacb7c580e4810e2ed9ba9a71643253524",
  "stack": "latest",
  "hardware": {
    "cpu_model": "Intel(R) Core(TM) Ultra 7 165H",
    "logical_cpus_visible": 22,
    "cpu_affinity": [
      2
    ],
    "cpuset_requested": "2",
    "scaling_governor": "powersave",
    "mem_total": "MemTotal:       65248288 kB"
  },
  "software": {
    "os_release": [
      "NAME=\"Fedora Linux\"",
      "VERSION=\"42 (Container Image)\"",
      "RELEASE_TYPE=stable",
      "ID=fedora"
    ],
    "kernel": "7.2.11-100.fc43.x86_64",
    "python": "3.13.13",
    "gcc": "gcc (GCC) 15.2.1 20260123 (Red Hat 15.2.1-7)",
    "openssl": "OpenSSL 3.6.0 1 Oct 2025 (Library: OpenSSL 3.6.0 1 Oct 2025)",
    "openssl_tag": "openssl-3.6.0",
    "liboqs_tag": "0.16.0",
    "mtl_reference_commit": "7cef0191da55048111d252a567b7614672424ed3",
    "mtl_reference_cflags": "-fPIC -Wall -Wextra -O2",
    "harness_sha256": "533ab957c8eca39fab22583f1ea43929d14709b05d50e595c396bb5668f6cfd5",
    "python_packages": {
      "dnspython": "2.8.0",
      "numpy": "2.5.2",
      "pandas": "3.0.6",
      "pyarrow": "25.0.1",
      "PyYAML": "6.0.3",
      "cryptography": "49.0.0",
      "matplotlib": "3.11.2",
      "Markdown": "3.11"
    }
  },
  "timer": {
    "clock": "CLOCK_MONOTONIC_RAW",
    "clock_getres_ns": 1,
    "smallest_observed_step_ns": 25,
    "empty_region": {
      "samples": 200000,
      "min_ns": 24,
      "median_ns": 29,
      "p99_ns": 38,
      "max_ns": 44847,
      "mean_ns": 31.05,
      "zero_fraction": 0.0
    },
    "operations": {
      "ed25519_verify": {
        "calls": 1000,
        "batches": 30,
        "per_call_median_ns": 167246.0,
        "per_call_mean_ns": 168687.871,
        "per_call_p95_ns": 172975.05,
        "batch_per_call_median_ns": 169334.7085,
        "batch_per_call_min_ns": 168225.321,
        "batch_per_call_max_ns": 171690.607,
        "per_call_vs_batch_pct": -1.2334792544908226,
        "timer_share_of_operation": 0.0001712584517190107
      },
      "mtl_condensed_verify": {
        "calls": 1000,
        "batches": 30,
        "per_call_median_ns": 1152.0,
        "per_call_mean_ns": 1160.461,
        "per_call_p95_ns": 1200.0,
        "batch_per_call_median_ns": 1148.769,
        "batch_per_call_min_ns": 1139.839,
        "batch_per_call_max_ns": 1184.349,
        "per_call_vs_batch_pct": 0.2812575896459597,
        "timer_share_of_operation": 0.02524441380294907
      }
    },
    "max_timer_share": 0.05,
    "per_call_timing_reliable": true
  }
}
```

## Appendix C. Go/no-go gate

| check | ok | critical | detail |
|---|---|---|---|
| reference_library_installed | True | True | ok |
| reference_unit_tests_and_vectors | True | True | exit=0, 89 tests passed, 0 failed |
| reference_fixture_scheme | True | False | bundled known-answer vectors cover ML-DSA-44-MTL-SHAKE-128; SLH-DSA-SHA2-128s-MTL-SHA2-128 is validated by the tool round trip |
| reference_tools_roundtrip | True | True | 16 messages, condensed+full verify failures=[], tampered rejected=True |
| harness_smoke_slh-dsa-mtl | True | True | exit=0 failures={'ladder': 0, 'verify_condensed': 0, 'verify_full': 0} tamper={'message_rejected': True, 'signature_rejected': True, 'ladder_rejected': True, 'c |
| harness_smoke_slh-dsa | True | True | exit=0 failures={'verify': 0} tamper={'message_rejected': True, 'signature_rejected': True, 'cross_message_rejected': True, 'truncated_signature_rejected': True |
| harness_smoke_ed25519 | True | False | exit=0 failures={'verify': 0, 'verify_wire': 0} tamper={'message_rejected': True, 'signature_rejected': True, 'cross_message_rejected': True, 'truncated_signatu |
| harness_smoke_ecdsa-p256 | True | False | exit=0 failures={'verify': 0, 'verify_wire': 0} tamper={'message_rejected': True, 'signature_rejected': True, 'cross_message_rejected': True, 'truncated_signatu |
| harness_smoke_rsa-2048 | True | False | exit=0 failures={'verify': 0, 'verify_wire': 0} tamper={'message_rejected': True, 'signature_rejected': True, 'cross_message_rejected': True, 'truncated_signatu |
| mtl_artifacts_verified_by_reference_tool | True | True | mtlverify accepted 8/8 harness signatures, tampered message rejected=True; note: the reference library does not authenticate the first 2 byte(s) of a condensed  |
| slh_dsa_artifacts_verified_by_openssl | True | True | OpenSSL accepted 8/8 liboqs SLH-DSA-SHA2-128s signatures, tampered message rejected=True (interop check, not a NIST KAT) |

## References

1. draft-harvey-cfrg-mtl-mode-09, *Merkle Tree Ladder (MTL) Mode Signatures*.
2. draft-fregly-dnsop-slh-dsa-mtl-dnssec, *SLH-DSA-MTL in DNSSEC*.
3. FIPS 205, *Stateless Hash-Based Digital Signature Standard*.
4. RFC 4033, RFC 4034, RFC 4035 (DNSSEC); RFC 5155 (NSEC3); RFC 9276 (NSEC3 guidance); RFC 6605 (ECDSA); RFC 8080 (Ed25519).
5. Verisign MTL reference library, https://github.com/verisign/MTL.
6. Open Quantum Safe liboqs, https://github.com/open-quantum-safe/liboqs.

