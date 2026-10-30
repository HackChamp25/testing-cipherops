# Readout

Five slides' worth. Full deck: [revised 30 Oct 2026](presentation/A3-PS036-TC161_2026-10-30.pdf).

## 1. Problem

DNSSEC answers must fit one unfragmented UDP packet (1,232 bytes by default). One SLH-DSA-SHA2-128s signature is 7,856
bytes, so a signed answer is truncated and retried over TCP, or fragmented and often dropped. Signing is slow too:
about 0.6 s per signature on one core. MTL mode signs a zone once and gives each record a short authentication path.
PS-036 asks: what does that change, compared with the same algorithm without MTL?

## 2. What we did

- Measured `slh-dsa-mtl` against `slh-dsa`, with Ed25519, ECDSA P-256 and RSA-2048 as references, on 50, 500 and 5,000
  names (quick run: 20, 60 and 200), using the Verisign MTL reference library unmodified.
- Two paths: an offline harness (one pinned core, no network) and a simulated lab (NSD and a validating Unbound in
  Docker, with packet capture). One stack profile pins both.
- Went beyond the minimum: zone updates, an A/A noise control, a go/no-go gate and intervals with stated coverage.

## 3. Results

Quoted from the generated report of the frozen run
[`quick-demo-20261030T074948Z`](results/quick-demo-20261030T074948Z/report.md); where and how it ran:
[results/](results/README.md). **This is a 3-trial quick demonstration on small zones (45 / 125 / 405 RRsets), not the
full run.**

- **Signing, small zone (45 RRsets).** MTL 835.42 ms; direct SLH-DSA 36.55 s. MTL was 43.8× faster (median of per-trial
  ratios, interval 38.6×–44.8×).
- **Signing, large zone (405 RRsets).** MTL 752.10 ms; direct SLH-DSA about 318 s, **extrapolated** from 100 sampled
  RRsets.
- **Verification, small zone, warm.** MTL 1.01 ms for every RRSIG in the zone; direct SLH-DSA 37.60 ms.
- **Response size, large zone.** At a 1,232-byte EDNS buffer, 78% of MTL responses fit in UDP, against 0% for direct
  SLH-DSA.
- **Transmitted bytes, large zone.** 88.89 KB with MTL against 1.52 MB with direct SLH-DSA; 106 truncation and TCP-retry
  events became 32, plus 1 full-signature fetch.

The trade-offs are measured too (resolver without the ladder, zone updates, cache); see the report and the dashboard's
**Compare** tile.

## 4. Issues found

Details, evidence and the interop matrix: [feedback.md](feedback.md).

- On the newer stack the lab's Unbound answers SERVFAIL for plain SLH-DSA although the signed zone verifies elsewhere.
- On the older stack, a parent zone with separate KSK and ZSK fails to validate a child DS signed with a condensed MTL
  signature.
- The reference library does not authenticate the first two bytes of a condensed signature and trusts a ladder passed in
  as pre-verified.
- Cold starts show several full-signature fetches toward the root (an observation, not a proven defect).

None is filed upstream yet.

## 5. Next steps

1. Run the full benchmark on a fixed machine and freeze it here.
2. File the findings with the Verisign repositories.
3. Measure ML-DSA-MTL, which the newest IETF drafts centre on, and the always-full encoding of draft-kaizer.
4. Re-run on a resolver build that validates plain SLH-DSA on the newer stack, so one stack serves both paths.
