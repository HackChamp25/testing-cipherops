<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/media/cipherops-logo-dark.png">
    <img src="docs/media/cipherops-logo-light.png" alt="CipherOps" width="480">
  </picture>

  # CipherOps

  **PQC DNSSEC MTL benchmark using a reference implementation**

  AIORI Hackathon 3 · PS-036 · Team **A3-PS036-TC161**

  <p>
    <a href="https://portal.aiori.in/aiori-3/hackathon-guideline/"><img alt="AIORI 3 Hackathon" src="https://img.shields.io/static/v1?label=AIORI%203&message=Hackathon&color=1E90FF&labelColor=0B1C2C&style=for-the-badge"></a>
    <a href="https://portal.aiori.in/aiori-3/hackathon-guideline/"><img alt="Problem statement PS-036" src="https://img.shields.io/static/v1?label=problem&message=PS-036&color=1E90FF&labelColor=0B1C2C&style=for-the-badge"></a>
    <a href="https://youtu.be/FaVfeO5WTV8"><img alt="Project video" src="https://img.shields.io/static/v1?label=video&message=YouTube&color=3A7BD5&labelColor=0B1C2C&style=for-the-badge&logo=youtube&logoColor=white"></a>
  </p>
</div>

Post-quantum DNSSEC signatures are large; answers stop fitting in one UDP packet.
**Merkle Tree Ladder (MTL) mode** signs a zone once and attaches a short proof per record.
Cipherops measures what that changes — against classical DNSSEC and against plain SLH-DSA —
using the [Verisign MTL](https://github.com/verisign/MTL) reference stack, unmodified.

> **New to DNSSEC, post-quantum signatures or MTL?** Start with [Learn](docs/learn/README.md): two short animated
> walkthroughs (why DNSSEC needs MTL, and what an operator does differently) and where the IETF drafts stand.
> Both are in the dashboard's **Learn** tile.

## For the panel

| | |
| :--- | :--- |
| **Presentation** | [`A3-PS036-TC161.pptx.pdf`](A3-PS036-TC161.pptx.pdf) |
| **Project video** | [YouTube](https://youtu.be/FaVfeO5WTV8) |
| **Dashboard (browser)** | [Quick start below](#dashboard-browser) — benchmark (offline or simulated), live queries with packet sequences, compare, learn |
| **How we measure** | [Methodology](docs/methodology.md) · [Architecture](docs/architecture.md) · [Design decisions](docs/design-decisions.md) |
| **Learn** | [Why DNSSEC needs MTL](docs/learn/README.md) · [IETF draft status](docs/learn/README.md#where-the-ietf-stands) |

Numbers live in each run’s `report.html` under `results/runs/` — not duplicated here, so this page stays current when you re-run.

---

## What you get

| Mode | Algorithm | Library |
| ----------------------------------- | ----------------------------- | ------------------------------------------------------------------------ |
| `slh-dsa-mtl` | SLH-DSA-SHA2-128s in MTL mode | [Verisign MTL](https://github.com/verisign/MTL) |
| `slh-dsa` | SLH-DSA-SHA2-128s directly | liboqs |
| `ed25519`, `ecdsa-p256`, `rsa-2048` | Classical DNSSEC | OpenSSL |

Zone sizes: 50, 500 and 5,000 names (quick run: 20, 60 and 200). Measured: signing time, verification time, signature
and response size, truncation, cache use, and the cost of updating a zone.

Fedora 42 base, OpenSSL 3.6.0. Versions live in one file per **stack profile**
([`ecosystem/stacks/`](ecosystem/stacks)); the offline image and the lab images are both built from it:

| Profile | MTL / liboqs | Signature primitive | Used for |
| --- | --- | --- | --- |
| `latest` | `7cef019` / 0.16.0 | FIPS 205 SLH-DSA, one library call for MTL and the plain baseline | **offline harness** (default) |
| `draft06` | 1.2.0 `93b05ef` / 0.14.0 | SPHINCS+-SHA2-128s-simple, the pre-standard form (same sizes) | **simulated lab** (default) |

Why two profiles: on `latest` the lab's Unbound answers SERVFAIL for plain SLH-DSA, so the MTL-versus-plain comparison
in the lab runs on `draft06`; the offline harness needs `latest` for FIPS 205 names. Evidence and alternatives:
[design decisions](docs/design-decisions.md).

![Cipherops architecture](docs/architecture-slide1.png)

### Scope (honest)

- Empirical timings and wire sizes on pinned stacks — not a security proof or a production DNSSEC product.
- Offline harness (zone sign / verify / model) plus an optional simulated hierarchy (NSD + Unbound) with packet capture.
- Absolute milliseconds depend on the host; fair comparisons share the same image and configs.
- **Profiles are not interchangeable.** Offline results are FIPS 205 SLH-DSA; simulated results on `draft06` are the pre-standard form. Each run records its profile.
- **Simulated timings are indicative.** Containers are not pinned to cores; byte counts and relative comparisons are more reliable than absolute milliseconds.
- **Fixtures.** The reference library's known-answer vectors cover ML-DSA, not SLH-DSA. SLH-DSA is checked by round trips, negative cases and agreement between independent implementations — an interoperability check, not a NIST known-answer test ([methodology §3](docs/methodology.md#3-gono-go-gate)).
- Few trials give wide intervals: the full run uses 10 (the interval of the median covers 98%), the quick run 3 (75%).
- DNSSEC algorithm numbers and the `mtl-mode-full` EDNS option are lab placeholders, not IANA assignments. The MTL drafts are individual Internet-Drafts, not RFCs ([status](docs/learn/README.md#where-the-ietf-stands)).

### PS-036 coverage

| Requirement | Where it is met |
| --- | --- |
| One supported PQC algorithm, one MTL reference implementation | SLH-DSA-SHA2-128s; Verisign MTL pinned by commit |
| Three dataset sizes, with and without MTL | 50 / 500 / 5,000 names; `slh-dsa-mtl` vs `slh-dsa`, plus classical references |
| Repeated trials, pinned environment | pinned image, dedicated core, seeded order, discarded warm-up (offline); the simulated lab is not core-pinned |
| Signing time, verification time, transmitted bytes | `trials.csv`, `responses.csv`, `workload.csv`; simulated-lab captures |
| MTL on a changing zone (beyond the minimum) | `evolution.csv` and the dashboard's **Zone updates** view; synthetic same-size updates |
| Parameters recorded; cache measured vs analytical kept apart | `config.yaml`, `environment.json`, `suite.json`; `cache.csv` has a `kind` column |
| Defer if implementation or fixtures are missing | go/no-go gate (`preflight`) blocks the run |
| No new cryptography, resolver or deployment | the harness only calls libraries; the lab uses stock servers |

---

## Requirements

- **Docker** (Desktop or Engine) with Compose v2 — about 3 CPUs / 6 GB RAM (the harness is pinned to core 2; pass another core as the script's second argument)
- **git**
- **Python 3.11+** — dashboard and host tests only

```bash
git clone https://github.com/aiori-hackathon/A3-PS036-TC161.git
cd A3-PS036-TC161
```

First image build compiles OpenSSL, liboqs, and MTL from source (several minutes up to tens of minutes). Later runs reuse it.

---

## Dashboard (browser)

One Streamlit app: build the lab, query it, benchmark, compare, learn.

```bash
pip install -r requirements-dashboard.txt
streamlit run dashboard/live_lab/app.py
```

| Tile | Use |
| --- | --- |
| **Setup** | step 1 build or pull the images; step 2 choose zone size and algorithms, then **Sign zones**; step 3 **Start** the lab |
| **Live** | send queries or `dig`, switch algorithm, flush the cache, capture packets, view the packet sequence |
| **Benchmark** | two modes. *Offline (harness)*: a quick check or the full run on a dedicated core, started from the dashboard, no Setup needed. *Simulated (Verisign stack)*: the three-size benchmark on the Docker lab with repeated runs; needs only the built images |
| **Compare** | *Algorithms side by side* and *Run against run* for offline and simulated results (never mixed), and *Zone updates*: re-sign cost, response size and stale-cache impact when a zone changes |
| **Learn** | why DNSSEC needs MTL, and the operator walkthrough |
| **Reset** | remove sessions, captures, runs or signed zones |

Hover the ⓘ icons for what each setting and measurement means. Needs Docker. Start with **Small** zone size for Live, and use
the **`draft06`** image version (the default) for the MTL-versus-plain comparison. Walkthrough:
[`dashboard/live_lab/README.md`](dashboard/live_lab/README.md).

---

## Offline benchmark

Run it from the dashboard (**Benchmark → Offline**) or from a shell:

### 1. Preflight (go / no-go)

```powershell
# Windows
powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmark.ps1 -Command preflight
```

```bash
# macOS / Linux
bash scripts/run_benchmark.sh preflight
```

If the gate fails, no numbers are produced and the run exits with `NO-GO`.

### 2. Run

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmark.ps1 -Config configs/quick.yaml   # short demo
powershell -ExecutionPolicy Bypass -File .\scripts\run_benchmark.ps1                              # full, about 5 h
```

```bash
bash scripts/run_benchmark.sh configs/quick.yaml
bash scripts/run_benchmark.sh                              # full: 10 trials, about 5 h
```

### 3. Live validation (optional)

Replay lookups against NSD over LAN / WAN / lossy profiles; captures land in the run folder.

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\run_live.ps1 -Run <run-folder>
```

```bash
bash scripts/run_live.sh <run-folder> lan 1232 1      # one profile, one UDP size, one repeat
```

### 4. Results

Open `report.html` in `results/runs/<id>/`, or use the dashboard: **Benchmark → Offline → Results**, then **Compare**.

---

## Output

Each run writes under `results/runs/<id>/` — `report.html`, CSVs, figures, `environment.json`, and (live mode) `pcap/`. A simulated-lab benchmark writes `ecosystem/results/suites/<id>/` with `suite.json` and its own `report.html`. Column-level detail: [Outputs reference](docs/outputs-reference.md).

---

## Configuration

`configs/scenarios.yaml` is the full matrix; `configs/quick.yaml` is the short demo. Knobs: trials, modes, zone sizes, wire workload, seed. See comments in those files. Pick a stack with `CIPHEROPS_STACK=<profile>` (default `latest` for the harness).

---

## Tests

```bash
pip install -r requirements-dashboard.txt
PYTHONPATH=src python3 -m pytest tests -m "not harness"     # host tests, no Docker needed
```

Harness gates need the compiled library, so they run in the image:

```bash
docker run --rm --network none cipherops-bench:latest \
  "python3 -m pytest tests/test_harness.py tests/test_crosscheck.py -q"
```

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `Permission denied` under `ecosystem/work` or `results` | Docker creates files as root on Linux. The dashboard's Reset removes them; by hand use `sudo rm -rf`. |
| **Sign zones** or Start disabled in Setup | the images for the chosen version are not built yet (step 1) |
| Every query to `slh-dsa` returns SERVFAIL on `latest` | known limitation of that stack; use `draft06` |
| `cpuset` error starting the harness container | the host has fewer than 3 cores; pass another core as the script's second argument |
| Buttons greyed out or "busy" | an offline or simulated benchmark, image build or signing job is running; wait or cancel it |
| Image build seems idle | it runs in the background; open Setup to see the log, or Cancel build |

---

## Repository layout

```
configs/        run settings
docker/         pinned image and compose
harness/        mtlbench.c linked to reference libs
src/cipherops/  offline runner, report, live validation
ecosystem/      multi-zone lab (NSD / Unbound / MTL signing), stack pins
dashboard/      Streamlit app (dashboard/app.py launches live_lab/app.py)
scripts/        Windows / Unix entry points
docs/           methodology, architecture, learn (explainers), brand (docs/media)
tests/          gates and unit tests
```

## Documentation

- [Learn](docs/learn/README.md) — background, interactive walkthroughs, IETF draft status
- [Design decisions](docs/design-decisions.md)
- [Methodology](docs/methodology.md)
- [Architecture](docs/architecture.md) · [End-to-end flow](docs/end-to-end-flow.md)
- [Outputs reference](docs/outputs-reference.md)
- [Dashboard guide](dashboard/live_lab/README.md)
- [IETF draft notes](ecosystem/drafts/README.md)

## Team

**A3-PS036-TC161** — Akash Joshi · Anitha · Induradhakrishnan

## License

MIT — see [LICENSE](LICENSE). Verisign MTL, liboqs, OpenSSL, and NSD keep their own licences at build time.
