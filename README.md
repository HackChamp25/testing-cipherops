<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/media/cipherops-logo-dark.png">
    <img src="docs/media/cipherops-logo-light.png" alt="CipherOps" width="480">
  </picture>

  # CipherOps

  **PQC DNSSEC MTL benchmark using a reference implementation**

  AIORI Hackathon 3 · PS-036 · Team **A3-PS036-TC161**

  <p>
    <a href="https://codespaces.new/aiori-hackathon/A3-PS036-TC161"><img alt="Open in GitHub Codespaces" src="https://github.com/codespaces/badge.svg"></a>
    <a href="https://portal.aiori.in/aiori-3/hackathon-guideline/"><img alt="Problem statement PS-036" src="https://img.shields.io/static/v1?label=problem&message=PS-036&color=1E90FF&labelColor=0B1C2C&style=for-the-badge"></a>
    <a href="https://youtu.be/FaVfeO5WTV8"><img alt="Project video" src="https://img.shields.io/static/v1?label=video&message=YouTube&color=3A7BD5&labelColor=0B1C2C&style=for-the-badge&logo=youtube&logoColor=white"></a>
  </p>
</div>

Post-quantum DNSSEC signatures are large, so signed answers stop fitting in one UDP packet.
**Merkle Tree Ladder (MTL) mode** signs a zone once and gives each record a short proof instead.
CipherOps measures what that changes, against classical DNSSEC and against plain SLH-DSA, using the
[Verisign MTL](https://github.com/verisign/MTL) reference stack unmodified. It adds no cryptography of its own.

> **New to DNSSEC, post-quantum signatures or MTL?** Start with [Learn](docs/learn/README.md): two short animated
> walkthroughs and where the IETF drafts stand.

## For the panel

| | |
| :--- | :--- |
| **Presentation** | [`A3-PS036-TC161.pptx.pdf`](A3-PS036-TC161.pptx.pdf) |
| **Project video** | [YouTube](https://youtu.be/FaVfeO5WTV8) |
| **Try it** | [Codespaces](docs/codespaces.md) or [locally](docs/getting-started.md) |
| **How we measure** | [Methodology](docs/methodology.md) · [Architecture](docs/architecture.md) |

Numbers live in each run's `report.html` under `results/runs/`, not in the documentation, so they cannot go stale.

## What it measures

| Mode | Algorithm | Library |
| --- | --- | --- |
| `slh-dsa-mtl` | SLH-DSA-SHA2-128s in MTL mode | [Verisign MTL](https://github.com/verisign/MTL) |
| `slh-dsa` | SLH-DSA-SHA2-128s directly | liboqs |
| `ed25519`, `ecdsa-p256`, `rsa-2048` | Classical DNSSEC | OpenSSL |

On zones of 50, 500 and 5,000 names: signing time, verification time, signature and response size, truncation, cache
use, and the cost of updating a zone. Two paths answer different questions: an **offline harness** (one pinned core,
no network) and a **simulated lab** (root, TLD and leaf NSD servers behind a validating Unbound, with packet capture).

![CipherOps architecture](docs/architecture-slide1.png)

## Quick start

You need Docker, git and Python 3.11+, or just a browser with [Codespaces](docs/codespaces.md).

```bash
git clone https://github.com/aiori-hackathon/A3-PS036-TC161.git && cd A3-PS036-TC161
pip install -r requirements-dashboard.txt
streamlit run dashboard/live_lab/app.py          # the dashboard
bash scripts/run_benchmark.sh configs/quick.yaml  # or: a short offline run from the shell
```

The first image build compiles OpenSSL, liboqs and MTL from source and takes a while; later runs reuse it. Full
instructions, Windows commands, tests and troubleshooting: [Getting started](docs/getting-started.md).

## The dashboard

| Tile | Use |
| --- | --- |
| **Setup** | build the images, sign the zones, start the lab |
| **Live** | send queries, flush the cache, inspect the captured packets |
| **Benchmark** | *Offline (harness)* or *Simulated (Verisign stack)*, run from the browser |
| **Compare** | algorithms side by side, run against run, and the cost of zone updates |
| **Learn** | why DNSSEC needs MTL, and an operator walkthrough |
| **Reset** | clear only what you choose |

Details: [dashboard guide](dashboard/live_lab/README.md).

## Scope, honestly

Empirical timings and wire sizes on pinned stacks; not a security proof and not a production DNSSEC product. Offline
and simulated results use different library versions and are never mixed; simulated timings are indicative, not
core-pinned; the MTL drafts are not RFCs yet. Full list, software stacks and PS-036 coverage:
[Scope and limits](docs/scope-and-limits.md).

## Documentation

The full index is [docs/README.md](docs/README.md).

| | |
| --- | --- |
| **Use** | [Getting started](docs/getting-started.md) · [Codespaces](docs/codespaces.md) · [Dashboard guide](dashboard/live_lab/README.md) |
| **Understand** | [Learn](docs/learn/README.md) · [Scope and limits](docs/scope-and-limits.md) · [Design decisions](docs/design-decisions.md) |
| **Check** | [Methodology](docs/methodology.md) · [Architecture](docs/architecture.md) · [End-to-end flow](docs/end-to-end-flow.md) · [Outputs reference](docs/outputs-reference.md) |

## Team and license

**A3-PS036-TC161**: Akash Joshi · Anitha · Induradhakrishnan. MIT, see [LICENSE](LICENSE). Verisign MTL, liboqs,
OpenSSL and NSD keep their own licences at build time.
