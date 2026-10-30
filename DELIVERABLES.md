# Deliverables

The single place that says what this team is submitting and where each item lives. The README links here, so this file
is the source of truth for the PS-036 requirements.

## AIORI Hackathon 3 deliverables

What the [hackathon guideline](https://portal.aiori.in/aiori-3/hackathon-guideline/) asks for, and where each is here.

| Deliverable | Where | State |
| --- | --- | --- |
| **Presentation** (PDF) | [revised 30 Oct 2026](hackathon/presentation/A3-PS036-TC161_2026-10-30.pdf); [original 13 Oct 2026](hackathon/presentation/A3-PS036-TC161_2026-10-13.pdf) | done |
| **Team video** (YouTube link in the repository) | [YouTube](https://youtu.be/FaVfeO5WTV8), linked from the [README](README.md) | done |
| **Source code, documents and supporting material** | this repository; start at the [README](README.md) and [docs/](docs/README.md) | done |
| **Working demo** | run it in the browser with [Codespaces](docs/codespaces.md), or [locally](docs/getting-started.md); the demo is built by the visitor, not hosted | done |
| **Final deliverable files**, for evaluators who do not run the demo | [hackathon/results/](hackathon/results/README.md): a frozen run with its report | a quick run; the full run is pending (below) |

Supporting material: the [project page](hackathon/README.md), a short [readout](hackathon/readout.md), and
[findings with an interop matrix and follow-ups](hackathon/feedback.md).

### Open items before the submission is final

- **Full run on a fixed machine.** The frozen run is a 3-trial quick demonstration on a laptop CPU with the `powersave`
  governor. The full run (50 / 500 / 5,000 names, 10 trials, about 5 hours) has not been frozen. Until it is, quote the
  quick run only as a demonstration.
- **Simulated-lab benchmark.** No finished simulated benchmark is frozen yet.
- **Fixed state.** Tag the repository (for example `hackathon-submission`) when the submission is final.
- **Findings.** The findings in [hackathon/feedback.md](hackathon/feedback.md) are written up with evidence but not
  reported to the upstream projects.

## PS-036 requirements

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
