# Deliverables

The single place that says what this team is submitting and where each item lives. The README links here, so this file
is the source of truth for the PS-036 requirements.

## Hackathon deliverables

What IETF-style hackathon teams usually produce, and where each is here.

| Deliverable | Where | State |
| --- | --- | --- |
| **Project page**: goal, team, what was attempted | [hackathon/README.md](hackathon/README.md) | done |
| **Working code or reproducible results** in a public repo | this repository; run it with [Getting started](docs/getting-started.md) or [Codespaces](docs/codespaces.md); frozen results in [hackathon/results/](hackathon/results/README.md) | code done; frozen results are a quick run, the full run is pending (below) |
| **Short readout** (problem, what was done, results, issues found, next steps) | [hackathon/readout.md](hackathon/readout.md); full deck: [revised 30 Oct 2026](hackathon/presentation/A3-PS036-TC161_2026-10-30.pdf), [original 13 Oct 2026](hackathon/presentation/A3-PS036-TC161_2026-10-13.pdf) | done |
| **Feedback to the drafts and implementations**: issues found, interop and results matrix | [hackathon/feedback.md](hackathon/feedback.md) | findings written up; **none filed upstream yet** |
| **Known limits and follow-ups** | [Scope and limits](docs/scope-and-limits.md) and [hackathon/feedback.md](hackathon/feedback.md#follow-ups) | done |
| **Project video** | [YouTube](https://youtu.be/FaVfeO5WTV8) | done |
| **Fixed submission state** | git tag `hackathon-submission`, set when the submission is final | pending |

### Open items before the submission is final

- **Full run on a fixed machine.** The frozen run is a 3-trial quick demonstration on a laptop CPU with the `powersave`
  governor. The full run (50 / 500 / 5,000 names, 10 trials, about 5 hours) has not been frozen. Until it is, quote the
  quick run only as a demonstration.
- **Simulated-lab benchmark.** No finished simulated benchmark is frozen yet.
- **Upstream reports.** The findings in [hackathon/feedback.md](hackathon/feedback.md) are written up with evidence but
  not filed.

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
