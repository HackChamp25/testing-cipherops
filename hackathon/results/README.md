# Frozen results

Results quoted by the submission are copied here so they cannot change when the tool is re-run. The data is not edited
after copying. The only change is that `report.md` and `report.html` were regenerated once from the same data after a
wording change to the report subtitle; every number and figure is identical.

## quick-demo-20261030T074948Z

A **quick demonstration**, not the full run.

| | |
| --- | --- |
| Run id | `20261030T074948Z-quick-demo` |
| Configuration | [`config.yaml`](quick-demo-20261030T074948Z/config.yaml): 3 trials plus 1 discarded warm-up, zones of 20 / 60 / 200 names (45 / 125 / 405 RRsets), seed 20261005 |
| Stack profile | `latest`: OpenSSL 3.6.0, liboqs 0.16.0, Verisign MTL `7cef0191da55048111d252a567b7614672424ed3` (FIPS 205 SLH-DSA) |
| Code version | git `90ecbc1f20cc3139d070ac97d943f05ea97ec50e` (clean tree) |
| Image | `sha256:d05eeb6684c037f5c48afe348a1fe1cacb7c580e4810e2ed9ba9a71643253524` |
| Machine | Intel Core Ultra 7 165H laptop, 22 logical CPUs, 62 GiB RAM, Fedora Linux host kernel 7.2.11 |
| Pinning | benchmark pinned to CPU core 2; **CPU governor `powersave`** |
| Network | none (container `network_mode: none`) |
| Gate | go/no-go: GO |
| Report | [`report.html`](quick-demo-20261030T074948Z/report.html) (self-contained), [`report.md`](quick-demo-20261030T074948Z/report.md) |

**How to read the numbers.** The machine is a laptop with a power-saving governor, so absolute milliseconds are
indicative; the ratios between algorithms measured in the same trial are more reliable. Three trials give a 75%
interval of the median, not 95% (see [methodology §6.2](../../docs/methodology.md#62-statistics)). The run's own
`environment.json` is the full record of versions and hardware. Sizes and byte counts do not depend on the machine.

### Contents

`report.html`, `report.md`, `figures/`, `config.yaml`, `environment.json`, `preflight.json`, `summary.json` and the CSV
tables (`trials`, `control`, `responses`, `workload`, `sizes`, `cache`, `datasets`, `evolution`, `evolution_direct`).
Column meanings: [outputs reference](../../docs/outputs-reference.md). The Parquet files, raw harness output and signature
artifacts of the original run are not copied.

## Still to freeze

- The **full run** (50 / 500 / 5,000 names, 10 trials, about 5 hours) on a fixed machine with a performance governor.
- A finished **simulated-lab benchmark** (`suite.json` and its report).

Timings from a Codespace or other shared virtual CPUs are indicative only and should not be frozen as headline results.
