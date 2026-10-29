# CipherOps · MTL DNSSEC benchmark dashboard

The dashboard for CipherOps: it shows the benchmark's results and evidence, and drives a live DNSSEC lab (a root → TLD → SLD hierarchy with a validating resolver and MTL mode).

```bash
pip install -r requirements-dashboard.txt
streamlit run dashboard/live_lab/app.py
```

Reading results needs nothing but files on disk (an offline run in `results/runs/`, or a live-lab benchmark). The live lab needs Docker. Use the **Small** dataset size for a first visit and the **draft-06** software stack for any MTL-versus-non-MTL comparison (on the **latest** stack, its Unbound does not validate plain SLH-DSA and answers SERVFAIL; the dashboard warns about it).

## Home

The home page answers four questions in order: what is this, what do you want to do, what did it find, and can I trust it. Top to bottom:

1. **Header.** The question the project answers, links to the two drafts, the event and the team.
2. **What brings you here?** Four choices: *Check the PS-036 deliverables*, *Watch the demonstration*, *Reproduce the benchmark*, *Understand MTL first*. Each shows an ordered path with buttons to the exact tile. The choice is kept in the address (`?visitor=evaluator`, `presenter`, `reproducer`, `explainer`) so a link can be shared. There is one primary button on the page: the next step for that visitor. An evaluator with a run on disk is never sent to Setup.
3. **What it found.** Headline cards read from the newest finished **offline run** (`results/runs/<id>/`), badged *Primary · pinned core*, then live-lab cards badged *Indicative · not core-pinned* for timings. Each card shows its kind (Measured, Extrapolated), the run id and date, the trial count and the interval label, and a *Provenance* popover with the run's `config.yaml`, `environment.json`, `preflight.json` and report. Failed lookups in a live-lab run are listed, never hidden. With no run, the page says which command produces one and shows no figures.
4. **PS-036 deliverables.** One row per expected outcome: *Evidence found*, *Partial* (what is missing is named) or *Not found on this machine*, with the proof file and a button to where it is shown. *Export evidence summary* downloads the table as Markdown with run ids and file paths. The rules are in `evidence.py`; for example, six or more trials count as found because that is where the interval of the median reaches 95%, and a run without `preflight.json` never counts as the benchmark harness.
5. **Two measurement paths.** The offline benchmark (primary: signing time, verification time, sizes) and the live-lab benchmark (resolver behaviour: truncation, TCP retry, bytes per level, cache counters).
6. **Tools.** The tiles below, each with when to use it and what it needs.
7. **Lab status.** The lab chips and the next step for the lab only. If Docker is down, it says so once here; the rest of the page still works.
8. **Known limits.** Always visible: the two paths run different MTL versions, plain SLH-DSA on the latest stack, placeholder code points, live-lab timings.
9. **Terms.** The glossary, generated from `terms.py`.
10. **Footer.** Git commit, whether the working tree has uncommitted changes, links to the README and methodology.

Nothing on the home page is a typed-in result. Figures are read from files (cached on their modification times) and carry their run id; the home page never starts a container or a job.

## Vocabulary

Display words come from one module, `terms.py`; internal ids (`mtl`, `slh-dsa`, folder names, CSV columns, config keys, `?tile=` values) never change. The glossary on the home page lists the PS-036 wording and the IETF term for each.

| On screen | Replaces | Navigation id |
|---|---|---|
| **Algorithm**: SLH-DSA-MTL, SLH-DSA, ECDSAP256SHA256 (13), ED25519 (15), RSASHA256 (8), Mixed | scenario, mtl, slh-dsa | |
| **Dataset size**: Small / Medium / Large | zone size | |
| **Level**: Root, TLD, SLD | tier, leaf zone | |
| **Sign zones** | Prepare | |
| **Software stack**: draft-06, latest | image version | |
| **Run** | suite, benchmark (as a noun) | |
| **Offline benchmark** | (new) | `offline` |
| **Setup** | Setup | `setup` |
| **Demonstrate** | Live | `live` |
| **Live-lab benchmark** | Benchmark | `benchmark` |
| **Results** | Compare | `compare` |
| **Learn** | Learn | `learn` |
| **Clean up** | Reset | `reset` |

The `mtl-mode-full` option (how a resolver asks for the full signature) has a **lab** code point, not an IANA one, and it differs by path: the offline byte model uses 65001 (`cipherops.codepoints.EDNS_MTL_MODE_FULL`) and the live lab's draft-06 stack uses 65050 (`driver.MTL_FULL`). The home page shows both.

## Tiles

Each tile page opens with the same three facts, from `terms.py`: *Use it when*, *Not for*, *Needs*.

| Tile | What it is for | Sidebar | Results view |
|------|----------------|---------|--------------|
| **Offline benchmark** | *Pinned core · primary results.* Runs the offline harness (`scripts/run_benchmark.sh`) as a background job with a live log and a Cancel button, lists the runs in `results/runs/` (id, date, dataset sizes with RRset counts, trials with the interval label, MTL commit, go/no-go verdict), lets you download each run's `report.html` or open it in Results, and shows the three commands with copy buttons. The full run takes several hours, and more than an hour even with the fewest trials | Run configuration (read from `configs/`), software stack (default latest), CPU core, **Start run**, **Run the go/no-go gate only** | The list of runs; the live log while one runs |
| **Setup** | Images, then dataset size and algorithms, sign zones, start / stop the lab (for Demonstrate) | Step 1 **Images** (**Software stack** draft-06 or latest, build or pull), step 2 **Sign zones** (zone design, sign), step 3 **Start**. Sign zones, Start and the live-lab benchmark run inside the images, so they wait until step 1 is done | Signing summary and timings |
| **Demonstrate** | Switch algorithm, send a lookup or `dig`, cold vs warm. A progress panel lists each step of a query with its duration; the last result is labelled with its query, path and algorithm and is cleared when the algorithm changes. **Presenting** (top of the page) hides the sidebar and the activity log and enlarges the text | Active algorithm, capture name | Queries (newest first), packet decode, sequence diagram. Results open on the current query's capture, or the newest capture if no query was run |
| **Live-lab benchmark** | *Real resolver · indicative timings.* The PS-036 benchmark through a real resolver: several dataset sizes, repeated trials | Name, dataset sizes, algorithms, trials, queries, networks, workload | Per-size tables, CSVs, and a reproducible `report.html` like the offline report |
| **Results** | Algorithms side by side, run against run, and the evolving zone. *Data from* has three options: **Offline benchmark**, **Live-lab benchmark** and **Single lab (older runs)** | Run, dataset size, network, candidate and baseline | Cards, scaling across sizes, signing, bytes per level, cache, latency, CSV |
| **Learn** | Why DNSSEC needs MTL: six animated scenes | none | the explainer |
| **Clean up** | Clear only the scopes you pick | Notes on what is kept | What the last clean-up removed |

### One benchmark at a time

The two benchmark tiles share one rule (`benchmark_lock.py`): while an offline run, a live-lab benchmark, an image build or a signing job is running, none of the others may start, because two jobs would share the CPU and distort the timings. The second one is refused with the reason ("An offline benchmark run (quick.yaml) is already running. ..."), the Start buttons are disabled with the same message, and the check is made under a lock so two sessions, or the dashboard and `suite.py` on the command line, cannot both pass it. A run started from a terminal with `scripts/run_benchmark.sh` is outside the dashboard's view, so the dashboard cannot see it.

The **About** button (top right) opens a panel describing the lab and the team; a full-screen button sits beside it. Start is available only once Sign zones has signed at least one algorithm for the chosen dataset size.

## Signing replay

After **Prepare**, Setup opens an animated replay of how the hierarchy was signed (also under Setup → **Signing replay**, any time the lab is prepared). It plays bottom-up: leaf zones, then TLDs, then the root, with the DS record travelling up to each parent and the root DS ending as the trust anchor. Pick a scenario to compare the stories:

- **mtl:** the zone's RRsets become leaves, the leaves are hashed into a Merkle tree, the rungs form the ladder, the ladder is signed once, and each RRset keeps only a short condensed path.
- **slh-dsa, ecdsa, rsa, ed25519:** every RRset is signed on its own, with a bar per signature drawn to the same scale so the sizes compare.

It is a normal animation: play, pause, restart, speed, and a timeline you can drag. Story time is compressed (each tier takes the same few seconds) and the real signing times are on the labels. Counts, timings and bytes are **measured** from the Prepare manifest. Signature and ladder sizes are **analytical** (draft section 12). The tree shape is **illustrative**: it is drawn from each zone's real RRSIG count (one leaf per RRSIG, one rung per 1-bit of that count), because the signing library does not report its tree. Code: `prepare_story.py` (scene builder, tested in `tests/test_prepare_story.py`) and `assets/prepare_player.html` (the player).

### Live while Prepare runs

**Build images** also runs as a background job (`build_job.py`, state in `ecosystem/jobs/_build/`): the Setup page shows its log live and has a Cancel button, and only one build runs at a time. **Prepare** no longer blocks the page. It starts a background job (`prepare_job.py`) and Setup shows the signing as it happens: an overall progress bar, a chip per scenario, leaf/TLD/root counters, the hierarchy coloured by state (grey waiting, amber signing, green signed, with the measured RRSIG count and time on each zone) and a zone table with a live clock. The signer prints one `@@EVENT {json}` line per zone start and finish when `ECOLAB_EVENTS=1` is set (`ecolab.sign.emit`); the job writes them to `ecosystem/jobs/<lab>/prepare-live/events.jsonl`, so the page can be reloaded or closed and picked up again. When signing ends the page opens the replay by itself. **Cancel signing** stops the job and its container. The job signs from a private copy of the config, so changing Zone size in the sidebar while it runs cannot redirect its output. Tests: `tests/test_prepare_job.py`.

### RRSIG counts

An RRSIG count is the number of real RRSIG records in the signed zone: a leaf zone has 2 per name (its record and its NSEC3 proof) plus 7 of its own, a TLD 2 per child plus 7, the root 2 per TLD plus 8 (Small = 55, Medium = 353). Earlier versions also counted NSEC3 records (their type bitmap lists RRSIG), about 1.5x too many. The signer now counts exactly, and manifests written before the fix are recounted from the signed files when the dashboard loads them (the stored figure is kept as `rrsig_count_manifest`). The planned-lab estimate uses the same exact formula.

## Live-lab benchmark

One press of **Run benchmark** does, for each dataset size (default 50, 500 and 5,000 data names): build the hierarchy, sign it with every chosen scenario (timed), repeat signing and verification on sample zones (several trials), start the lab, replay the same seeded workload with repeated cold and warm trials, and stop the lab. It needs only the built images: no Prepare and no running lab. It runs in the background, so you can leave the page; Results fills in when it finishes.

- **From the command line:** `python3 dashboard/live_lab/suite.py --sizes 50,500,5000 --trials 5 --name full` runs the same suite in the foreground and saves it like a dashboard run. `--plan` prints the settings and time estimate only, and a run estimated above 12 hours needs `--yes`. It takes the same lab guard as the dashboard: it refuses to start while another benchmark, a build or a signing job owns the lab, and while it runs the dashboard's lab buttons are disabled. Defaults: 5 measurement and 5 signing trials, scenarios ecdsa, slh-dsa, mtl, rsa, ed25519.
- **Algorithm and implementation:** SLH-DSA-SHA2-128s, with MTL (mtl) and without (slh-dsa), using Verisign's MTL-mode ldns, NSD and Unbound. ecdsa is an optional classical reference.
- **Signing and verification time:** each trial signs two sample zones; a straight line through them gives a fixed cost per zone and a cost per RRSIG, applied to every zone of the dataset. This is an extrapolation and is labelled as one. The full zones are also signed once and that time is shown next to it.
- **Transmitted bytes, truncation, cache memory, latency:** measured in the resolver run, per tier (root, TLD, leaf), cold and warm.
- **Trials and statistics:** the defaults are 5 measurement trials and 5 signing trials, each preceded by one discarded warm-up trial. The bracketed interval is a distribution-free interval of the median whose real coverage is 94% for 5 trials (75% for 3; at least 6 trials are needed for 95%). See `docs/methodology.md` §6.2.
- **Failed lookups are not data:** latency counts answered lookups only (NOERROR, NXDOMAIN). A pass with any SERVFAIL, timeout or other failure is marked invalid and excluded from every figure, its failures stay counted in `summary.csv`, and Benchmark and Compare show a warning. A scenario the resolver cannot validate therefore shows no numbers.
- **Not core-pinned:** lab containers share all host CPUs and the CPU governor is recorded, not changed. Use bytes and relative comparisons; treat absolute milliseconds as indicative.
- **Recorded:** every setting, the workload numbers, the network profiles, the pinned images and the host are stored in ecosystem/results/suites/<id>/ and shown under *Settings and environment recorded*. `suite.json` also holds the git commit (and whether the tree was modified), CPU model, memory, kernel, governor, Docker version, the stack's pinned component versions and the image IDs.
- **Report:** when a suite finishes it writes `report.md`, `report.html` and `figures/` (same role as the main Cipherops library report). Regenerate with `python -m live_lab.suite_report <suite-id>` from a shell that has `dashboard` on `PYTHONPATH`.

Compare reads a finished benchmark (or, for older single-lab runs, a lab you pick). Every figure is badged **Measured**, **Estimated** or **Analytical**; the analytical ones (signature storage from the draft section 12 formulas) have their own section and are never mixed with measured cache.

## Numbers you can change

| Where | Numbers | Needs re-Prepare |
|-------|---------|------------------|
| Setup → Zone size → **Custom…** | TLDs, leaf zones, names per leaf zone, leaf servers, seed (Live lab only) | Yes |
| Live-lab benchmark → **Workload mix** | NXDOMAIN share, zone and name popularity skew, lookup timeout | No |
| Live-lab benchmark → **Network profiles** | Delay to client, root, TLD and leaf, and loss, for `wan` and `lossy` | No |

Setup shows a **Planned lab** card (zones, names, containers, rough Prepare time) and the exact YAML the lab will use. A Custom shape gets its own lab folder named after a hash of its numbers (`eco-ui-custom-<hash>`), so signed zones and results from different shapes never mix. Only one lab runs at a time: Start stops any other. Each benchmark records the numbers it used.

## Naming runs

Give a benchmark a name in the Live-lab benchmark sidebar; it is stored with the date and time (`<YYYYMMDD-HHMMSS>_<name>`). Live captures take an optional name the same way (`live-<name>-<date>-<time>.pcap`). Names keep letters, digits, `-` and `_`.
