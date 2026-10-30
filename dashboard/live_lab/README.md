# Cipherops · MTL DNSSEC Lab

Public lab UI for a multi-zone DNSSEC hierarchy (root → TLD → leaf) with a validating resolver and MTL mode.

```bash
pip install -r requirements-dashboard.txt
streamlit run dashboard/live_lab/app.py
```

Needs Docker. Use **Small** zone size for a first visit and the **`draft06`** image version for any MTL-versus-non-MTL comparison (on `latest`, its Unbound does not validate plain SLH-DSA and answers SERVFAIL; the dashboard warns about it).

## Home

The app opens on a hub of five tiles. **Setup** builds the images (and, for Live, signs and starts a lab); **Benchmark** runs by itself: *Offline (harness)* needs nothing built beforehand, *Simulated (Verisign stack)* needs only the images.

| Tile | What it is for | Sidebar | Results view |
|------|----------------|---------|--------------|
| **Setup** | Images, then zone size and scenarios, sign zones, start / stop the lab (for Live) | Step 1 **Images** (**Image version** `draft06` or `latest`, build or pull), step 2 **Prepare** (zone design, sign), step 3 **Start**. Prepare, Start and the benchmark run inside the images, so they wait until step 1 is done | Signing summary and timings |
| **Live** | Switch scenario, send a lookup or `dig`, cold vs warm. A progress panel lists each step of a query with its duration; the last result is labelled with its query, path and scenario and is cleared when the scenario changes | Active scenario, capture name | Queries (newest first), packet decode, sequence diagram. Results open on the current query's capture, or the newest capture if no query was run |
| **Benchmark** | *Offline (harness)*: quick check or full run on a dedicated core. *Simulated (Verisign stack)*: several zone sizes, repeated trials on the Docker lab | Mode; run size (offline); or name, zone sizes, scenarios, trials, queries, networks, workload (simulated) | Per-size tables, CSVs, and a reproducible `report.html` like the main Cipherops report |
| **Compare** | MTL vs SLH-DSA and the other modes, side by side | Benchmark, dataset size, network, candidate and baseline | Cards, scaling across sizes, signing, bytes per tier, cache, latency, CSV |
| **Reset** | Clear only the scopes you pick | Notes on what is kept | What the last reset removed |

## Signing replay

After **Prepare**, Setup opens an animated replay of how the hierarchy was signed (also under Setup → **Signing replay**, any time the lab is prepared). It plays bottom-up: leaf zones, then TLDs, then the root, with the DS record travelling up to each parent and the root DS ending as the trust anchor. Pick a scenario to compare the stories:

- **mtl:** the zone's RRsets become leaves, the leaves are hashed into a Merkle tree, the rungs form the ladder, the ladder is signed once, and each RRset keeps only a short condensed path.
- **slh-dsa, ecdsa, rsa, ed25519:** every RRset is signed on its own, with a bar per signature drawn to the same scale so the sizes compare.

It is a normal animation: play, pause, restart, speed, and a timeline you can drag. Story time is compressed (each tier takes the same few seconds) and the real signing times are on the labels. Counts, timings and bytes are **measured** from the Prepare manifest. Signature and ladder sizes are **analytical** (draft section 12). The tree shape is **illustrative**: it is drawn from each zone's real RRSIG count (one leaf per RRSIG, one rung per 1-bit of that count), because the signing library does not report its tree. Code: `prepare_story.py` (scene builder, tested in `tests/test_prepare_story.py`) and `assets/prepare_player.html` (the player).

### Live while Prepare runs

**Build images** also runs as a background job (`build_job.py`, state in `ecosystem/jobs/_build/`): the Setup page shows its log live and has a Cancel button, and only one build runs at a time. **Prepare** no longer blocks the page. It starts a background job (`prepare_job.py`) and Setup shows the signing as it happens: an overall progress bar, a chip per scenario, leaf/TLD/root counters, the hierarchy coloured by state (grey waiting, amber signing, green signed, with the measured RRSIG count and time on each zone) and a zone table with a live clock. The signer prints one `@@EVENT {json}` line per zone start and finish when `ECOLAB_EVENTS=1` is set (`ecolab.sign.emit`); the job writes them to `ecosystem/jobs/<lab>/prepare-live/events.jsonl`, so the page can be reloaded or closed and picked up again. When signing ends the page opens the replay by itself. **Cancel signing** stops the job and its container. The job signs from a private copy of the config, so changing Zone size in the sidebar while it runs cannot redirect its output. Tests: `tests/test_prepare_job.py`.

### RRSIG counts

An RRSIG count is the number of real RRSIG records in the signed zone: a leaf zone has 2 per name (its record and its NSEC3 proof) plus 7 of its own, a TLD 2 per child plus 7, the root 2 per TLD plus 8 (Small = 55, Medium = 353). Earlier versions also counted NSEC3 records (their type bitmap lists RRSIG), about 1.5x too many. The signer now counts exactly, and manifests written before the fix are recounted from the signed files when the dashboard loads them (the stored figure is kept as `rrsig_count_manifest`). The planned-lab estimate uses the same exact formula.

## Benchmark

One press of **Run benchmark** does, for each dataset size (default 50, 500 and 5,000 data names): build the hierarchy, sign it with every chosen scenario (timed), repeat signing and verification on sample zones (several trials), start the lab, replay the same seeded workload with repeated cold and warm trials, and stop the lab. It needs only the built images: no Prepare and no running lab. It runs in the background, so you can leave the page; Results fills in when it finishes.

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
| Benchmark → **Workload mix** | NXDOMAIN share, zone and name popularity skew, lookup timeout | No |
| Benchmark → **Network profiles** | Delay to client, root, TLD and leaf, and loss, for `wan` and `lossy` | No |

Setup shows a **Planned lab** card (zones, names, containers, rough Prepare time) and the exact YAML the lab will use. A Custom shape gets its own lab folder named after a hash of its numbers (`eco-ui-custom-<hash>`), so signed zones and results from different shapes never mix. Only one lab runs at a time: Start stops any other. Each benchmark records the numbers it used.

## Naming runs

Give a benchmark a name in the Benchmark sidebar; it is stored with the date and time (`<YYYYMMDD-HHMMSS>_<name>`). Live captures take an optional name the same way (`live-<name>-<date>-<time>.pcap`). Names keep letters, digits, `-` and `_`.
