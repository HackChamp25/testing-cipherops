# Cipherops · MTL DNSSEC Lab

Public lab UI for a multi-zone DNSSEC hierarchy (root → TLD → leaf) with a validating resolver and MTL mode.

```powershell
pip install -r requirements-dashboard.txt
streamlit run dashboard/live_lab/app.py
```

Needs Docker. Use **Small** zone size for a first visit.

## Home

The app opens on a hub of five tiles. **Setup** builds the images (and, for Live, signs and starts a lab); **Benchmark** needs only the images and runs by itself.

| Tile | What it is for | Sidebar | Results view |
|------|----------------|---------|--------------|
| **Setup** | Zone size, scenarios, images, sign zones, start / stop the lab (for Live) | Settings and steps 1-3 | Signing summary and timings |
| **Live** | Switch scenario, send a lookup, cold vs warm | Active scenario, capture name | Queries, packet decode, sequence diagram |
| **Benchmark** | The PS-036 benchmark: several dataset sizes, repeated trials | Name, dataset sizes, scenarios, trials, queries, networks, workload | Per-size signing and resolver tables, recorded settings, CSVs |
| **Compare** | MTL vs SLH-DSA and the other modes, side by side | Benchmark, dataset size, network, candidate and baseline | Cards, scaling across sizes, signing, bytes per tier, cache, latency, CSV |
| **Reset** | Clear only the scopes you pick | Notes on what is kept | What the last reset removed |

## Benchmark

One press of **Run benchmark** does, for each dataset size (default 50, 500 and 5,000 data names): build the hierarchy, sign it with every chosen scenario (timed), repeat signing and verification on sample zones (several trials), start the lab, replay the same seeded workload with repeated cold and warm trials, and stop the lab. It needs only the built images: no Prepare and no running lab. It runs in the background, so you can leave the page; Results fills in when it finishes.

- **Algorithm and implementation:** SLH-DSA-SHA2-128s, with MTL (mtl) and without (slh-dsa), using Verisign's MTL-mode ldns, NSD and Unbound. ecdsa is an optional classical reference.
- **Signing and verification time:** each trial signs two sample zones; a straight line through them gives a fixed cost per zone and a cost per RRSIG, applied to every zone of the dataset. This is an extrapolation and is labelled as one. The full zones are also signed once and that time is shown next to it.
- **Transmitted bytes, truncation, cache memory, latency:** measured in the resolver run, per tier (root, TLD, leaf), cold and warm.
- **Recorded:** every setting, the workload numbers, the network profiles, the pinned images and the host are stored in ecosystem/results/suites/<id>/ and shown under *Settings and environment recorded*.

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
