# Cipherops · MTL DNSSEC Lab

Public lab UI for a multi-zone DNSSEC hierarchy (root → TLD → leaf) with a validating resolver and MTL mode.

```powershell
pip install -r requirements-dashboard.txt
streamlit run dashboard/live_lab/app.py
```

Needs Docker. Use **Small** zone size for a first visit.

## Home

The app opens on a hub of five independent tiles. **Setup** comes first and only needs doing once; the others work on their own after that.

| Tile | What it is for | Sidebar | Results view |
|------|----------------|---------|--------------|
| **Setup** | Zone size, scenarios, images, sign zones, start / stop the lab | Settings and steps 1–3 | Signing summary and timings |
| **Live** | Switch scenario, send a lookup, cold vs warm | Active scenario, capture name | Queries, packet decode, sequence diagram |
| **Benchmark** | Multi-trial runs across scenarios and networks | Run name, scenarios, queries, trials, networks | Named runs, summary table, charts, CSV |
| **Compare** | All scenarios side by side, headline ratios for MTL vs SLH-DSA | Lab, saved run, network, candidate and baseline | Signing, verification, signed size, bytes per tier, truncation, cache memory, latency, CSV |
| **Reset** | Clear only the scopes you pick | Notes on what is kept | What the last reset removed |

On Home the sidebar shows the entry instructions and lab readiness. Inside a tile it shows that tile's settings.

Compare reads what the lab already wrote: signing time, zone verification (`ldns-verify-zone`) and signed size from the last Prepare, and bytes per tier, truncation, cache memory and latency from the saved benchmark run you pick (cold pass). Every figure is badged **Measured** or **Analytical**; the analytical ones (signature storage from the draft §12 formulas) are shown in their own section and never mixed with measured cache.

## Numbers you can change

| Where | Numbers | Needs re-Prepare |
|-------|---------|------------------|
| Setup → Zone size → **Custom…** | TLDs, leaf zones, names per leaf zone, leaf servers, seed | Yes |
| Benchmark → **Workload mix** | NXDOMAIN share, zone and name popularity skew, lookup timeout | No |
| Benchmark → **Network profiles** | Delay to client, root, TLD and leaf, and loss, for `wan` and `lossy` | No |

Setup shows a **Planned lab** card (zones, names, containers, rough Prepare time) and the exact YAML the lab will use. A Custom shape gets its own lab folder named after a hash of its numbers (`eco-ui-custom-<hash>`), so signed zones and results from different shapes never mix. Only one lab runs at a time: Start stops any other. Each saved benchmark run records the numbers it used (Results → *Settings used for this run*).

## Naming runs

Give a benchmark run a name in the Benchmark sidebar; it is stored with the date and time (`<YYYYMMDD-HHMMSS>_<name>`). Live captures take an optional name the same way (`live-<name>-<date>-<time>.pcap`). Names keep letters, digits, `-` and `_`.
