# Cipherops · MTL DNSSEC Lab

Public lab UI for a multi-zone DNSSEC hierarchy (root → TLD → leaf) with a validating resolver and MTL mode.

```powershell
pip install -r requirements-dashboard.txt
streamlit run dashboard/live_lab/app.py
```

Needs Docker. Use **Small** zone size for a first visit.

## Sidebar

| Section | Purpose |
|---------|---------|
| **Setup** | Zone size and scenarios to sign |
| **Steps 1–5** | Images → Prepare → Start → Scenario → Query |
| **Reset** | Clear captures / results |
| **Batch benchmark** | Long multi-trial run across scenarios and networks |

## Tabs

**Lab** · **Metrics** · **Packets** · **Activity**
