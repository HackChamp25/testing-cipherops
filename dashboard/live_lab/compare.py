"""Side-by-side comparison of scenarios (signing, size, bytes on the wire, cache).

Pure functions over what the lab already writes to disk: the Prepare manifests (signing and
verification time, signed size) and a saved benchmark run's ``summary.csv`` (bytes per hop,
truncation, cache memory, cold and warm latency). Nothing here talks to Docker.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

_SRC = Path(__file__).resolve().parents[2] / "src"
if str(_SRC) not in sys.path:
    sys.path.append(str(_SRC))
from cipherops import analytical  # noqa: E402  (formula module: draft section 12 maxima)
from cipherops.codepoints import MTL_SECURITY_PARAMETER_N, SLH_DSA_SHA2_128S_SIG_BYTES  # noqa: E402

ORDER = ["rsa", "ecdsa", "ed25519", "slh-dsa", "mixed-mtl", "mtl"]
COLORS = {
    "rsa": "#7f8fa9", "ecdsa": "#4c78a8", "ed25519": "#9aa9c4",
    "slh-dsa": "#e4572e", "mixed-mtl": "#8e6bbf", "mtl": "#2e9e6f",
}


def order_scenarios(names) -> list[str]:
    names = list(dict.fromkeys(names))
    known = [s for s in ORDER if s in names]
    return known + sorted(s for s in names if s not in ORDER)


def signing_by_scenario(rows: list[dict]) -> pd.DataFrame:
    """One row per scenario from the Prepare manifest rows (one per zone per scenario)."""
    cols = ["scenario", "zones", "sign_s", "verify_s", "signed_bytes", "rrsigs", "sign_ms_per_rrsig"]
    if not rows:
        return pd.DataFrame(columns=cols)
    df = pd.DataFrame(rows)
    for c in ("sign_seconds", "verify_seconds", "signed_bytes", "rrsig_count"):
        df[c] = pd.to_numeric(df.get(c), errors="coerce").fillna(0)
    g = df.groupby("scenario").agg(
        zones=("origin", "count"), sign_s=("sign_seconds", "sum"), verify_s=("verify_seconds", "sum"),
        signed_bytes=("signed_bytes", "sum"), rrsigs=("rrsig_count", "sum"),
    ).reset_index()
    g["sign_ms_per_rrsig"] = (g.sign_s * 1000 / g.rrsigs.where(g.rrsigs > 0)).round(3)
    return g[cols]


def bench_by_scenario(summary: pd.DataFrame, profile: str | None = None,
                      udp_limit: int | None = None) -> pd.DataFrame:
    """One row per scenario from a benchmark ``summary.csv`` (cold and warm pass side by side)."""
    cols = ["scenario", "cold_ms", "warm_ms", "upstream_bytes", "upstream_queries", "truncated", "tcp_conns",
            "client_bytes", "root_bytes", "tld_bytes", "sld_bytes", "cache_rrset", "cache_message"]
    if summary is None or summary.empty:
        return pd.DataFrame(columns=cols)
    s = summary
    if profile is not None and "profile" in s:
        s = s[s["profile"] == profile]
    if udp_limit is not None and "udp_limit" in s:
        s = s[s["udp_limit"] == udp_limit]

    def pick(frame: pd.DataFrame, col: str) -> float | None:
        if col not in frame or frame[col].dropna().empty:
            return None
        return float(frame[col].dropna().iloc[0])

    rows = []
    for scenario, g in s.groupby("scenario", sort=False):
        cold, warm = g[g["pass"] == "cold"], g[g["pass"] == "warm"]
        rows.append({
            "scenario": scenario,
            "cold_ms": pick(cold, "median_ms"),
            "warm_ms": pick(warm, "median_ms"),
            "upstream_bytes": pick(cold, "upstream_bytes"),
            "upstream_queries": pick(cold, "upstream_queries"),
            "truncated": pick(cold, "upstream_truncated"),
            "tcp_conns": pick(cold, "upstream_tcp_connections"),
            "client_bytes": pick(cold, "hop_client_bytes"),
            "root_bytes": pick(cold, "hop_root_bytes"),
            "tld_bytes": pick(cold, "hop_tld_bytes"),
            "sld_bytes": pick(cold, "hop_sld_bytes"),
            "cache_rrset": pick(cold, "mem.cache.rrset"),
            "cache_message": pick(cold, "mem.cache.message"),
        })
    return pd.DataFrame(rows, columns=cols)


def analytical_by_scenario(rows: list[dict]) -> pd.DataFrame:
    """Formula-derived (draft section 12) signature storage per scenario; never measured.

    Per zone: direct SLH-DSA is N x 7,856 B; MTL is N maximum condensed signatures plus one maximum
    signed ladder. N is the zone's RRSIG count. Classical scenarios are left out.
    """
    n = MTL_SECURITY_PARAMETER_N
    total: dict[str, float] = {}
    for r in rows:
        alg, cnt = str(r.get("algorithm", "")), int(r.get("rrsig_count") or 0)
        if cnt <= 0 or not alg.upper().startswith("SLH-DSA"):
            continue
        if "MTL" in alg.upper():
            b = cnt * analytical.max_condensed_signature(n, cnt) + analytical.max_signed_ladder(
                n, cnt, SLH_DSA_SHA2_128S_SIG_BYTES)
        else:
            b = cnt * SLH_DSA_SHA2_128S_SIG_BYTES
        total[r["scenario"]] = total.get(r["scenario"], 0) + b
    return pd.DataFrame({"scenario": list(total), "analytic_sig_bytes": list(total.values())},
                        columns=["scenario", "analytic_sig_bytes"])


def analytical_per_signature(rows: list[dict]) -> dict | None:
    """Maximum size of one signature for the largest MTL zone in the lab (draft section 12)."""
    counts = [int(r.get("rrsig_count") or 0) for r in rows if "MTL" in str(r.get("algorithm", "")).upper()]
    if not counts or max(counts) <= 0:
        return None
    n_msg, n = max(counts), MTL_SECURITY_PARAMETER_N
    return {
        "n_messages": n_msg,
        "direct": SLH_DSA_SHA2_128S_SIG_BYTES,
        "condensed": analytical.max_condensed_signature(n, n_msg),
        "ladder": analytical.max_signed_ladder(n, n_msg, SLH_DSA_SHA2_128S_SIG_BYTES),
        "full": analytical.max_full_signature(n, n_msg, SLH_DSA_SHA2_128S_SIG_BYTES),
    }


def merge(signing: pd.DataFrame, bench: pd.DataFrame, analytic: pd.DataFrame | None = None) -> pd.DataFrame:
    df = signing.merge(bench, on="scenario", how="outer")
    if analytic is not None and not analytic.empty:
        df = df.merge(analytic, on="scenario", how="left")
    if "analytic_sig_bytes" not in df:
        df["analytic_sig_bytes"] = float("nan")
    if df.empty:
        return df
    df["_o"] = df.scenario.map({s: i for i, s in enumerate(order_scenarios(df.scenario))})
    return df.sort_values("_o").drop(columns="_o").reset_index(drop=True)


def _num(df: pd.DataFrame, scenario: str, col: str) -> float | None:
    if df.empty or col not in df:
        return None
    r = df[df.scenario == scenario]
    if r.empty or pd.isna(r.iloc[0][col]):
        return None
    return float(r.iloc[0][col])


def ratio_text(base: float | None, cand: float | None, better: str, worse: str) -> str:
    """'39× faster' when the candidate is lower than the baseline, '2.1× slower' when higher."""
    if not base or not cand or base <= 0 or cand <= 0:
        return "—"
    r = base / cand
    if abs(r - 1) < 0.05:
        return "about the same"
    n = r if r >= 1 else 1 / r
    word = better if r >= 1 else worse
    return f"{n:,.1f}× {word}" if n < 10 else f"{n:,.0f}× {word}"


def fmt_seconds(s: float | None) -> str:
    if s is None or pd.isna(s):
        return "—"
    if s < 1:
        return f"{s * 1000:.0f} ms"
    if s < 90:
        return f"{s:.1f} s"
    return f"{s / 60:.1f} min"


def fmt_bytes(n: float | None) -> str:
    if n is None or pd.isna(n):
        return "—"
    n = float(n)
    if n < 1024:
        return f"{n:.0f} B"
    if n < 1024 ** 2:
        return f"{n / 1024:.1f} KB"
    return f"{n / 1024 ** 2:.2f} MB"


def headline(df: pd.DataFrame, base: str, cand: str) -> list[dict]:
    """The five 'candidate vs baseline' cards."""
    spec = [
        ("Signing time", "sign_s", "faster", "slower", fmt_seconds, "Whole-zone signing during Prepare"),
        ("Zone verification", "verify_s", "faster", "slower", fmt_seconds,
         "ldns-verify-zone over every signed zone (offline check, not the resolver)"),
        ("Signed size", "signed_bytes", "smaller", "larger", fmt_bytes, "Total size of the signed zone files"),
        ("Bytes on the wire", "upstream_bytes", "less data", "more data", fmt_bytes,
         "Resolver ↔ authoritative traffic, cold pass"),
        ("Resolver cache", "cache_rrset", "less memory", "more memory", fmt_bytes,
         "Measured: RRset cache memory in Unbound after the cold pass"),
    ]
    out = []
    for label, col, better, worse, fmt, help_ in spec:
        b, c = _num(df, base, col), _num(df, cand, col)
        out.append({
            "label": label,
            "value": ratio_text(b, c, better, worse),
            "delta": f"{fmt(c)} vs {fmt(b)}" if b is not None and c is not None else "no data",
            "help": help_,
        })
    return out


def table(df: pd.DataFrame) -> pd.DataFrame:
    """Human-readable comparison table (one row per scenario)."""
    if df.empty:
        return df
    t = pd.DataFrame({
        "Scenario": df.scenario,
        "Sign zones": df.sign_s.map(fmt_seconds),
        "Verify zones": df.verify_s.map(fmt_seconds),
        "Sign / RRSIG (ms)": df.sign_ms_per_rrsig,
        "Signed size": df.signed_bytes.map(fmt_bytes),
        "RRSIGs": df.rrsigs,
        "Cold median (ms)": df.cold_ms.round(2),
        "Warm median (ms)": df.warm_ms.round(2),
        "Upstream bytes (cold)": df.upstream_bytes.map(fmt_bytes),
        "Upstream queries": df.upstream_queries,
        "Truncated": df.truncated,
        "TCP connections": df.tcp_conns,
        "Root": df.root_bytes.map(fmt_bytes),
        "TLD": df.tld_bytes.map(fmt_bytes),
        "Leaf": df.sld_bytes.map(fmt_bytes),
        "RRset cache (measured)": df.cache_rrset.map(fmt_bytes),
        "Message cache (measured)": df.cache_message.map(fmt_bytes),
        "Signature storage, whole zone (analytical)": df.analytic_sig_bytes.map(fmt_bytes),
    })
    return t
