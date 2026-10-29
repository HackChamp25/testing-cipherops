"""Scene model for the "Signing replay": what Prepare did, as a timeline a browser can animate.

Pure functions over a Prepare manifest (``ecosystem/work/<lab>/zones/<scenario>/manifest.json``). Nothing
here talks to Docker or Streamlit, so it is cheap to test.

What is measured and what is drawn
----------------------------------
* **Measured**: zones, tiers, algorithm, sign and verify seconds, signed-file bytes and DS records come
  from the manifest. The number of signed RRsets per zone is counted from the RRSIG records in the signed
  zone file (``rrsig_profile``), because the manifest's ``rrsig_count`` also counts NSEC3 records.
* **Analytical** (draft section 12 formulas in ``cipherops.analytical``): condensed signature and
  signed-ladder sizes.
* **Illustrative**: the shape of the Merkle tree. One signed RRset is one leaf, so a zone with N of them
  has N leaves, and the ladder has one rung per 1-bit of N (draft section 6.6, ``analytical.rung_count``).
  The library does not report its tree, so the drawing is derived from N, not read back from it.

Story time is compressed: every tier gets the same ``PHASE_S`` seconds however long the real signing
took, so a 5,000-name lab replays as fast as a 50-name one. Real durations stay on the labels.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[2] / "src"
if str(_SRC) not in sys.path:
    sys.path.append(str(_SRC))
from cipherops import analytical  # noqa: E402
from cipherops.codepoints import MTL_SECURITY_PARAMETER_N, SLH_DSA_SHA2_128S_SIG_BYTES  # noqa: E402

INTRO_S = 1.6      # title card before the first tier
PHASE_S = 9.0      # story seconds per tier (leaf zones, TLD, root)
OUTRO_S = 5.0      # summary card after the root
ZONE_END = 0.88    # a zone's signing finishes this far into its phase; the rest is DS hand-off

TIER_ORDER = ("sld", "tld", "root")
TIER_LABEL = {"sld": "SLD zone", "tld": "TLD", "root": "Root"}
TIER_PLURAL = {"sld": "SLD zones", "tld": "TLDs", "root": "Root"}

# Direct (per-RRset) signature sizes; SLH-DSA comes from the project's own constant.
DIRECT_SIG_BYTES = {"slh-dsa": SLH_DSA_SHA2_128S_SIG_BYTES, "ecdsa": 64, "ed25519": 64, "rsa": 256}
FAMILY_LABEL = {"mtl": "MTL", "slh-dsa": "SLH-DSA", "ecdsa": "ECDSA", "ed25519": "Ed25519", "rsa": "RSA",
                "classical": "classical"}
COLORS = {"mtl": "#2e9e6f", "slh-dsa": "#e4572e", "ecdsa": "#4c78a8", "ed25519": "#9aa9c4",
          "rsa": "#7f8fa9", "classical": "#7f8fa9"}


def family(algorithm: str) -> str:
    """Which signing story an algorithm name belongs to."""
    a = (algorithm or "").upper()
    if "MTL" in a:
        return "mtl"
    if "SLH" in a:
        return "slh-dsa"
    if "ECDSA" in a:
        return "ecdsa"
    if "ED25519" in a or "ED448" in a:
        return "ed25519"
    if "RSA" in a:
        return "rsa"
    return "classical"


def ladder_rungs(n_leaves: int) -> list[int]:
    """Leaf count under each rung, largest first: one perfect subtree per 1-bit of N (draft section 6.6)."""
    n = max(1, int(n_leaves))
    return [1 << k for k in range(n.bit_length() - 1, -1, -1) if n >> k & 1]


def parent_origin(origin: str, known: set[str]) -> str | None:
    """Nearest ancestor of ``origin`` that is one of the signed zones (the root is the last resort)."""
    if origin == ".":
        return None
    labels = origin.rstrip(".").split(".")
    for i in range(1, len(labels)):
        cand = ".".join(labels[i:]) + "."
        if cand in known:
            return cand
    return "."


def _direct_bytes(fam: str) -> int:
    return DIRECT_SIG_BYTES.get(fam, 64)


def zone_signature_bytes(fam: str, n_leaves: int) -> int:
    """Analytical signature material for one zone: MTL = N condensed + one ladder, else N direct."""
    if fam == "mtl":
        return (n_leaves * analytical.max_condensed_signature(MTL_SECURITY_PARAMETER_N, n_leaves)
                + analytical.max_signed_ladder(MTL_SECURITY_PARAMETER_N, n_leaves, SLH_DSA_SHA2_128S_SIG_BYTES))
    return n_leaves * _direct_bytes(fam)


def fmt_bytes(n: float) -> str:
    n = float(n)
    if n < 10240:  # exact bytes for single signatures (SLH-DSA is 7,856 B)
        return f"{n:,.0f} B"
    if n < 1024 ** 2:
        return f"{n / 1024:,.1f} KB"
    return f"{n / 1024 ** 2:,.1f} MB"


_PROFILE_CACHE: dict[tuple, dict] = {}


def rrsig_profile(path: Path) -> dict | None:
    """Count the RRSIG records in a signed zone file, by the type each one covers.

    ``manifest.json``'s ``rrsig_count`` also counts NSEC3 records (their type bitmap lists RRSIG), so it
    runs about 1.5x high. The MTL tree has one leaf per signed RRset, so the replay needs the real number.
    """
    try:
        stt = path.stat()
    except OSError:
        return None
    key = (str(path), stt.st_mtime_ns, stt.st_size)
    if key in _PROFILE_CACHE:
        return _PROFILE_CACHE[key]
    by_type: dict[str, int] = {}
    with path.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            parts = line.split(None, 6)  # RRSIG lines carry a huge base64 tail we never need
            for i in range(min(4, len(parts) - 2)):
                if parts[i] == "IN" and parts[i + 1] == "RRSIG":
                    by_type[parts[i + 2]] = by_type.get(parts[i + 2], 0) + 1
                    break
    out = {"total": sum(by_type.values()), "by_type": by_type}
    _PROFILE_CACHE[key] = out
    return out


def _span(values: list[int]) -> str:
    lo, hi = min(values), max(values)
    return f"{lo:,}" if lo == hi else (f"{lo:,} / {hi:,}" if len(set(values)) <= 2 else f"{lo:,}–{hi:,}")


def _plan(zones: list[dict], size_label: str, exact: bool) -> dict:
    """The one-line answer to "how many records go where, and why", per tier."""
    tiers = []
    for tier in TIER_ORDER:
        zs = [z for z in zones if z["tier"] == tier]
        if not zs:
            continue
        counts: dict[int, int] = {}
        for z in zs:
            counts[z["n_leaves"]] = counts.get(z["n_leaves"], 0) + 1
        total = sum(z["n_leaves"] for z in zs)
        if len(zs) == 1:
            head = f"{TIER_LABEL[tier]} · {total:,} RRsets"
        else:
            groups = " + ".join(f"{c} × {n:,}" for n, c in sorted(counts.items()))
            head = f"{TIER_PLURAL[tier]} · {groups} = {total:,} RRsets" if len(counts) > 1 else \
                f"{TIER_PLURAL[tier]} · {len(zs)} × {zs[0]['n_leaves']:,} RRsets"
        unit = [z["n_names"] if tier == "sld" else z["children"] for z in zs]
        one, many = {"sld": ("name", "names"), "tld": ("SLD zone", "SLD zones"), "root": ("TLD", "TLDs")}[tier]
        noun = one if max(unit) == 1 else many
        proof = "record + NSEC3 proof" if tier == "sld" else "DS + NSEC3 proof"
        if exact:
            extra = [z["n_leaves"] - 2 * u for z, u in zip(zs, unit)]
            why = f"{_span(unit)} {noun} × 2 ({proof}) + {_span(extra)} zone records"
        else:
            why = "counted from the Prepare manifest"
        tiers.append({"tier": tier, "label": TIER_PLURAL[tier] if len(zs) > 1 else TIER_LABEL[tier],
                      "head": head, "why": why, "zones": len(zs), "total": total})
    names = sum(z["n_names"] for z in zones if z["tier"] == "sld")
    return {"size": size_label, "names": names, "zones": len(zones), "tiers": tiers, "exact": exact}


def _zone_windows(tier_zones: list[dict], spotlight: int, t0: float) -> None:
    """Give every zone in a tier its start/end story time. The spotlight zone gets the whole phase."""
    lo, hi = t0 + 0.4, t0 + PHASE_S * ZONE_END
    others = [i for i in range(len(tier_zones)) if i != spotlight]
    tier_zones[spotlight]["t0"], tier_zones[spotlight]["t1"] = lo, hi
    if not others:
        return
    span = hi - lo
    dz = min(span, max(0.9, span * 0.4))
    for j, i in enumerate(others):
        start = lo + ((span - dz) * j / (len(others) - 1) if len(others) > 1 else (span - dz) / 2)
        tier_zones[i]["t0"], tier_zones[i]["t1"] = start, start + dz


def build_scene(manifest: dict, *, lab: str = "", scenario: str | None = None,
                zones_dir: Path | None = None, size_label: str = "") -> dict:
    """Turn one scenario's Prepare manifest into the scene the player animates.

    With ``zones_dir`` (the folder holding the signed zone files) every leaf count is the real number of
    RRSIG records in the signed file. Without it the manifest's ``rrsig_count`` is used, which runs high.
    """
    scen = scenario or manifest.get("scenario") or ""
    raw = list(manifest.get("zones") or [])
    known = {z.get("origin", "") for z in raw}

    zones: list[dict] = []
    exact = bool(raw)
    for z in raw:
        fam = family(z.get("algorithm", ""))
        prof = rrsig_profile(Path(zones_dir) / z["signed_file"]) if (zones_dir and z.get("signed_file")) else None
        if prof and prof["total"] > 0:
            n = prof["total"]
        else:
            n, exact = max(1, int(z.get("rrsig_count") or 0)), False
        ds = (z.get("ds") or [""])[0]
        zones.append({
            "origin": z.get("origin", ""), "tier": z.get("tier", "sld"),
            "parent": parent_origin(z.get("origin", ""), known),
            "family": fam, "algorithm": z.get("algorithm", ""),
            "n_names": int(z.get("n_names") or 0), "children": 0,
            "n_leaves": n, "rungs": ladder_rungs(n),
            "sign_s": float(z.get("sign_seconds") or 0.0), "verify_s": float(z.get("verify_seconds") or 0.0),
            "signed_bytes": int(z.get("signed_bytes") or 0),
            "direct_bytes": _direct_bytes(fam),
            "condensed_bytes": analytical.max_condensed_signature(MTL_SECURITY_PARAMETER_N, n) if fam == "mtl" else 0,
            "ladder_bytes": (analytical.max_signed_ladder(MTL_SECURITY_PARAMETER_N, n, SLH_DSA_SHA2_128S_SIG_BYTES)
                             if fam == "mtl" else 0),
            "ds": ds[:72],
            "t0": 0.0, "t1": 0.0, "phase": -1, "spotlight": False,
        })

    for z in zones:
        z["children"] = sum(1 for c in zones if c["parent"] == z["origin"])

    phases: list[dict] = []
    t = INTRO_S
    for tier in TIER_ORDER:
        idx = [i for i, z in enumerate(zones) if z["tier"] == tier]
        if not idx:
            continue
        tz = [zones[i] for i in idx]
        spot = max(range(len(tz)), key=lambda k: (tz[k]["n_leaves"], -k))
        _zone_windows(tz, spot, t)
        for z in tz:
            z["phase"] = len(phases)
        tz[spot]["spotlight"] = True
        phases.append({
            "index": len(phases), "tier": tier, "label": TIER_PLURAL[tier], "t0": t, "t1": t + PHASE_S,
            "zones": len(tz), "spot": tz[spot]["origin"],
            "sign_s": round(sum(z["sign_s"] for z in tz), 3),
            "verify_s": round(sum(z["verify_s"] for z in tz), 3),
        })
        t += PHASE_S

    fams = sorted({z["family"] for z in zones})
    main = max(fams, key=lambda f: sum(z["n_leaves"] for z in zones if z["family"] == f)) if fams else "classical"
    ta = manifest.get("trust_anchor") or []
    scene = {
        "lab": lab, "scenario": scen, "family": main, "families": fams, "color": COLORS.get(main, "#7f8fa9"),
        "label": FAMILY_LABEL.get(main, main), "algorithms": manifest.get("algorithms") or {},
        "zones": zones, "phases": phases, "slh_sig_bytes": SLH_DSA_SHA2_128S_SIG_BYTES,
        "t_intro": INTRO_S, "t_phases_end": t, "duration": t + OUTRO_S,
        "trust_anchor": (ta[0] if ta else "")[:96],
        "totals": _totals(zones),
        "plan": _plan(zones, size_label or lab, exact),
        "leaves_exact": exact,
    }
    scene["outro"] = _outro(scene)
    return scene


def _totals(zones: list[dict]) -> dict:
    rrsigs = sum(z["n_leaves"] for z in zones)
    mtl_zones = [z for z in zones if z["family"] == "mtl"]
    return {
        "zones": len(zones), "rrsigs": rrsigs,
        "signed_bytes": sum(z["signed_bytes"] for z in zones),
        "sign_s": round(sum(z["sign_s"] for z in zones), 3),
        "verify_s": round(sum(z["verify_s"] for z in zones), 3),
        # One slow signature per MTL zone; every other zone signs each RRset on its own.
        "slow_sigs": len(mtl_zones) + sum(z["n_leaves"] for z in zones if z["family"] != "mtl"),
        "sig_bytes": sum(zone_signature_bytes(z["family"], z["n_leaves"]) for z in zones),
        "sig_bytes_if_slh": sum(zone_signature_bytes("slh-dsa", z["n_leaves"]) for z in zones),
        "by_tier": {t: sum(1 for z in zones if z["tier"] == t) for t in TIER_ORDER},
    }


def _outro(scene: dict) -> list[str]:
    tot, fam = scene["totals"], scene["family"]
    tiers = tot["by_tier"]
    lines = [f"Signed bottom-up: {tiers['sld']} SLD · {tiers['tld']} TLD · {tiers['root']} root "
             f"({tot['zones']} zones, {tot['rrsigs']:,} RRSIGs)"]
    if fam == "mtl":
        lines.append(f"Only {tot['slow_sigs']} SLH-DSA signatures computed: one signed ladder per zone, "
                     f"not one per RRset")
        lines.append(f"Signature material ≈ {fmt_bytes(tot['sig_bytes'])} vs "
                     f"{fmt_bytes(tot['sig_bytes_if_slh'])} with plain SLH-DSA (analytical)")
    else:
        lines.append(f"{tot['slow_sigs']:,} {scene['label']} signatures computed, one per RRset")
        lines.append(f"Signature material ≈ {fmt_bytes(tot['sig_bytes'])} (analytical)")
    lines.append(f"Measured: signing {tot['sign_s']:.2f} s · zone verify {tot['verify_s']:.2f} s · "
                 f"signed zones {fmt_bytes(tot['signed_bytes'])}")
    if scene["trust_anchor"]:
        lines.append("Root DS is the trust anchor handed to the validating resolver")
    return lines


def scene_json(scene: dict) -> str:
    """JSON that is safe to place inside a ``<script>`` element."""
    return json.dumps(scene, separators=(",", ":")).replace("<", "\\u003c")


ASSET = Path(__file__).with_name("assets") / "prepare_player.html"


def render_html(scene: dict) -> str:
    """The self-contained player page for one scene."""
    return ASSET.read_text(encoding="utf-8").replace("__SCENE_JSON__", scene_json(scene))
