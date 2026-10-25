"""Cipherops · MTL DNSSEC Lab — control room for the multi-zone stack.

    streamlit run dashboard/live_lab/app.py

Layout: a home hub of independent tiles (Setup, Live, Benchmark, Reset). Setup is the one
mandatory first step; every other tile works on its own once the lab is up. Each tile keeps
its controls in the sidebar and its own Results view in the main area.
"""

from __future__ import annotations

import importlib
import sys
import time
from datetime import datetime
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

ROOT = Path(__file__).resolve().parents[2]
ECO_DIR = ROOT / "ecosystem"
sys.path.insert(0, str(ROOT / "dashboard"))

from live_lab import compare, decode, driver  # noqa: E402

compare = importlib.reload(compare)
decode = importlib.reload(decode)
driver = importlib.reload(driver)

st.set_page_config(page_title="Cipherops · MTL DNSSEC Lab", layout="wide", page_icon="🛰️")

APP_NAME = "Cipherops · MTL DNSSEC Lab"
APP_TAGLINE = "Root → TLD → SLD · validating Unbound · Verisign MTL"

IMAGE_LABELS = {
    "cipherops-eco-nsd": "NSD authoritative servers",
    "cipherops-eco-unbound": "Unbound validating resolver",
    "cipherops-eco-tools": "Signing & probe tools",
}

SCENARIO_BLURB = {
    "rsa": "RSA-2048 with SHA-256",
    "ecdsa": "ECDSA P-256",
    "ed25519": "Ed25519",
    "slh-dsa": "Post-quantum SLH-DSA (large signatures)",
    "mtl": "SLH-DSA with MTL condensed signatures",
    "mixed-mtl": "ECDSA at root/TLD, MTL at the leaf zone",
}

LEVEL_ICON = {"info": "ℹ️", "ok": "✅", "warn": "⚠️", "err": "❌", "step": "▶️"}
ACTIVITY_CAP = 500

NAV_MODES = ("home", "setup", "live", "benchmark", "compare", "reset")
TILE_TEXT_HEIGHT = 290  # px; fits heading, pitch and bullets even when the copy wraps

TILES = {
    "setup": {
        "icon": "🛠️",
        "title": "Setup",
        "pitch": "Build the lab once. Everything else depends on it.",
        "bullets": [
            "Choose zone size and the DNSSEC scenarios to sign",
            "Get the images, sign the hierarchy, start the containers",
        ],
        "cta": "Open Setup",
    },
    "live": {
        "icon": "📡",
        "title": "Live",
        "pitch": "Send real lookups and watch the packets they cause.",
        "bullets": [
            "Switch scenario, run a query, compare cold and warm",
            "Decode the capture and draw its message sequence",
        ],
        "cta": "Open Live",
    },
    "benchmark": {
        "icon": "📊",
        "title": "Benchmark",
        "pitch": "Repeatable multi-trial runs, saved under a name you choose.",
        "bullets": [
            "Scenarios × networks × trials, cold then warm",
            "Charts and CSVs for every saved run",
        ],
        "cta": "Open Benchmark",
    },
    "compare": {
        "icon": "⚖️",
        "title": "Compare",
        "pitch": "All algorithms side by side: MTL against SLH-DSA in one place.",
        "bullets": [
            "Signing, verification, signed size, bytes on the wire, cache",
            "Headline ratios, charts and one table you can download",
        ],
        "cta": "Open Compare",
    },
    "reset": {
        "icon": "🧹",
        "title": "Reset",
        "pitch": "Clean up exactly what you pick, and nothing else.",
        "bullets": [
            "Session, logs, captures, saved runs, signed zones",
            "See what will go before you confirm",
        ],
        "cta": "Open Reset",
    },
}

_CSS = """
<style>
.co-chip{display:inline-block;padding:2px 11px;border-radius:999px;font-size:.78rem;
  font-weight:600;letter-spacing:.01em;vertical-align:middle}
.co-ok{background:#0f3d2b;color:#6df0b0}
.co-warn{background:#47360a;color:#ffd166}
.co-idle{background:#2a2f3a;color:#b6bdcc}
.co-info{background:#0e2f52;color:#7cc4ff}
.co-hero h1{margin-bottom:.1rem}
.co-sub{opacity:.75;margin-top:0}
.co-strip{margin:.2rem 0 .8rem 0;opacity:.95}
</style>
"""


@st.cache_resource(show_spinner=False)
def _brand():
    """(symbol, full logo) from the team logo, with its black backdrop made transparent.

    Returns (None, None) if the logo file is missing so the app still runs without it.
    """
    try:
        import numpy as np
        from PIL import Image

        src = ROOT / "docs" / "media" / "cipherops-logo-dark.png"
        rgb = np.asarray(Image.open(src).convert("RGB")).astype(float)
        alpha = np.clip((rgb.max(axis=2) - 12) * (255 / 70), 0, 255)
        full = Image.fromarray(np.dstack([rgb, alpha]).astype("uint8"), "RGBA")

        def _crop(img, rows=None, pad=6):
            a = np.asarray(img)[..., 3]
            if rows is not None:
                a = a[:rows]
            ys, xs = np.where(a > 60)
            return img.crop((max(xs.min() - pad, 0), max(ys.min() - pad, 0),
                             xs.max() + pad, ys.max() + pad))

        return _crop(full, rows=605), _crop(full)
    except Exception:  # noqa: BLE001
        return None, None


def _chip(text: str, kind: str = "idle") -> str:
    return f'<span class="co-chip co-{kind}">{text}</span>'


def _hint(text: str) -> None:
    """One-line sidebar guidance (public-demo friendly, not a wall of text)."""
    st.sidebar.caption(text)


_SESSION_KEYS = ("last_query", "query_log", "last_stats", "cache_result", "prepare_wall_s",
                 "prepare_summary", "last_log")
_PCAP_KEYS = ("last_pcap", "last_dropped", "last_story", "last_wire", "last_seq_steps",
              "last_seq_pcap", "auto_decode")


# ─────────────────────────── settings that survive tile switches ───────────────────────────
# Streamlit drops a widget's state as soon as the widget stops being drawn. Each tile draws a
# different sidebar, so values live in st.session_state["cfg"] and widgets are re-seeded from it.

def _store() -> dict:
    return st.session_state.setdefault("cfg", {})


def cfg(name: str, default=None):
    return _store().get(name, default)


def sb(fn, name: str, default, *args, options=None, **kw):
    """Draw a sidebar widget whose value persists in cfg[name] across tiles."""
    ss = st.session_state
    wk = f"w_{name}"
    if wk not in ss:
        ss[wk] = cfg(name, default)
    if options is not None:
        opts = list(options)
        if isinstance(ss[wk], list):
            ss[wk] = [v for v in ss[wk] if v in opts]
        elif ss[wk] not in opts:
            ss[wk] = default if default in opts else (opts[0] if opts else None)
        val = fn(*args, opts, key=wk, **kw) if args else fn(opts, key=wk, **kw)
    else:
        val = fn(*args, key=wk, **kw)
    _store()[name] = val
    return val


# ─────────────────────────── shared state helpers ───────────────────────────

def _handle() -> driver.LabHandle:
    if "lab_handle" not in st.session_state:
        st.session_state.lab_handle = driver.LabHandle()
    return st.session_state.lab_handle


def activity(
    level: str, title: str, detail: str = "", *,
    phase: str = "ui", source: str = "ui", h: driver.LabHandle | None = None,
) -> None:
    entry = {
        "t": datetime.now().strftime("%H:%M:%S"),
        "level": level, "title": title, "detail": (detail or "").strip(),
        "phase": phase, "source": source,
    }
    log = st.session_state.setdefault("activity", [])
    log.insert(0, entry)
    st.session_state.activity = log[:ACTIVITY_CAP]
    handle = h or st.session_state.get("lab_handle")
    if handle is not None:
        try:
            line = f"{entry['t']} [{source}/{phase}] {level.upper()} {title}"
            if entry["detail"]:
                line += f" | {entry['detail'][:2000]}"
            driver.append_activity_file(handle, line)
        except Exception:  # noqa: BLE001
            pass


def _log_chunks(text: str, *, phase: str, source: str, title: str) -> None:
    chunks = driver.chunk_log(text)
    for i, ch in enumerate(chunks, 1):
        suffix = f" ({i}/{len(chunks)})" if len(chunks) > 1 else ""
        activity("info", f"{title}{suffix}", f"```\n{ch}\n```", phase=phase, source=source)


def prepare_metrics_visible(h: driver.LabHandle) -> bool:
    if "show_prepare_metrics" in st.session_state:
        return bool(st.session_state.show_prepare_metrics)
    return bool(driver.load_session(h).get("show_prepare_metrics", False))


def _status(h: driver.LabHandle) -> dict:
    try:
        return driver.status(h)
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)[:300], "images": {}, "containers": {}, "prepared": False, "active": None}


def readiness(stt: dict) -> dict:
    imgs = stt.get("images") or {}
    containers = stt.get("containers") or {}
    r = {
        "images": bool(imgs) and all(imgs.values()),
        "prepared": bool(stt.get("prepared")),
        "running": any(containers.values()),
        "active": stt.get("active"),
    }
    r["ready"] = r["images"] and r["prepared"] and r["running"]
    r["count"] = sum(1 for k in ("images", "prepared", "running") if r[k])
    return r


def _go(mode: str) -> None:
    st.session_state.nav = mode if mode in NAV_MODES else "home"
    try:
        if mode == "home":
            if "tile" in st.query_params:
                del st.query_params["tile"]
        else:
            st.query_params["tile"] = mode
    except Exception:  # noqa: BLE001
        pass


def _init_nav() -> None:
    if "nav" in st.session_state:
        return
    tile = "home"
    try:
        tile = st.query_params.get("tile", "home")
    except Exception:  # noqa: BLE001
        pass
    st.session_state.nav = tile if tile in NAV_MODES else "home"


PROFILE_FIELDS = (
    ("client_ms", "Client link (ms)"), ("root_ms", "To root (ms)"), ("tld_ms", "To TLD (ms)"),
    ("sld_ms", "To leaf (ms)"), ("loss_pct", "Loss (%)"),
)
EDITABLE_PROFILES = ("wan", "lossy")  # lan stays the zero-delay baseline


def _custom_inputs() -> dict:
    return {
        "tlds": cfg("custom_tlds", "test"),
        "sld_count": int(cfg("custom_sld_count", 4)),
        "sizes": cfg("custom_sizes", "25, 50"),
        "servers": int(cfg("custom_servers", 1)),
        "seed": int(cfg("custom_seed", driver.DEFAULT_SEED)),
    }


def _shape() -> tuple[dict | None, list[str], list[str]]:
    """Zone shape for the current Setup choice, plus validation errors and warnings."""
    return driver.shape_for(cfg("zone_size", "small"), _custom_inputs())


def _workload() -> dict:
    d = driver.WORKLOAD_DEFAULTS
    return {
        "nx_fraction": int(cfg("nx_pct", round(d["nx_fraction"] * 100))) / 100,
        "zone_zipf_s": float(cfg("zone_zipf", d["zone_zipf_s"])),
        "name_zipf_s": float(cfg("name_zipf", d["name_zipf_s"])),
        "timeout_s": float(cfg("timeout_s", d["timeout_s"])),
    }


def _profiles() -> dict:
    out = {}
    for p in EDITABLE_PROFILES:
        base = driver.PROFILE_DEFAULTS[p]
        out[p] = {f: cfg(f"{p}_{f}", base[f]) for f, _ in PROFILE_FIELDS}
    return out


def _workload_is_default() -> bool:
    d = driver.WORKLOAD_DEFAULTS
    w = _workload()
    if (w["nx_fraction"], w["zone_zipf_s"], w["name_zipf_s"], w["timeout_s"]) != (
            d["nx_fraction"], d["zone_zipf_s"], d["name_zipf_s"], d["timeout_s"]):
        return False
    return all(float(v) == float(driver.PROFILE_DEFAULTS[p][f])
               for p, vals in _profiles().items() for f, v in vals.items())


def _restore_workload() -> None:
    keys = ["nx_pct", "zone_zipf", "name_zipf", "timeout_s"] + [
        f"{p}_{f}" for p in EDITABLE_PROFILES for f, _ in PROFILE_FIELDS]
    for k in keys:
        _store().pop(k, None)
        st.session_state.pop(f"w_{k}", None)


def _apply_ui_config(h: driver.LabHandle) -> str | None:
    """Write configs/_dashboard.yaml from the stored settings and point the handle at it."""
    sc = list(cfg("scenarios") or ["ecdsa", "slh-dsa", "mtl"])
    if not sc:
        return "Select at least one scenario in Setup."
    zone = cfg("zone_size", "small")
    shape, errors, _warnings = _shape()
    st.session_state.shape_errors = errors
    if errors or shape is None:
        return "Fix the custom zone numbers in Setup: " + " ".join(errors)
    if cfg("_zone_prev") != zone:
        # New zone size → queries-per-trial follows that size's default until the user edits it.
        _store()["n_queries"] = int(shape["n_queries_default"])
        _store()["_zone_prev"] = zone
        st.session_state.pop("w_n_queries", None)
    nq = int(cfg("n_queries", shape["n_queries_default"]))
    try:
        path = driver.write_ui_config(
            zone_size=zone,
            scenarios=sc,
            n_queries=nq,
            trials=int(cfg("trials", 1)),
            network_run=list(cfg("networks") or ["lan"]),
            udp_limits=[int(cfg("udp", 1232))],
            custom=_custom_inputs(),
            workload=_workload(),
            profiles=_profiles(),
        )
    except Exception as e:  # noqa: BLE001
        return str(e)[:400]
    h.config = path
    h.stack = cfg("stack", "draft06")
    st.session_state.lab_handle = h
    return None


# ─────────────────────────── page chrome ───────────────────────────

def _lab_strip(h: driver.LabHandle, stt: dict) -> None:
    r = readiness(stt)
    chips = [
        _chip("Lab running", "ok") if r["running"] else _chip("Lab stopped", "idle"),
        _chip("Prepared", "ok") if r["prepared"] else _chip("Not prepared", "warn"),
        _chip(f"Scenario · {r['active']}", "info") if r["active"] else "",
        _chip(f"Zone · {cfg('zone_size', 'small')}", "idle"),
    ]
    st.markdown(f'<div class="co-strip">{" ".join(c for c in chips if c)}</div>', unsafe_allow_html=True)


def _page_header(mode: str, h: driver.LabHandle, stt: dict) -> None:
    tile = TILES[mode]
    st.markdown(f"## {tile['icon']} {tile['title']}")
    st.caption(tile["pitch"])
    _lab_strip(h, stt)


def _gate(stt: dict, what: str) -> bool:
    """True when the lab is ready; otherwise explain what is missing and offer a way to Setup."""
    r = readiness(stt)
    if r["ready"]:
        return True
    missing = [name for name, ok in (("images", r["images"]), ("signed zones", r["prepared"]),
                                     ("running containers", r["running"])) if not ok]
    st.warning(f"{what} needs a ready lab. Still missing: {', '.join(missing)}.")
    st.button("Go to Setup", on_click=_go, args=("setup",), key=f"gate_{what}", type="primary")
    return False


def _activity_expander(h: driver.LabHandle) -> None:
    with st.expander("Activity log", expanded=False):
        activity_tab(h)


# ─────────────────────────── sidebars ───────────────────────────

def _sidebar_brand(mode: str) -> None:
    st.sidebar.title("Cipherops")
    st.sidebar.caption("MTL DNSSEC Lab")
    if mode != "home":
        st.sidebar.button("← Home", on_click=_go, args=("home",), key="sb_home", width="stretch")
        st.sidebar.markdown("---")


def sidebar_home(h: driver.LabHandle, stt: dict) -> None:
    _sidebar_brand("home")
    st.sidebar.markdown("### How to use this lab")
    st.sidebar.markdown(
        "1. **Setup** (first, once) — pick zone size and scenarios, get the images, "
        "sign the hierarchy, start the lab  \n"
        "2. **Live** — send a lookup, compare cold and warm, read the packets  \n"
        "3. **Benchmark** — name a run and measure scenarios across networks  \n"
        "4. **Compare** — MTL vs SLH-DSA and the other modes, side by side  \n"
        "5. **Reset** — clear only what you choose"
    )
    st.sidebar.markdown("---")
    r = readiness(stt)
    st.sidebar.markdown("### Lab readiness")
    for ok, text in ((r["images"], "Images built"), (r["prepared"], "Zones signed"),
                     (r["running"], "Containers running")):
        st.sidebar.markdown(f"{'🟢' if ok else '⚪'}  {text}")
    if r["active"]:
        st.sidebar.markdown(f"🔵  Scenario **{r['active']}**")
    st.sidebar.markdown("---")
    _hint("Open a tile to see its settings here. Each tile has its own Results view.")
    if st.sidebar.button("Refresh status", width="stretch", key="sb_refresh_home"):
        st.rerun()


def _step_label(n: int, title: str, state: str) -> str:
    mark = {"done": "🟢", "partial": "🟡"}.get(state, "⚪")
    return f"{mark}  **Step {n}** · {title}"


def sidebar_setup(h: driver.LabHandle, stt: dict) -> None:
    _sidebar_brand("setup")
    st.sidebar.markdown("### Setup")

    size_keys = list(driver.ZONE_SIZE_PRESETS.keys())
    size = sb(
        st.sidebar.selectbox, "zone_size", "small", "Zone size", options=size_keys,
        format_func=lambda k: driver.ZONE_SIZE_PRESETS[k]["label"],
        help="Controls how many zones and names are generated. Use Small for a first visit, "
             "or Custom to set the numbers yourself.",
    )
    if size == driver.CUSTOM_SIZE:
        st.sidebar.markdown("**Custom zones**")
        sb(st.sidebar.text_input, "custom_tlds", "test", "TLDs",
           help="Comma-separated, e.g. test, lab. One server per TLD (up to 9).")
        sb(st.sidebar.number_input, "custom_sld_count", 4, "Leaf zones", min_value=1, max_value=200, step=1,
           help="Second-level zones, spread round-robin over the TLDs.")
        sb(st.sidebar.text_input, "custom_sizes", "25, 50", "Names per leaf zone",
           help="Comma-separated; the list repeats across the leaf zones, e.g. 25, 100, 250.")
        sb(st.sidebar.number_input, "custom_servers", 1, "Leaf servers", min_value=1, max_value=9, step=1,
           help="Servers that host the leaf zones (up to 9, and no more than leaf zones).")
        sb(st.sidebar.number_input, "custom_seed", driver.DEFAULT_SEED, "Seed", min_value=0,
           max_value=2**31 - 1, step=1, help="Same numbers and seed give the same zones every time.")
    shape, shape_errors, shape_warnings = _shape()
    if shape_errors:
        for msg in shape_errors:
            st.sidebar.error(msg)
    else:
        _hint(f"{shape['sld_count']} leaf zones · TLDs: {', '.join(shape['tlds'])}")
        for msg in shape_warnings:
            st.sidebar.warning(msg)

    all_sc = list(driver.SCENARIO_ALGS.keys())
    default_sc = [s for s in ("ecdsa", "slh-dsa", "mtl") if s in all_sc]
    sc = sb(
        st.sidebar.multiselect, "scenarios", default_sc, "Scenarios", options=all_sc,
        help="DNSSEC modes to sign. Change this, then run Prepare again.",
    )
    sb(st.sidebar.number_input, "jobs", 2, "Sign jobs", min_value=1, max_value=8,
       help="How many zones to sign in parallel during Prepare.")
    sb(st.sidebar.selectbox, "stack", "draft06", "Image version", options=["draft06"],
       help="Pinned server/tooling build used by the lab.")
    if not sc:
        st.sidebar.warning("Select at least one scenario")

    r = readiness(stt)
    prepared_session = r["prepared"] and prepare_metrics_visible(h)
    st.sidebar.markdown("---")
    st.sidebar.markdown("### Steps")
    _hint("Green means ready. Yellow means found on disk from an earlier session.")

    # —— Step 1: images ——
    st.sidebar.markdown(_step_label(1, "Images", "done" if r["images"] else "none"))
    _hint("Get the DNS server and tooling containers.")
    img_mode = sb(st.sidebar.radio, "image_mode", "Build locally", "Image source",
                  options=["Build locally", "Pull from registry"])
    if img_mode.startswith("Pull"):
        reg = sb(
            st.sidebar.text_input, "registry", "", "Registry", placeholder="ghcr.io/your-org/cipherops",
            help="Pre-built images named cipherops-eco-nsd / unbound / tools.",
        )
        if st.sidebar.button("Pull images", key="btn_pull", width="stretch"):
            activity("step", "Pull images", reg, phase="build", source="compose", h=h)
            with st.spinner("Pulling…"):
                try:
                    t0 = time.perf_counter()
                    log = driver.pull_images(h, reg)
                    secs = time.perf_counter() - t0
                    st.session_state.last_log = log[-8000:]
                    _log_chunks(log, phase="build", source="compose", title="pull")
                    activity("ok", f"Pull done ({secs:.0f}s)", "", phase="build", source="compose", h=h)
                    st.sidebar.success(f"Done · {secs:.0f}s")
                except Exception as e:  # noqa: BLE001
                    st.sidebar.error(str(e)[:800])
                    activity("err", "Pull failed", str(e)[:2000], phase="build", source="compose", h=h)
            st.rerun()
    else:
        if st.sidebar.button("Build images", key="btn_build", width="stretch"):
            activity("step", "Build images", "", phase="build", source="compose", h=h)
            with st.spinner("Building…"):
                try:
                    t0 = time.perf_counter()
                    log = driver.build_images(h)
                    secs = time.perf_counter() - t0
                    st.session_state.last_log = log[-8000:]
                    _log_chunks(log, phase="build", source="compose", title="build")
                    activity("ok", f"Build done ({secs:.0f}s)", "", phase="build", source="compose", h=h)
                    st.sidebar.success(f"Done · {secs:.0f}s")
                except Exception as e:  # noqa: BLE001
                    st.sidebar.error(str(e)[:600])
                    activity("err", "Build failed", str(e)[:2000], phase="build", source="compose", h=h)
            st.rerun()

    # —— Step 2: prepare ——
    prep_state = "done" if prepared_session else ("partial" if r["prepared"] else "none")
    st.sidebar.markdown(_step_label(2, "Prepare", prep_state))
    _hint("Sign the DNS hierarchy for each selected scenario.")
    if st.sidebar.button("Prepare", key="btn_prep", width="stretch", disabled=not sc or bool(shape_errors)):
        _apply_ui_config(h)
        jobs = int(cfg("jobs", 2))
        activity("step", "Prepare", f"size={size} scenarios={sc}", phase="prepare", source="prepare", h=h)
        with st.spinner("Signing…"):
            try:
                t0 = time.perf_counter()
                log = driver.prepare(h, jobs=jobs, scenarios=list(sc))
                secs = time.perf_counter() - t0
                st.session_state.last_log = log[-8000:]
                st.session_state.prepare_wall_s = secs
                st.session_state.show_prepare_metrics = True
                summary = driver.prepare_summary(h, wall_s=secs, scenarios=list(sc))
                st.session_state.prepare_summary = summary
                sess = driver.load_session(h)
                sess["prepare_wall_s"] = secs
                sess["show_prepare_metrics"] = True
                sess["prepare_summary"] = summary
                driver.save_session(h, sess)
                _log_chunks(log, phase="prepare", source="prepare", title="prepare")
                paths = (
                    f"work: `{summary['work_dir']}`\n"
                    f"zones: `{summary['zones_dir']}`\n"
                    f"active: `{summary['active_dir']}`\n"
                    f"compose: `{summary['compose']}`"
                )
                activity("ok", f"Prepare done ({secs:.0f}s)", paths, phase="prepare", source="prepare", h=h)
                st.sidebar.success(f"Done · {secs:.0f}s")
            except Exception as e:  # noqa: BLE001
                st.sidebar.error(str(e)[:600])
                activity("err", "Prepare failed", str(e)[:2000], phase="prepare", source="prepare", h=h)
        st.rerun()

    # —— Step 3: start / stop ——
    st.sidebar.markdown(_step_label(3, "Start", "done" if r["running"] else "none"))
    _hint("Start root, TLD, leaf, and resolver containers. Only one lab runs at a time, "
          "so starting stops any other zone shape.")
    b3a, b3b = st.sidebar.columns(2)
    if b3a.button("Start", key="btn_up", width="stretch"):
        activity("step", "Start lab", "", phase="compose", source="compose", h=h)
        with st.spinner("Starting…"):
            try:
                log = driver.up(h)
                st.session_state.last_log = log[-4000:]
                _log_chunks(log, phase="compose", source="compose", title="up")
                activity("ok", "Lab started", "", phase="compose", source="compose", h=h)
            except Exception as e:  # noqa: BLE001
                st.sidebar.error(str(e)[:600])
                activity("err", "Start failed", str(e)[:2000], phase="compose", source="compose", h=h)
        st.rerun()
    if b3b.button("Stop", key="btn_down", width="stretch"):
        with st.spinner("Stopping…"):
            try:
                driver.down(h)
                activity("ok", "Lab stopped", "", phase="compose", source="compose", h=h)
            except Exception as e:  # noqa: BLE001
                st.sidebar.error(str(e)[:600])
        st.rerun()

    st.sidebar.markdown("---")
    if st.sidebar.button("Refresh", width="stretch", key="sb_refresh_setup"):
        st.rerun()


def sidebar_live(h: driver.LabHandle, stt: dict) -> None:
    _sidebar_brand("live")
    r = readiness(stt)
    st.sidebar.markdown("### Live")

    st.sidebar.markdown(_step_label(1, "Scenario", "done" if r["running"] and r["active"] else "none"))
    _hint("Which signed mode the live servers use right now.")
    scenarios: list[str] = []
    try:
        if h.prepared():
            scenarios = h.scenarios()
    except Exception:  # noqa: BLE001
        scenarios = []
    active = r["active"]
    if scenarios:
        default = active if active in scenarios else scenarios[0]
        scenario = sb(st.sidebar.selectbox, "live_scenario", default, "Active scenario", options=scenarios)
        st.session_state.selected_scenario = scenario
        _hint(SCENARIO_BLURB.get(scenario, ""))
        if r["running"] and scenario and scenario != active:
            udp = int(cfg("udp", 1232))
            activity("step", f"Activate {scenario}", "", phase="activate", source="compose", h=h)
            with st.spinner(f"Switching to {scenario}…"):
                try:
                    msg = driver.activate(h, scenario, udp=udp)
                    st.session_state.query_log = []
                    _log_chunks(msg, phase="activate", source="compose", title="activate")
                    activity("ok", f"{scenario} live", "", phase="activate", source="compose", h=h)
                except Exception as e:  # noqa: BLE001
                    st.sidebar.error(str(e)[:600])
                    activity("err", "Activate failed", str(e)[:2000], phase="activate", source="compose", h=h)
            st.rerun()
        elif not r["running"] and scenario != active:
            _hint("Start the lab in Setup to apply this choice.")
    else:
        _hint("Prepare the lab in Setup first.")

    done_q = bool(st.session_state.get("query_log") or st.session_state.get("last_query"))
    st.sidebar.markdown(_step_label(2, "Query", "done" if done_q else "none"))
    _hint("Use the Query tab to send a lookup; Results shows packets.")

    st.sidebar.markdown("---")
    st.sidebar.markdown("### Capture name")
    label = sb(
        st.sidebar.text_input, "capture_label", "", "Name (optional)",
        placeholder="e.g. mtl-cold-lookup", max_chars=40,
        help="Added to the capture file name, next to the date and time.",
    )
    tag = driver.sanitize_label(label)
    _hint(f"File: live-{tag + '-' if tag else ''}<date>-<time>.pcap")
    st.sidebar.markdown("---")
    if st.sidebar.button("Refresh", width="stretch", key="sb_refresh_live"):
        st.rerun()


def sidebar_benchmark(h: driver.LabHandle, stt: dict) -> None:
    _sidebar_brand("benchmark")
    r = readiness(stt)
    runs = driver.list_runs(h)
    st.sidebar.markdown("### Benchmark")
    mark = "🟢" if runs else "⚪"
    st.sidebar.markdown(f"{mark}  {len(runs)} saved run(s)" if runs else f"{mark}  No run yet")
    _hint(
        "Runs every chosen scenario across the networks you pick (cold cache, then warm). "
        "The lab must be running. This can take a while."
    )

    st.sidebar.markdown("**Run name**")
    label = sb(
        st.sidebar.text_input, "run_label", "", "Name this run",
        placeholder="e.g. panel-demo-wan", max_chars=40,
        help="Stored with the date and time, so you can tell runs apart later.",
    )
    clean = driver.sanitize_label(label)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    _hint(f"Saved as {stamp}{'_' + clean if clean else ''} (time = when you press Run)")
    if label and clean != label.strip():
        _hint("Letters, digits, - and _ only; other characters become -.")

    try:
        available = h.scenarios() if h.prepared() else list(cfg("scenarios") or [])
    except Exception:  # noqa: BLE001
        available = list(cfg("scenarios") or [])
    sc = sb(st.sidebar.multiselect, "bench_scenarios", list(available), "Scenarios to measure",
            options=available, help="Subset of the scenarios prepared in Setup.")
    shape, _errs, _warns = _shape()
    default_nq = int((shape or driver.ZONE_SIZE_PRESETS["custom"])["n_queries_default"])
    sb(st.sidebar.number_input, "n_queries", default_nq, "Queries per trial",
       min_value=10, max_value=5000, help="How many lookups in each cold/warm pass.")
    sb(st.sidebar.number_input, "trials", 1, "Trials", min_value=1, max_value=10,
       help="Each trial repeats a cold pass then a warm pass.")
    nets = sb(st.sidebar.multiselect, "networks", ["lan"], "Networks", options=["lan", "wan", "lossy"],
              help="lan = local · wan = added delay · lossy = delay plus packet loss.")
    sb(st.sidebar.selectbox, "udp", 1232, "UDP size limit", options=[1232, 4096],
       help="Max UDP answer size before falling back to TCP.")

    wl_default = driver.WORKLOAD_DEFAULTS
    with st.sidebar.expander("Workload mix", expanded=False):
        sb(st.number_input, "nx_pct", int(round(wl_default["nx_fraction"] * 100)), "NXDOMAIN share (%)",
           min_value=0, max_value=50, step=1,
           help="Share of lookups for names that do not exist. Every such name is distinct.")
        sb(st.number_input, "zone_zipf", float(wl_default["zone_zipf_s"]), "Zone popularity skew",
           min_value=0.0, max_value=2.0, step=0.1, format="%.1f",
           help="0 = every zone equally likely; higher = a few zones get most lookups.")
        sb(st.number_input, "name_zipf", float(wl_default["name_zipf_s"]), "Name popularity skew",
           min_value=0.0, max_value=2.0, step=0.1, format="%.1f",
           help="Same idea inside a zone. Higher skew means more cache hits.")
        sb(st.number_input, "timeout_s", float(wl_default["timeout_s"]), "Lookup timeout (s)",
           min_value=1.0, max_value=30.0, step=1.0, format="%.0f")
    with st.sidebar.expander("Network profiles", expanded=False):
        st.caption("lan is the zero-delay baseline. Delay is added towards each tier on the resolver; "
                   "loss applies to the resolver's queries. Only the profiles ticked above are run.")
        for prof in EDITABLE_PROFILES:
            base = driver.PROFILE_DEFAULTS[prof]
            st.markdown(f"**{prof}**")
            cols = st.columns(2)
            for i, (field, label) in enumerate(PROFILE_FIELDS):
                with cols[i % 2]:
                    if field == "loss_pct":
                        sb(st.number_input, f"{prof}_{field}", float(base[field]), label,
                           min_value=0.0, max_value=20.0, step=0.5, format="%.1f")
                    else:
                        sb(st.number_input, f"{prof}_{field}", int(base[field]), label,
                           min_value=0, max_value=500, step=1)
    if not _workload_is_default():
        st.sidebar.caption("Custom workload or network numbers are in use.")
        st.sidebar.button("Restore defaults", on_click=_restore_workload, key="btn_restore_wl",
                          width="stretch")

    bad_shape = bool(st.session_state.get("shape_errors"))
    if bad_shape:
        st.sidebar.error("The custom zone numbers in Setup need fixing before a run.")
    if st.sidebar.button("Run benchmark", key="btn_bench", type="primary", width="stretch",
                         disabled=not (sc and nets) or bad_shape):
        if not r["running"]:
            st.sidebar.error("Start the lab in Setup first.")
        else:
            _apply_ui_config(h)
            trials = int(cfg("trials", 1))
            activity("step", f"Benchmark{' · ' + clean if clean else ''}",
                     f"scenarios={sc} profiles={nets} trials={trials}",
                     phase="run", source="compose", h=h)
            with st.spinner("Running benchmark…"):
                try:
                    t0 = time.perf_counter()
                    log = driver.run_benchmark(
                        h, scenarios=list(sc), profiles=list(nets), trials=trials,
                        udp=int(cfg("udp", 1232)), run_label=clean,
                    )
                    secs = time.perf_counter() - t0
                    st.session_state.last_log = log[-8000:]
                    newest = driver.list_runs(h)
                    st.session_state.last_run_dir = str(newest[0]["path"]) if newest else ""
                    if newest:
                        st.session_state.bench_run_pick = newest[0]["folder"]
                    st.session_state.bench_flash = f"Run saved in {secs:.0f}s"
                    _log_chunks(log, phase="run", source="compose", title="benchmark")
                    activity("ok", f"Benchmark done ({secs:.0f}s)", st.session_state.last_run_dir,
                             phase="run", source="compose", h=h)
                except Exception as e:  # noqa: BLE001
                    st.sidebar.error(str(e)[:800])
                    activity("err", "Benchmark failed", str(e)[:2000], phase="run", source="compose", h=h)
            st.rerun()
    st.sidebar.markdown("---")
    if st.sidebar.button("Refresh", width="stretch", key="sb_refresh_bench"):
        st.rerun()


def sidebar_reset(h: driver.LabHandle, stt: dict) -> None:
    _sidebar_brand("reset")
    st.sidebar.markdown("### Reset")
    _hint("Pick what to clear in the main area. Nothing is removed until you press the button.")
    st.sidebar.markdown("**Always kept**")
    st.sidebar.markdown("- Docker images  \n- Configuration files  \n- Repository code")
    st.sidebar.markdown("---")
    if st.sidebar.button("Refresh", width="stretch", key="sb_refresh_reset"):
        st.rerun()


# ─────────────────────────── HOME ───────────────────────────

def _tile_chip(mode: str, stt: dict, h: driver.LabHandle) -> str:
    r = readiness(stt)
    if mode == "setup":
        if r["ready"]:
            return _chip("Ready", "ok")
        if r["count"] == 0:
            return _chip("Start here", "warn")
        return _chip(f"In progress · {r['count']}/3", "info")
    if mode in ("live", "benchmark"):
        if not r["ready"]:
            return _chip("Needs Setup", "warn")
        if mode == "live":
            return _chip(f"Live · {r['active']}", "ok") if r["active"] else _chip("Ready", "ok")
        n = len(driver.list_runs(h))
        return _chip(f"Ready · {n} saved" if n else "Ready", "ok")
    if mode == "compare":
        labs = driver.list_labs()
        return _chip("Has data", "ok") if labs else _chip("No data yet", "idle")
    return _chip("Maintenance", "idle")


def home_page(h: driver.LabHandle, stt: dict) -> None:
    _symbol, full = _brand()
    if full is not None:
        logo_col, title_col = st.columns([1, 4], vertical_alignment="center")
        logo_col.image(full, width=190)
    else:
        title_col = st.container()
    title_col.markdown(
        f'<div class="co-hero"><h1>{APP_NAME}</h1><p class="co-sub">{APP_TAGLINE}</p></div>',
        unsafe_allow_html=True,
    )
    _lab_strip(h, stt)
    if stt.get("error"):
        st.error(f"Could not read lab status: {stt['error']}")

    r = readiness(stt)
    if not r["ready"]:
        st.info("**Start with Setup.** Live and Benchmark need the lab built, signed and running.")

    order = [("setup", "live"), ("benchmark", "compare"), ("reset",)]
    for pair in order:
        cols = st.columns(2)
        for col, mode in zip(cols, pair):
            tile = TILES[mode]
            with col, st.container(border=True):
                # Fixed-height text block so all four tiles (and their buttons) line up,
                # however the copy wraps.
                with st.container(height=TILE_TEXT_HEIGHT, border=False):
                    st.markdown(f"### {tile['icon']} {tile['title']}  {_tile_chip(mode, stt, h)}",
                                unsafe_allow_html=True)
                    st.markdown(f"**{tile['pitch']}**")
                    for b in tile["bullets"]:
                        st.markdown(f"- {b}")
                if mode == "setup":
                    emphasise = not r["ready"]
                elif mode in ("live", "benchmark"):
                    emphasise = r["ready"]
                elif mode == "compare":
                    emphasise = bool(driver.list_labs())
                else:
                    emphasise = False
                st.button(
                    f"{tile['cta']} →", key=f"open_{mode}", on_click=_go, args=(mode,),
                    type="primary" if emphasise else "secondary", width="stretch",
                )


# ─────────────────────────── SETUP ───────────────────────────

def _render_prepare_summary(h: driver.LabHandle) -> None:
    summary = st.session_state.get("prepare_summary")
    if not summary:
        sess = driver.load_session(h)
        summary = sess.get("prepare_summary")
        if summary:
            st.session_state.prepare_summary = summary
    if not summary and h.prepared():
        wall = driver.load_session(h).get("prepare_wall_s")
        summary = driver.prepare_summary(h, wall_s=wall)
        st.session_state.prepare_summary = summary
    if not summary:
        return
    with st.expander("What Prepare created", expanded=True):
        wall = summary.get("wall_s")
        wall_txt = f"{wall:.1f}" if isinstance(wall, (int, float)) else (wall or "—")
        st.markdown(
            f"Signed **{summary.get('lab')}** in **{wall_txt}** s — "
            f"leaf zones first, then TLD, then root. "
            f"Files below are what the running lab serves."
        )
        st.code(
            "\n".join([
                f"work     {summary.get('work_dir')}",
                f"zones    {summary.get('zones_dir')}",
                f"active   {summary.get('active_dir')}",
                f"compose  {summary.get('compose')}",
            ]),
            language="text",
        )
        rows = summary.get("scenarios") or []
        if rows:
            st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)


def planned_lab(h: driver.LabHandle) -> None:
    """The numbers behind the current Setup choice, and the exact config the lab will use."""
    shape, errors, warnings = _shape()
    with st.container(border=True):
        st.markdown("**Planned lab**")
        if errors or shape is None:
            for e in errors:
                st.error(e)
            return
        scenarios = list(cfg("scenarios") or [])
        stats = driver.shape_stats(shape, scenarios, int(cfg("jobs", 2)))
        m = st.columns(5)
        m[0].metric("Zones", stats["zones"], help="Root + TLDs + leaf zones")
        m[1].metric("Leaf names", f"{stats['names']:,}")
        m[2].metric("Containers", stats["containers"], help="Root, TLD and leaf servers, resolver and client")
        m[3].metric("Signatures", f"~{stats['est_rrsigs']:,}", help="RRSIGs per scenario (estimate)")
        m[4].metric("Prepare time", driver.format_duration(stats["est_prepare_s"]),
                    help="Rough estimate from the Medium lab; SLH-DSA dominates.")
        sizes = ", ".join(str(s) for s in shape["sld_sizes"])
        st.caption(
            f"TLDs **{', '.join(shape['tlds'])}** · {shape['sld_count']} leaf zones on "
            f"{shape['sld_servers']} server(s) · names per zone cycle **{sizes}** · "
            f"lab folder **{h.tag}**"
        )
        for w in warnings:
            st.warning(w)
        cfg_path = ECO_DIR / h.config
        if cfg_path.is_file():
            with st.expander("Effective configuration (read-only)"):
                text = cfg_path.read_text(encoding="utf-8")
                st.code(text, language="yaml")
                st.download_button("Download YAML", data=text, file_name=f"{h.lab}.yaml",
                                   mime="text/yaml", key="cfg_dl")


def setup_overview(h: driver.LabHandle, stt: dict) -> None:
    imgs = stt.get("images") or {}
    containers = stt.get("containers") or {}
    r = readiness(stt)

    c = st.columns(4)
    c[0].metric("Docker images", f"{sum(imgs.values())}/{len(imgs) or 3}")
    c[1].metric("Prepared", "yes" if r["prepared"] else "no")
    c[2].metric("Containers up", str(sum(1 for v in containers.values() if v)))
    c[3].metric("Scenario", r["active"] or "—")
    st.caption(
        f"Lab **{h.lab}** · zone size **{cfg('zone_size', 'small')}** · "
        f"scenarios **{', '.join(cfg('scenarios') or [])}**"
    )

    if r["ready"]:
        with st.container(border=True):
            st.success("Setup complete. The lab is signed, running and ready.")
            a, b, _ = st.columns([1, 1, 2])
            a.button("Continue to Live →", on_click=_go, args=("live",), key="setup_to_live",
                     type="primary", width="stretch")
            b.button("Continue to Benchmark →", on_click=_go, args=("benchmark",),
                     key="setup_to_bench", width="stretch")
    else:
        nxt = ("Build or pull the images (Step 1)" if not r["images"]
               else "Run Prepare to sign the zones (Step 2)" if not r["prepared"]
               else "Press Start to launch the containers (Step 3)")
        st.info(f"**Next:** {nxt} — use the sidebar.")

    planned_lab(h)

    left, right = st.columns(2)
    with left:
        st.markdown("**Images**")
        for name, ok in imgs.items():
            repo = name.split(":")[0]
            tag = name.split(":")[1] if ":" in name else ""
            st.write(("🟢" if ok else "🔴"), IMAGE_LABELS.get(repo, repo) + (f" · {tag}" if tag else ""))
    with right:
        st.markdown("**Running services**")
        if containers:
            for name, ok in sorted(containers.items()):
                st.write(("🟢" if ok else "🔴"), name)
        else:
            st.caption("No services yet.")


def setup_results(h: driver.LabHandle) -> None:
    if not (prepare_metrics_visible(h) and h.prepared()):
        st.info("Signing results appear here after you run Prepare.")
        return
    _render_prepare_summary(h)
    rows = driver.manifest_rows(h)
    if not rows:
        return
    df = pd.DataFrame(rows)
    scenarios = sorted(df["scenario"].unique())
    pick = st.multiselect("Scenarios", scenarios, default=scenarios, key="setup_res_pick")
    view = df[df["scenario"].isin(pick)] if pick else df
    wall = st.session_state.get("prepare_wall_s") or driver.load_session(h).get("prepare_wall_s")
    if wall:
        st.metric("Prepare wall", f"{wall:.1f}s")
    st.dataframe(
        view[["scenario", "tier", "origin", "sign_seconds", "verify_seconds", "signed_bytes", "rrsig_count"]],
        width="stretch", hide_index=True,
    )
    agg = view.groupby("scenario", as_index=False).agg(
        sign_seconds=("sign_seconds", "sum"), verify_seconds=("verify_seconds", "sum"),
    )
    c1, c2 = st.columns(2)
    c1.plotly_chart(px.bar(agg, x="scenario", y="sign_seconds", title="Sign (s)"), width="stretch")
    c2.plotly_chart(px.bar(agg, x="scenario", y="verify_seconds", title="Zone verify (s)"),
                    width="stretch")


def setup_page(h: driver.LabHandle, stt: dict) -> None:
    _page_header("setup", h, stt)
    overview, results = st.tabs(["Overview", "Results"])
    with overview:
        setup_overview(h, stt)
    with results:
        setup_results(h)
    _activity_expander(h)


# ─────────────────────────── LIVE ───────────────────────────

def show_sequence_diagram(steps: list) -> None:
    """Interactive sequence (Plotly hover) plus optional PNG download."""
    if not steps:
        st.warning("Could not build a sequence from this capture’s DNS hops.")
        return

    summary = decode.sequence_summary(steps)
    m = st.columns(5)
    m[0].metric("Messages", summary["messages"])
    m[1].metric("Client B", f"{summary['client_bytes']:,}")
    m[2].metric("Max answer", decode.format_bytes(summary["max_bytes"]))
    m[3].metric("Span", f"{summary['span_ms']} ms")
    m[4].metric("MTL-FULL", summary["mtl_full"])
    st.caption(
        "Solid = query · dashed = response · amber = MTL-FULL. "
        "Hover an arrow for exact bytes, t (capture offset), and Δ (gap since prior step)."
    )

    try:
        st.plotly_chart(
            decode.sequence_plotly_figure(steps),
            width="stretch",
            theme=None,  # keep dark ink; Streamlit theme was painting legend/hover white-on-white
            config={"displayModeBar": False},
        )
    except Exception as e:  # noqa: BLE001
        st.error(f"Diagram failed: {e}")
        return

    table_rows = []
    for i, s in enumerate(steps, 1):
        delta = s.get("delta_ms")
        table_rows.append({
            "#": i,
            "Message": s.get("label") or "",
            "Hop": f"{s.get('src')} → {s.get('dst')}",
            "Bytes": int(s.get("bytes") or 0),
            "Size": decode.format_bytes(s.get("bytes")),
            "t (ms)": s.get("ms"),
            "Δ (ms)": "—" if delta is None else f"{float(delta):g}",
            "Phase": s.get("phase_label") or s.get("phase") or "",
        })
    st.dataframe(pd.DataFrame(table_rows), width="stretch", hide_index=True,
                 height=min(360, 80 + 28 * len(table_rows)))

    try:
        png = decode.sequence_png_bytes(steps)
        st.download_button("Download PNG", data=png, file_name="cipherops-sequence.png",
                           mime="image/png", key="seq_png_dl")
    except Exception:  # noqa: BLE001
        pass


def query_panel(h: driver.LabHandle, stt: dict) -> None:
    st.caption("Send one DNS lookup. Enable Capture to inspect packets afterward.")
    if not _gate(stt, "Querying"):
        return

    presets = driver.query_presets(h)
    st.session_state._presets_list = presets
    if "qname_in" not in st.session_state:
        st.session_state.qname_in = presets[2][0]
        st.session_state.qtype_in = presets[2][1]
        st.session_state.preset_idx = 2

    def _on_preset() -> None:
        i = min(int(st.session_state.get("preset_idx", 0)), len(presets) - 1)
        st.session_state.qname_in = presets[i][0]
        st.session_state.qtype_in = presets[i][1]

    st.selectbox(
        "Preset", list(range(len(presets))),
        format_func=lambda i: f"{presets[i][0]} {presets[i][1]}",
        key="preset_idx", on_change=_on_preset,
    )
    qname = st.text_input("QNAME", key="qname_in")
    qtype = st.text_input("QTYPE", key="qtype_in")
    path = st.radio("Path", ["Through Unbound", "Direct to root", "Direct to SLD"], horizontal=True)
    server = {
        "Through Unbound": "10.53.0.53",
        "Direct to root": "10.53.0.2",
        "Direct to SLD": driver.sld_server_ip(h),
    }[path]
    recurse = path.startswith("Through")
    if path.startswith("Direct to SLD") and (
        qname.strip() in (".", "") or (qtype.upper() == "DNSKEY" and qname.rstrip(".").count(".") == 0)
    ):
        st.warning("Direct-to-leaf works for host names, not for root DNSKEY queries.")

    c1, c2, c3 = st.columns(3)
    dnssec = c1.checkbox("DO (DNSSEC RRs)", value=True)
    mtl_full = c2.checkbox("MTL-FULL", value=False)
    capture = c3.checkbox("Capture", value=True)
    if capture:
        sniffer = "unbound (full chain)" if recurse else "client (direct to auth — no Unbound hops)"
        st.caption(f"Recording packets on **{sniffer}**")

    if st.button("Run query", type="primary"):
        pcap_path = None
        activity("step", f"Query {qname} {qtype}", path, phase="probe", source="probe", h=h)
        try:
            if recurse:
                try:
                    driver.unbound_stats(h)
                except Exception:  # noqa: BLE001
                    pass
            if capture:
                pcap_path = driver.start_capture(h, server=server, label=cfg("capture_label", ""))
            row = driver.probe(
                h, qname, qtype, server=server, mtl_full=mtl_full, dnssec=dnssec, recurse=recurse,
            )
            if recurse:
                try:
                    row["unbound_stats"] = driver.unbound_stats_delta({}, driver.unbound_stats(h))
                except Exception:  # noqa: BLE001
                    row["unbound_stats"] = {}
            dropped = 0
            if capture:
                pcap_path, dropped = driver.stop_capture(h)
                if pcap_path and Path(pcap_path).exists():
                    try:
                        df = decode.decode_pcap(pcap_path)
                        st.session_state.last_story = decode.build_story(df)
                        st.session_state.last_wire = decode.wire_summary(df)
                        st.session_state.auto_decode = True
                        activity("info", "Packet story", "\n".join((st.session_state.last_story or [])[:10]),
                                 phase="pcap", source="pcap", h=h)
                    except Exception:  # noqa: BLE001
                        pass
                try:
                    _log_chunks(driver.container_logs(h, "unbound", 40),
                                phase="probe", source="unbound", title="unbound")
                except Exception:  # noqa: BLE001
                    pass

            st.session_state.last_query = row
            st.session_state.last_pcap = str(pcap_path) if pcap_path else None
            st.session_state.last_dropped = dropped
            st.session_state.last_stats = row.get("unbound_stats") or {}
            st.session_state.setdefault("query_log", []).append({**row, "pcap": st.session_state.last_pcap})
            driver.append_session_query(h, {**row, "pcap": st.session_state.last_pcap})
            size = row.get("tcp_response_bytes") or row.get("response_bytes") or 0
            activity(
                "ok",
                f"{row.get('rcode')} · AD={'yes' if row.get('ad') else 'no'} · {size:,} B",
                f"{row.get('latency_ms', 0):.1f} ms",
                phase="probe", source="probe", h=h,
            )
        except Exception as e:  # noqa: BLE001
            st.error(str(e)[:800])
            activity("err", "Query failed", str(e)[:2000], phase="probe", source="probe", h=h)
            if capture:
                try:
                    driver.stop_capture(h)
                except Exception:  # noqa: BLE001
                    pass

    row = st.session_state.get("last_query")
    if row:
        m = st.columns(5)
        m[0].metric("RCODE", row.get("rcode", "—"))
        m[1].metric("AD", "YES" if row.get("ad") else "no")
        m[2].metric("Transport", row.get("transport", "—"))
        m[3].metric("Bytes", f"{(row.get('tcp_response_bytes') or row.get('response_bytes') or 0):,}")
        m[4].metric("Latency", f"{row.get('latency_ms', 0):.1f} ms")
        st.caption("Full history, packet decode and sequence diagram are in the Results tab.")


def cache_panel(h: driver.LabHandle, stt: dict) -> None:
    st.caption("Compare a first lookup (cold cache) with repeats (warm cache).")
    if not _gate(stt, "Cold vs warm"):
        return
    presets = driver.query_presets(h)
    qname = st.text_input("QNAME", presets[2][0] if len(presets) > 2 else "host000000.zone00.test.", key="cache_q")
    qtype = st.text_input("QTYPE", "A", key="cache_t")
    if st.button("Run cold then warm ×3"):
        activity("step", "Cold/warm", qname, phase="cache", source="unbound", h=h)
        try:
            with st.spinner("Flushing…"):
                driver.flush(h)
            try:
                driver.unbound_stats(h)
            except Exception:  # noqa: BLE001
                pass
            cold = driver.probe(h, qname, qtype)
            try:
                cold_stats = driver.unbound_stats_delta({}, driver.unbound_stats(h))
            except Exception:  # noqa: BLE001
                cold_stats = {}
            warms, warm_stats = [], []
            for _ in range(3):
                try:
                    driver.unbound_stats(h)
                except Exception:  # noqa: BLE001
                    pass
                warms.append(driver.probe(h, qname, qtype))
                try:
                    warm_stats.append(driver.unbound_stats_delta({}, driver.unbound_stats(h)))
                except Exception:  # noqa: BLE001
                    warm_stats.append({})
            st.session_state.cache_result = {
                "cold": cold, "warms": warms, "cold_stats": cold_stats, "warm_stats": warm_stats,
            }
            sess = driver.load_session(h)
            sess["cold_warm"] = st.session_state.cache_result
            driver.save_session(h, sess)
            activity("ok", "Cold/warm done", "", phase="cache", source="unbound", h=h)
        except Exception as e:  # noqa: BLE001
            st.error(str(e)[:600])
    _cache_result_view()


def _cache_result_view() -> None:
    res = st.session_state.get("cache_result")
    if not res:
        return
    c, w = res["cold"], res["warms"]
    wmed = float(pd.Series([x["latency_ms"] for x in w]).median())
    a, b, d = st.columns(3)
    a.metric("Cold", f"{c['latency_ms']:.1f} ms")
    b.metric("Warm median", f"{wmed:.1f} ms")
    d.metric("AD", "YES" if c.get("ad") and all(x.get("ad") for x in w) else "mixed/no")
    rows = [{
        "pass": "cold", "ms": c["latency_ms"], "ad": c.get("ad"),
        "hits": (res.get("cold_stats") or {}).get("total.num.cachehits"),
        "miss": (res.get("cold_stats") or {}).get("total.num.cachemiss"),
    }]
    for i, x in enumerate(w, 1):
        ws = (res.get("warm_stats") or [{}])[i - 1] if i - 1 < len(res.get("warm_stats") or []) else {}
        rows.append({
            "pass": f"warm{i}", "ms": x["latency_ms"], "ad": x.get("ad"),
            "hits": ws.get("total.num.cachehits"), "miss": ws.get("total.num.cachemiss"),
        })
    st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)


def _pcap_options(h: driver.LabHandle) -> list[str]:
    captures = sorted(h.capture_dir.glob("*.pcap"), key=lambda p: p.stat().st_mtime, reverse=True)
    options = [str(p) for p in captures]
    last = st.session_state.get("last_pcap")
    if last and last not in options and Path(last).exists():
        options = [last] + options
    return options


def _pcap_name(p: str) -> str:
    return Path(p).name


def pcap_decode_view(h: driver.LabHandle, options: list[str]) -> None:
    if not options:
        st.caption("No captures yet — run a Live query with Capture on.")
        return
    choice = st.selectbox("Capture", options, index=0, key="pcap_story_choice", format_func=_pcap_name)
    hide_tcp = st.checkbox("Hide TCP handshake noise", value=True, key="pcap_hide_tcp")
    if st.button("Decode", key="pcap_story_decode") or st.session_state.get("auto_decode"):
        st.session_state.auto_decode = False
        df = decode.decode_pcap(choice)
        if df.empty:
            st.warning("This capture has no DNS packets.")
            return
        wire = decode.wire_summary(df)
        story = decode.build_story(df)
        w = st.columns(4)
        w[0].metric("Packets", wire["packets"])
        w[1].metric("Client B", f"{wire['client_bytes']:,}")
        w[2].metric("Upstream B", f"{wire['upstream_bytes']:,}")
        w[3].metric("MTL-FULL", wire["mtl_full_packets"])
        st.markdown("**What happened**")
        for line in story:
            st.markdown(line)
        show = df[df["phase"] != "tcp_noise"] if hide_tcp and "phase" in df.columns else df
        cols = [c for c in ["#", "ms", "phase_label", "hop", "proto", "bytes", "summary", "ad", "rrsigs"]
                if c in show.columns]
        st.dataframe(show[cols], width="stretch", hide_index=True, height=360)


def pcap_sequence_view(h: driver.LabHandle, options: list[str]) -> None:
    if not options:
        st.caption("No captures yet — run a Live query with Capture on.")
        return
    # Prefer Capture-decode selection, then last lab capture, then last sequence.
    idx = 0
    for pref in (
        st.session_state.get("pcap_story_choice"),
        st.session_state.get("last_pcap"),
        st.session_state.get("last_seq_pcap"),
    ):
        if pref in options:
            idx = options.index(pref)
            break
    seq_choice = st.selectbox("Capture", options, index=idx, key="pcap_seq_choice", format_func=_pcap_name)
    if st.button("Show sequence", key="pcap_seq_decode", type="primary"):
        df = decode.decode_pcap(seq_choice)
        if df.empty:
            st.warning("This capture has no DNS packets.")
            st.session_state.pop("last_seq_steps", None)
            st.session_state.pop("last_seq_pcap", None)
        else:
            steps = decode.build_sequence_steps(df)
            st.session_state.last_seq_steps = steps
            st.session_state.last_seq_pcap = seq_choice
            if not steps:
                st.warning(
                    "Decoded the capture, but no Client/Unbound/Root/TLD/SLD hops "
                    "were recognized for a sequence diagram."
                )
    steps = st.session_state.get("last_seq_steps")
    shown_pcap = st.session_state.get("last_seq_pcap") or seq_choice
    if steps and st.session_state.get("last_seq_pcap") == seq_choice:
        st.caption(f"{Path(shown_pcap).name} · {len(steps)} messages from this capture")
        show_sequence_diagram(steps)
    elif steps and st.session_state.get("last_seq_pcap") != seq_choice:
        st.caption(
            f"Showing last sequence ({Path(st.session_state.last_seq_pcap).name}). "
            "Click Show sequence to rebuild for the selected capture."
        )
        show_sequence_diagram(steps)
    elif st.session_state.get("last_seq_pcap"):
        st.caption("No sequence steps for the last decode.")
    else:
        st.caption("Choose a capture and click Show sequence.")


def live_results(h: driver.LabHandle) -> None:
    queries, packets, sequence = st.tabs(["Queries", "Packet decode", "Sequence diagram"])
    options = _pcap_options(h)
    with queries:
        qlog = driver.session_queries(
            h, st.session_state.query_log if "query_log" in st.session_state else None,
        )
        if qlog:
            qdf = pd.DataFrame(qlog)
            cols = [c for c in ["qname", "qtype", "rcode", "ad", "latency_ms", "response_bytes",
                                "tcp_response_bytes", "transport"] if c in qdf.columns]
            st.dataframe(qdf[cols], width="stretch", hide_index=True)
        else:
            st.caption("No queries yet — send one from the Query tab.")
        row = st.session_state.get("last_query") or {}
        if row.get("rrsigs"):
            st.markdown("**Signatures in the last answer**")
            st.dataframe(pd.DataFrame(row["rrsigs"]), width="stretch", hide_index=True)
        stats = st.session_state.get("last_stats") or {}
        if stats:
            with st.expander("Resolver counters for the last query"):
                s = st.columns(4)
                s[0].metric("Cache hits", int(stats.get("total.num.cachehits") or 0))
                s[1].metric("Cache miss", int(stats.get("total.num.cachemiss") or 0))
                s[2].metric("Secure", int(stats.get("total.num.answer.secure") or 0))
                s[3].metric("Recursion s", f"{stats.get('total.recursion.time.avg') or 0:.4f}")
                st.json(stats)
        if st.session_state.get("cache_result"):
            st.markdown("**Cold vs warm**")
            _cache_result_view()
    with packets:
        pcap_decode_view(h, options)
    with sequence:
        pcap_sequence_view(h, options)


def live_page(h: driver.LabHandle, stt: dict) -> None:
    _page_header("live", h, stt)
    query, cache, results = st.tabs(["Query", "Cold vs warm", "Results"])
    with query:
        query_panel(h, stt)
    with cache:
        cache_panel(h, stt)
    with results:
        live_results(h)
    _activity_expander(h)


# ─────────────────────────── BENCHMARK ───────────────────────────

def _bench_plan(h: driver.LabHandle) -> None:
    sc = list(cfg("bench_scenarios") or cfg("scenarios") or [])
    nets = list(cfg("networks") or ["lan"])
    trials = int(cfg("trials", 1))
    nq = int(cfg("n_queries", 40))
    passes = len(sc) * len(nets) * trials * 2
    label = driver.sanitize_label(cfg("run_label", ""))
    with st.container(border=True):
        st.markdown("**Planned run**")
        a = st.columns(4)
        a[0].metric("Scenarios", len(sc))
        a[1].metric("Networks", len(nets))
        a[2].metric("Trials", trials)
        a[3].metric("Queries / pass", nq)
        st.caption(
            f"{passes} capture passes (cold then warm) ≈ **{passes * nq:,}** lookups · "
            f"name **{label or '(none — date and time only)'}** · UDP limit {cfg('udp', 1232)}"
        )
        st.caption(f"Scenarios: {', '.join(sc) or '—'} · Networks: {', '.join(nets)}")
        w = _workload()
        st.caption(
            f"Workload: NXDOMAIN **{round(w['nx_fraction'] * 100)}%** · zone skew **{w['zone_zipf_s']:g}** · "
            f"name skew **{w['name_zipf_s']:g}** · timeout **{w['timeout_s']:g} s**"
            + ("" if _workload_is_default() else " · _custom values_")
        )
        shown = {p: {**driver.PROFILE_DEFAULTS[p], **_profiles().get(p, {})} for p in nets}
        if shown:
            st.dataframe(
                pd.DataFrame(shown).T.rename(columns=dict(PROFILE_FIELDS)).rename_axis("network"),
                width="stretch",
            )


def benchmark_run(h: driver.LabHandle, stt: dict) -> None:
    if not _gate(stt, "Benchmarking"):
        return
    st.caption("Set the options in the sidebar, then press **Run benchmark**. Results land in the Results tab.")
    _bench_plan(h)
    log = st.session_state.get("last_log")
    if log and st.session_state.get("last_run_dir"):
        with st.expander("Output of the last benchmark"):
            st.code(log[-4000:], language="text")


def _bench_charts(summary: pd.DataFrame) -> None:
    if summary.empty:
        return
    base = {"x": "scenario", "color": "pass", "barmode": "group"}
    facet = {"facet_col": "profile"} if "profile" in summary and summary["profile"].nunique() > 1 else {}
    if "median_ms" in summary:
        st.plotly_chart(
            px.bar(summary, y="median_ms", title="Median lookup time (ms)", **base, **facet),
            width="stretch",
        )
    if "upstream_bytes" in summary:
        st.plotly_chart(
            px.bar(summary, y="upstream_bytes", title="Upstream bytes per pass", **base, **facet),
            width="stretch",
        )


def _run_settings(run: dict) -> None:
    """The numbers a saved run was measured with, read from its run.json."""
    c = run.get("cfg") or {}
    hier, wl = c.get("hierarchy") or {}, c.get("workload") or {}
    if not hier and not wl:
        return
    with st.expander("Settings used for this run"):
        if hier:
            st.markdown(
                f"**Zones** · TLDs {', '.join(hier.get('tlds', []))} · {hier.get('sld_count')} leaf zones on "
                f"{hier.get('sld_servers')} server(s) · names per zone {hier.get('sld_sizes')} · "
                f"seed {c.get('seed')}"
            )
        if wl:
            st.markdown(
                f"**Workload** · {wl.get('n_queries')} lookups per pass · NXDOMAIN "
                f"{round(float(wl.get('nx_fraction', 0)) * 100)}% · zone skew {wl.get('zone_zipf_s')} · "
                f"name skew {wl.get('name_zipf_s')} · timeout {wl.get('timeout_s')} s"
            )
        profiles = (c.get("network") or {}).get("profiles") or {}
        used = {p: profiles[p] for p in run.get("profiles", []) if p in profiles}
        if used:
            st.dataframe(pd.DataFrame(used).T.rename_axis("network"), width="stretch")


def benchmark_results(h: driver.LabHandle) -> None:
    runs = driver.list_runs(h)
    st.caption(f"Saved runs for lab **{h.tag}**. Change zone size in Setup to see other labs.")
    flash = st.session_state.pop("bench_flash", None)
    if flash:
        st.success(flash)
    if not runs:
        st.info("No saved runs yet. Name a run in the sidebar and press **Run benchmark**.")
        return

    by_folder = {r["folder"]: r for r in runs}
    folders = list(by_folder)
    if st.session_state.get("bench_run_pick") not in by_folder:
        st.session_state.pop("bench_run_pick", None)
    pick = st.selectbox("Run", folders, key="bench_run_pick", format_func=lambda f: by_folder[f]["title"])
    run = by_folder[pick]
    run_dir: Path = run["path"]

    m = st.columns(4)
    m[0].metric("Name", run["label"] or "—")
    m[1].metric("Started", run["when"])
    m[2].metric("Scenarios", len(run["scenarios"]) or "—")
    m[3].metric("Trials", run["trials"] if run["trials"] is not None else "—")
    st.caption(f"{run['folder']} · networks: {', '.join(run['profiles']) or '—'}")
    _run_settings(run)

    summary_csv = run_dir / "summary.csv"
    if summary_csv.is_file():
        try:
            summary = pd.read_csv(summary_csv)
        except Exception:  # noqa: BLE001
            summary = pd.DataFrame()
        if not summary.empty:
            st.markdown("**Summary**")
            show_cols = [c for c in ["scenario", "profile", "pass", "udp_limit", "trials", "median_ms", "p95_ms",
                                     "upstream_bytes", "upstream_queries", "upstream_truncated",
                                     "validated_pct", "servfail", "timeouts"] if c in summary.columns]
            st.dataframe(summary[show_cols], width="stretch", hide_index=True)
            _bench_charts(summary)
            st.download_button("Download summary.csv", data=summary_csv.read_bytes(),
                               file_name=f"{run['folder']}-summary.csv", mime="text/csv", key="bench_dl")
            return
    # No summary yet: run is unfinished or failed — show what exists.
    for name in ("passes.csv", "queries.csv"):
        f = run_dir / name
        if f.is_file():
            st.markdown(f"`{name}` (partial)")
            try:
                st.dataframe(pd.read_csv(f).head(50), width="stretch", hide_index=True)
            except Exception:  # noqa: BLE001
                st.caption("Could not read CSV")
            return
    files = sorted(p.name for p in run_dir.iterdir() if p.is_file())[:20]
    st.caption(("Files: " + ", ".join(files)) if files else "Empty run folder.")


def benchmark_page(h: driver.LabHandle, stt: dict) -> None:
    _page_header("benchmark", h, stt)
    run_tab, results = st.tabs(["Run", "Results"])
    with run_tab:
        benchmark_run(h, stt)
    with results:
        benchmark_results(h)
    _activity_expander(h)


# ─────────────────────────── COMPARE ───────────────────────────

def _cmp_summary(tag: str | None, folder: str | None) -> pd.DataFrame | None:
    if not tag or not folder:
        return None
    f = ECO_DIR / "results" / tag / folder / "summary.csv"
    if not f.is_file():
        return None
    try:
        return pd.read_csv(f)
    except Exception:  # noqa: BLE001
        return None


def sidebar_compare(h: driver.LabHandle, stt: dict) -> None:
    _sidebar_brand("compare")
    st.sidebar.markdown("### Compare")
    _hint("Signing numbers come from the lab's last Prepare; bytes and cache from a saved benchmark run.")

    labs = [x["tag"] for x in driver.list_labs()]
    default_lab = h.tag if h.tag in labs else (labs[0] if labs else h.tag)
    tag = sb(st.sidebar.selectbox, "cmp_lab", default_lab, "Lab", options=labs or [h.tag],
             help="Any lab folder that has signing data or saved runs.")

    runs = [r for r in driver.list_runs(h, tag) if (r["path"] / "summary.csv").is_file()]
    by = {r["folder"]: r for r in runs}
    folder = sb(st.sidebar.selectbox, "cmp_run", next(iter(by), None), "Benchmark run", options=list(by),
                format_func=lambda f: by[f]["title"], help="Bytes, truncation, cache and latency come from this run.")
    summary = _cmp_summary(tag, folder)

    if summary is not None and not summary.empty:
        profiles = [str(p) for p in summary["profile"].dropna().unique()] if "profile" in summary else []
        sb(st.sidebar.selectbox, "cmp_profile", profiles[0] if profiles else None, "Network", options=profiles)
        udps = [int(u) for u in summary["udp_limit"].dropna().unique()] if "udp_limit" in summary else []
        sb(st.sidebar.selectbox, "cmp_udp", udps[0] if udps else None, "UDP size limit", options=udps)

    sign = compare.signing_by_scenario(driver.manifest_rows(h, tag))
    names = list(sign.scenario) + (list(summary["scenario"].unique()) if summary is not None else [])
    scenarios = compare.order_scenarios(names)
    st.sidebar.markdown("---")
    st.sidebar.markdown("**Compare**")
    cand = sb(st.sidebar.selectbox, "cmp_cand", "mtl" if "mtl" in scenarios else (scenarios[-1] if scenarios else None),
              "Candidate", options=scenarios)
    others = [s for s in scenarios if s != cand]
    sb(st.sidebar.selectbox, "cmp_base", "slh-dsa" if "slh-dsa" in others else (others[0] if others else None),
       "against baseline", options=others)
    st.sidebar.markdown("---")
    if st.sidebar.button("Refresh", width="stretch", key="sb_refresh_cmp"):
        st.rerun()


def _plot_cfg(fig, height: int = 360):
    fig.update_layout(height=height, margin=dict(l=10, r=10, t=50, b=10), legend_title_text="")
    return fig


def compare_page(h: driver.LabHandle, stt: dict) -> None:
    _page_header("compare", h, stt)
    tag, folder = cfg("cmp_lab"), cfg("cmp_run")
    base, cand = cfg("cmp_base"), cfg("cmp_cand")

    man_rows = driver.manifest_rows(h, tag)
    sign = compare.signing_by_scenario(man_rows)
    summary = _cmp_summary(tag, folder)
    bench = compare.bench_by_scenario(summary, cfg("cmp_profile"), cfg("cmp_udp")) if summary is not None \
        else compare.bench_by_scenario(pd.DataFrame())
    df = compare.merge(sign, bench, compare.analytical_by_scenario(man_rows))

    if df.empty:
        st.info("Nothing to compare yet. Run **Prepare** in Setup for signing numbers and a **benchmark** for "
                "bytes and cache.")
        a, b, _ = st.columns([1, 1, 2])
        a.button("Go to Setup", on_click=_go, args=("setup",), key="cmp_to_setup", width="stretch")
        b.button("Go to Benchmark", on_click=_go, args=("benchmark",), key="cmp_to_bench", width="stretch")
        return

    run_title = next((r["title"] for r in driver.list_runs(h, tag) if r["folder"] == folder), None)
    src_sign = f"last Prepare of **{tag}**" if not sign.empty else "no signing data for this lab"
    src_bench = f"run **{run_title}** ({cfg('cmp_profile')}, UDP {cfg('cmp_udp')})" if not bench.empty \
        else "no benchmark run with results for this lab"
    st.caption(f"Signing and verification: {src_sign} · Bytes, truncation, cache: {src_bench}")

    if not (base and cand):
        st.warning("Pick a candidate and a baseline in the sidebar.")
        return

    st.markdown(f"#### {cand} vs {base}")
    cards = compare.headline(df, base, cand)
    cols = st.columns(len(cards))
    for col, c in zip(cols, cards):
        col.metric(c["label"], c["value"], c["delta"], delta_color="off", delta_arrow="off", help=c["help"])
    missing = [c["label"] for c in cards if c["value"] == "—"]
    if missing:
        st.caption("No data for: " + ", ".join(missing) + ". "
                   "Signing and verification need Prepare for both scenarios; the rest need both in the benchmark run.")

    glance, signing, wire, cache, allnums = st.tabs(
        ["At a glance", "Signing & size", "Bytes on the wire", "Cache & latency", "All numbers"])

    scen_order = list(df.scenario)
    colors = compare.COLORS

    with glance:
        metrics = [("Signing time", "sign_s"), ("Verification", "verify_s"), ("Signed size", "signed_bytes"),
                   ("Bytes on the wire", "upstream_bytes"), ("RRset cache", "cache_rrset")]
        rel_rows = []
        for _, r in df.iterrows():
            for label, col in metrics:
                b = df.loc[df.scenario == base, col]
                b = float(b.iloc[0]) if len(b) and pd.notna(b.iloc[0]) else None
                v = r.get(col)
                if b and b > 0 and pd.notna(v) and v > 0:
                    rel_rows.append({"Metric": label, "Scenario": r.scenario, "% of baseline": 100 * v / b})
        if rel_rows:
            fig = px.bar(pd.DataFrame(rel_rows), x="Metric", y="% of baseline", color="Scenario", barmode="group",
                         log_y=True, color_discrete_map=colors, category_orders={"Scenario": scen_order},
                         title=f"Everything relative to {base} (= 100%, log scale; lower is better)")
            fig.add_hline(y=100, line_dash="dot", annotation_text=base)
            st.plotly_chart(_plot_cfg(fig, 420), width="stretch")
        st.caption(
            "SLH-DSA signs every RRset with a post-quantum signature. MTL appends RRsets to a Merkle tree and "
            "signs the tree's ladder once, so signing is cheaper and signatures on the wire are much shorter."
        )

    with signing:
        st.markdown(":green-badge[Measured] from the last Prepare")
        sg = df.dropna(subset=["sign_s"]) if "sign_s" in df else df
        if sg.empty:
            st.info("No signing data: run Prepare in Setup.")
        else:
            c1, c2 = st.columns(2)
            long = sg.melt(id_vars="scenario", value_vars=["sign_s", "verify_s"], var_name="what", value_name="seconds")
            long["what"] = long["what"].map({"sign_s": "Sign zones", "verify_s": "Verify zones"})
            f1 = px.bar(long, x="scenario", y="seconds", color="what", barmode="group", log_y=True,
                        category_orders={"scenario": scen_order}, title="Signing and verification time (s, log)")
            c1.plotly_chart(_plot_cfg(f1), width="stretch")
            sz = sg.assign(MB=sg.signed_bytes / 1024 ** 2)
            f2 = px.bar(sz, x="scenario", y="MB", color="scenario", color_discrete_map=colors,
                        category_orders={"scenario": scen_order}, title="Signed zone size (MB)", text_auto=".2f")
            f2.update_layout(showlegend=False)
            c2.plotly_chart(_plot_cfg(f2), width="stretch")
            f3 = px.bar(sg, x="scenario", y="sign_ms_per_rrsig", color="scenario", color_discrete_map=colors,
                        category_orders={"scenario": scen_order}, log_y=True,
                        title="Sign time per RRSIG (ms, log)", text_auto=".3g")
            f3.update_layout(showlegend=False)
            st.plotly_chart(_plot_cfg(f3, 320), width="stretch")
            st.caption("Verification here is `ldns-verify-zone` over every signed zone (an offline check). "
                       "How long a resolver takes to validate is part of the cold-pass latency under Cache & latency.")

    with wire:
        st.markdown(":green-badge[Measured] from packet counts in the saved run")
        bw = df.dropna(subset=["upstream_bytes"]) if "upstream_bytes" in df else df
        if bw.empty:
            st.info("No benchmark data: run a benchmark in the Benchmark tile.")
        else:
            c1, c2 = st.columns(2)
            hops = bw.melt(id_vars="scenario", value_vars=["root_bytes", "tld_bytes", "sld_bytes"],
                           var_name="hop", value_name="bytes")
            hops["hop"] = hops["hop"].map({"root_bytes": "Root", "tld_bytes": "TLD", "sld_bytes": "Leaf"})
            hops["KB"] = hops["bytes"] / 1024
            f1 = px.bar(hops, x="scenario", y="KB", color="hop", barmode="stack",
                        category_orders={"scenario": scen_order},
                        title="Resolver ↔ authoritative bytes by tier, cold pass (KB)")
            c1.plotly_chart(_plot_cfg(f1), width="stretch")
            tr = bw.melt(id_vars="scenario", value_vars=["truncated", "tcp_conns", "upstream_queries"],
                         var_name="what", value_name="count")
            tr["what"] = tr["what"].map({"truncated": "Truncated responses", "tcp_conns": "TCP connections",
                                         "upstream_queries": "Upstream queries"})
            f2 = px.bar(tr, x="scenario", y="count", color="what", barmode="group",
                        category_orders={"scenario": scen_order}, title="Truncation, TCP fallback and queries")
            c2.plotly_chart(_plot_cfg(f2), width="stretch")
            cb = bw["client_bytes"].dropna()
            if not cb.empty:
                same = "the same in every scenario" if cb.nunique() == 1 else "shown in the table"
                st.caption(f"Client ↔ resolver traffic is {same} (about {compare.fmt_bytes(cb.median())}). "
                           "Warm passes are answered from cache and send no upstream traffic.")

    with cache:
        cc = df.dropna(subset=["cache_rrset"]) if "cache_rrset" in df else df
        st.markdown("##### Measured :green-badge[Measured]")
        if cc.empty:
            st.info("No benchmark data: run a benchmark in the Benchmark tile.")
        else:
            c1, c2 = st.columns(2)
            mem = cc.melt(id_vars="scenario", value_vars=["cache_rrset", "cache_message"],
                          var_name="cache", value_name="bytes")
            mem["cache"] = mem["cache"].map({"cache_rrset": "RRset cache", "cache_message": "Message cache"})
            mem["MB"] = mem["bytes"] / 1024 ** 2
            f1 = px.bar(mem, x="scenario", y="MB", color="cache", barmode="group",
                        category_orders={"scenario": scen_order}, title="Resolver cache memory after the cold pass (MB)")
            c1.plotly_chart(_plot_cfg(f1), width="stretch")
            lat = cc.melt(id_vars="scenario", value_vars=["cold_ms", "warm_ms"], var_name="pass", value_name="ms")
            lat["pass"] = lat["pass"].map({"cold_ms": "Cold (empty cache)", "warm_ms": "Warm (cached)"})
            f2 = px.bar(lat, x="scenario", y="ms", color="pass", barmode="group",
                        category_orders={"scenario": scen_order}, title="Median lookup time (ms)")
            c2.plotly_chart(_plot_cfg(f2), width="stretch")
            st.caption("Cold is the first pass after flushing the resolver; warm repeats the same lookups from cache. "
                       "Cache memory is Unbound's RRset and message cache after the cold pass.")

        st.markdown("---")
        st.markdown("##### Analytical :orange-badge[Analytical]")
        an = df.dropna(subset=["analytic_sig_bytes"])
        per = compare.analytical_per_signature(man_rows)
        if an.empty:
            st.info("No analytical estimate for these scenarios (needs Prepare for an SLH-DSA or MTL scenario).")
        else:
            c1, c2 = st.columns([3, 2])
            ax = an.assign(MB=an.analytic_sig_bytes / 1024 ** 2)
            f = px.bar(ax, x="scenario", y="MB", color="scenario", color_discrete_map=colors,
                       category_orders={"scenario": scen_order}, text_auto=".2f",
                       title="Signature storage for the whole zone set, draft §12 formulas (MB)")
            f.update_layout(showlegend=False)
            c1.plotly_chart(_plot_cfg(f, 320), width="stretch")
            if per:
                c2.markdown(f"**One signature, maximum size** (largest zone: {per['n_messages']} RRsets)")
                c2.markdown(
                    f"- Direct SLH-DSA: **{per['direct']:,} B**  \n"
                    f"- MTL condensed: **{per['condensed']:,} B**  \n"
                    f"- MTL signed ladder (once per zone): **{per['ladder']:,} B**  \n"
                    f"- MTL full (condensed + ladder): **{per['full']:,} B**"
                )
        st.caption("Analytical figures are computed from the draft's size formulas and the zone's RRSIG counts. "
                   "They are never read from the lab and are kept apart from the measured cache above. "
                   "They describe signature material for the whole zone set, not what the resolver actually cached.")

    with allnums:
        t = compare.table(df)
        st.dataframe(t, width="stretch", hide_index=True)
        st.download_button("Download comparison (CSV)", data=df.to_csv(index=False), key="cmp_dl",
                           file_name=f"comparison-{tag}.csv", mime="text/csv")


# ─────────────────────────── RESET ───────────────────────────

def _fmt_size(n: int) -> str:
    return decode.format_bytes(n) if n else "0 B"


def _do_reset() -> None:
    """Callback for the Reset button: runs before the page redraws, so the preview is fresh."""
    ss = st.session_state
    h = _handle()
    scopes = {k: bool(ss.get(f"rs_{k}")) for k in
              ("session", "activity", "pcaps", "runs", "flush", "work")}
    if not any(scopes.values()):
        return
    removed = driver.clear_demo_data(
        h, session=scopes["session"], activity=scopes["activity"], pcaps=scopes["pcaps"],
        hide_prepare_metrics=True, work=scopes["work"], benchmarks=scopes["runs"],
    )
    flushed = False
    flush_note = ""
    if scopes["flush"] and not scopes["work"]:
        try:
            if any((driver.status(h).get("containers") or {}).values()):
                driver.flush(h)
                flushed = True
            else:
                flush_note = "Resolver cache not flushed — the lab is not running."
        except Exception as e:  # noqa: BLE001
            flush_note = f"Resolver flush failed: {str(e)[:200]}"
    if scopes["session"] or scopes["work"]:
        for k in _SESSION_KEYS:
            ss.pop(k, None)
        ss.show_prepare_metrics = False
        ss.pop("selected_scenario", None)
    if scopes["activity"]:
        ss.activity = []
    if scopes["pcaps"]:
        for k in _PCAP_KEYS:
            ss.pop(k, None)
    if scopes["runs"] or scopes["work"]:
        for k in ("last_run_dir", "bench_run_pick", "bench_flash"):
            ss.pop(k, None)
    names = {"session": "dashboard session", "activity": "activity log", "pcaps": "packet captures",
             "runs": "saved benchmark runs", "flush": "resolver cache", "work": "signed zones and lab work"}
    ss.last_reset = {
        "when": datetime.now().strftime("%d %b %Y, %H:%M:%S"),
        "scopes": [names[k] for k, v in scopes.items() if v],
        "removed": removed,
        "flushed": flushed,
        "note": flush_note,
        "fresh": True,
    }
    activity("ok", "Reset", ", ".join(ss.last_reset["scopes"]), phase="ui", source="ui", h=h)
    # Back to the cautious defaults so a second click never repeats a destructive reset by accident.
    for k in ("pcaps", "runs", "flush", "work"):
        ss[f"rs_{k}"] = False
    ss.rs_confirm = False


def _scope_row(key: str, title: str, detail: str, *, default: bool, disabled: bool = False) -> bool:
    c1, c2 = st.columns([1, 3])
    v = c1.checkbox(title, value=default, key=f"rs_{key}", disabled=disabled)
    c2.caption(detail)
    return bool(v)


def reset_controls(h: driver.LabHandle, stt: dict) -> None:
    pv = driver.reset_preview(h)
    r = readiness(stt)
    last = st.session_state.get("last_reset")
    if last and last.pop("fresh", False):
        st.success(f"Reset complete · {last['when']} — cleared: {', '.join(last['scopes'])}.")
        if last.get("note"):
            st.warning(last["note"])

    with st.container(border=True):
        st.markdown("**Display and logs** · safe, nothing to rebuild")
        _scope_row("session", "Session view",
                   f"Recent queries ({pv['session_queries']}), cold/warm result, and the signing timings view.",
                   default=True)
        _scope_row("activity", "Activity log", f"Log file {_fmt_size(pv['activity_bytes'])} and the in-app feed.",
                   default=True)
    with st.container(border=True):
        st.markdown("**Evidence** · you can regenerate it, but not recover it")
        _scope_row("pcaps", "Live captures",
                   f"{pv['pcaps']} file(s) · {_fmt_size(pv['pcap_bytes'])} from the Live tile.", default=False)
        _scope_row("runs", "Saved benchmark runs",
                   f"{pv['runs']} run(s) · {_fmt_size(pv['run_bytes'])} for lab {h.tag}.", default=False)
    with st.container(border=True):
        st.markdown("**Lab environment**")
        _scope_row("flush", "Flush resolver cache",
                   "Empties Unbound's cache so the next lookup is cold." if r["running"]
                   else "Lab is not running, so there is nothing to flush.",
                   default=False, disabled=not r["running"])
        _scope_row("work", "Signed zones and lab work",
                   f"Stops the lab and deletes {_fmt_size(pv['work_bytes'])}. Run Prepare again afterwards."
                   if pv["work_exists"] else "Nothing signed yet.",
                   default=False, disabled=not pv["work_exists"])
    st.caption("Always kept: Docker images, configuration files and repository code.")

    ss = st.session_state
    chosen = [k for k in ("session", "activity", "pcaps", "runs", "flush", "work") if ss.get(f"rs_{k}")]
    destructive = [k for k in ("pcaps", "runs", "work") if ss.get(f"rs_{k}")]
    if destructive:
        wording = {"pcaps": f"{pv['pcaps']} capture file(s)", "runs": f"{pv['runs']} saved benchmark run(s)",
                   "work": "the signed zones (the lab will stop)"}
        st.warning("This permanently deletes " + ", ".join(wording[k] for k in destructive) + ".")
        confirmed = st.checkbox("I understand this cannot be undone", key="rs_confirm")
    else:
        confirmed = True
    st.button(
        f"Reset {len(chosen)} item(s)" if chosen else "Select something to reset",
        type="primary", disabled=not chosen or not confirmed,
        on_click=_do_reset, key="rs_go",
    )


def reset_last() -> None:
    last = st.session_state.get("last_reset")
    if not last:
        st.info("Nothing has been reset in this session yet.")
        return
    st.markdown(f"**{last['when']}** — cleared: {', '.join(last['scopes'])}")
    rm = last["removed"]
    m = st.columns(5)
    m[0].metric("Session", "cleared" if rm.get("session") else "—")
    m[1].metric("Activity log", "cleared" if rm.get("activity") else "—")
    m[2].metric("Captures removed", rm.get("pcaps", 0))
    m[3].metric("Runs removed", rm.get("benchmarks", 0))
    m[4].metric("Zones removed", "yes" if rm.get("work") else "no")
    if last.get("flushed"):
        st.caption("Resolver cache flushed.")
    if last.get("note"):
        st.warning(last["note"])


def reset_page(h: driver.LabHandle, stt: dict) -> None:
    _page_header("reset", h, stt)
    controls, last = st.tabs(["Reset", "Results"])
    with controls:
        reset_controls(h, stt)
    with last:
        reset_last()
    _activity_expander(h)


# ─────────────────────────── ACTIVITY ───────────────────────────

def activity_tab(h: driver.LabHandle) -> None:
    top = st.columns([1, 2, 2])
    if top[0].button("Clear", key="act_clear"):
        st.session_state.activity = []
        st.rerun()
    entries = st.session_state.get("activity") or []
    if not entries:
        st.caption("Empty.")
        return
    sources = sorted({e.get("source", "ui") for e in entries})
    phases = sorted({e.get("phase", "ui") for e in entries})
    filt_src = top[1].multiselect("Source", sources, default=sources, key="act_src")
    filt_phase = top[2].multiselect("Phase", phases, default=phases, key="act_phase")
    filtered = [e for e in entries if e.get("source") in filt_src and e.get("phase") in filt_phase]
    blob = "\n\n".join(
        f"[{e['t']}] {e['level']} {e['title']}\n{e.get('detail', '')}" for e in filtered
    )
    st.download_button("Download", data=blob, file_name=f"activity-{h.tag}.txt", mime="text/plain",
                       key="act_dl")
    for e in filtered[:80]:
        icon = LEVEL_ICON.get(e["level"], "•")
        with st.container(border=True):
            st.markdown(f"{icon} **{e['t']}** · {e['title']}")
            if e.get("detail") and not e["detail"].startswith("```"):
                st.caption(e["detail"][:500])
            elif e.get("detail"):
                with st.expander("output"):
                    st.code(e["detail"].strip("`").replace("```", ""))


# ─────────────────────────── ENTRY POINT ───────────────────────────

SIDEBARS = {
    "home": sidebar_home, "setup": sidebar_setup, "live": sidebar_live,
    "benchmark": sidebar_benchmark, "compare": sidebar_compare, "reset": sidebar_reset,
}
PAGES = {
    "setup": setup_page, "live": live_page, "benchmark": benchmark_page, "compare": compare_page,
    "reset": reset_page,
}


def main() -> None:
    st.markdown(_CSS, unsafe_allow_html=True)
    symbol, _full = _brand()
    if symbol is not None:
        st.logo(symbol, icon_image=symbol, size="large")  # top-left on Home and on every tile
    _init_nav()
    h = _handle()
    mode = st.session_state.nav

    err = _apply_ui_config(h)
    tag_before = h.tag
    stt = _status(h)

    SIDEBARS[mode](h, stt)
    # Sidebar widgets may have changed settings this run; write them out before the page reads them.
    err = _apply_ui_config(h) or err
    if h.tag != tag_before:
        st.rerun()  # zone size changed → a different lab; re-read its status
    if err and mode in ("setup", "benchmark") and not st.session_state.get("shape_errors"):
        st.sidebar.error(err)

    if mode == "home":
        home_page(h, stt)
    else:
        PAGES[mode](h, stt)


if __name__ == "__main__":
    main()
