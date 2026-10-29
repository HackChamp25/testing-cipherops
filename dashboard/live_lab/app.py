"""Cipherops · MTL DNSSEC Lab — control room for the multi-zone stack.

    streamlit run dashboard/live_lab/app.py

Layout: a home hub of independent tiles (Setup, Live, Benchmark, Reset). Setup is the one
mandatory first step; every other tile works on its own once the lab is up. Each tile keeps
its controls in the sidebar and its own Results view in the main area.
"""

from __future__ import annotations

import importlib
import json
import sys
import time
from datetime import datetime
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

ROOT = Path(__file__).resolve().parents[2]
ECO_DIR = ROOT / "ecosystem"
SUITES_DIR = ECO_DIR / "results" / "suites"
sys.path.insert(0, str(ROOT / "dashboard"))

from live_lab import compare, decode, driver  # noqa: E402
from live_lab import build_job, prepare_job, prepare_story  # noqa: E402
from live_lab import suite as suite_mod  # noqa: E402

compare = importlib.reload(compare)
decode = importlib.reload(decode)
driver = importlib.reload(driver)
build_job = importlib.reload(build_job)
prepare_story = importlib.reload(prepare_story)
suite_mod = importlib.reload(suite_mod)
prepare_job = importlib.reload(prepare_job)  # after suite_mod: it uses the suite's process helpers

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
            "Switch scenario, flush the cache, run a query, compare cold and warm",
            "Decode the capture and draw its message sequence",
        ],
        "cta": "Open Live",
    },
    "benchmark": {
        "icon": "📊",
        "title": "Benchmark",
        "pitch": "The PS-036 benchmark: three dataset sizes, repeated trials, on its own.",
        "bullets": [
            "Signs, starts the lab, measures and stops it for each size",
            "Signing, verification and bytes, with the settings recorded",
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
                 "prepare_summary", "last_log", "replay_fresh")
_PCAP_KEYS = ("last_pcap", "last_dropped", "last_story", "last_wire", "last_seq_steps",
              "last_seq_pcap")


# ─────────────────────────── settings that survive tile switches ───────────────────────────
# Streamlit drops a widget's state as soon as the widget stops being drawn. Each tile draws a
# different sidebar, so values live in st.session_state["cfg"] and widgets are re-seeded from it.

def _store() -> dict:
    return st.session_state.setdefault("cfg", {})


def _bootstrap_cfg_from_disk() -> None:
    """Browser refresh wipes session_state; restore stack/zone from disk so pcaps do not 'vanish'."""
    if st.session_state.get("_cfg_bootstrapped"):
        return
    st.session_state._cfg_bootstrapped = True
    inferred = driver.infer_ui_from_disk()
    if not inferred:
        return
    store = _store()
    for key in ("stack", "zone_size", "scenarios"):
        if key in inferred and key not in store:
            store[key] = inferred[key]
    # Seed widget keys before first sb() draw so selectboxes do not snap to DEFAULT_STACK.
    if "stack" in inferred and "w_stack" not in st.session_state:
        st.session_state.w_stack = inferred["stack"]
    if "zone_size" in inferred and "w_zone_size" not in st.session_state:
        st.session_state.w_zone_size = inferred["zone_size"]
    if "scenarios" in inferred and "w_scenarios" not in st.session_state:
        st.session_state.w_scenarios = list(inferred["scenarios"])


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
    tech: bool = False,
) -> None:
    entry = {
        "t": datetime.now().strftime("%H:%M:%S"),
        "level": level, "title": title, "detail": (detail or "").strip(),
        "phase": phase, "source": source, "tech": bool(tech),
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
    """Keep raw Docker/tool output for debugging; hidden from the simple Activity view."""
    chunks = driver.chunk_log(text)
    for i, ch in enumerate(chunks, 1):
        suffix = f" ({i}/{len(chunks)})" if len(chunks) > 1 else ""
        activity("info", f"{title}{suffix}", f"```\n{ch}\n```", phase=phase, source=source, tech=True)


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


def _scenario_list(h: driver.LabHandle) -> list[str]:
    """Scenarios chosen in Setup (and present on disk after Prepare), not only the active one."""
    chosen = [str(s) for s in (cfg("scenarios") or [])]
    on_disk: list[str] = []
    zones = h.work / "zones"
    if zones.is_dir():
        on_disk = sorted(
            p.name for p in zones.iterdir()
            if p.is_dir() and (p / "manifest.json").is_file()
        )
    if on_disk:
        ordered = [s for s in chosen if s in on_disk]
        return ordered + [s for s in on_disk if s not in ordered]
    return chosen


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
    # Survive browser refresh: session_state alone is not enough for stack/zone.
    driver.save_ui_prefs({
        "stack": h.stack,
        "zone_size": zone,
        "scenarios": sc,
        "lab": h.lab,
        "tag": h.tag,
        "saved_at": datetime.now().isoformat(timespec="seconds"),
    })
    return None


# ─────────────────────────── page chrome ───────────────────────────

def _lab_strip(h: driver.LabHandle, stt: dict, *, mode: str = "setup") -> None:
    r = readiness(stt)
    sc = _scenario_list(h)
    if mode == "live" and r["active"]:
        scen_chip = _chip(f"Active · {r['active']}", "info")
    elif sc:
        label = "Scenario" if len(sc) == 1 else "Scenarios"
        scen_chip = _chip(f"{label} · {', '.join(sc)}", "info")
    elif r["active"]:
        scen_chip = _chip(f"Scenario · {r['active']}", "info")
    else:
        scen_chip = ""
    chips = [
        _chip("Lab running", "ok") if r["running"] else _chip("Lab stopped", "idle"),
        _chip("Prepared", "ok") if r["prepared"] else _chip("Not prepared", "warn"),
        scen_chip,
        _chip(f"Zone · {cfg('zone_size', 'small')}", "idle"),
    ]
    st.markdown(f'<div class="co-strip">{" ".join(c for c in chips if c)}</div>', unsafe_allow_html=True)


def _page_header(mode: str, h: driver.LabHandle, stt: dict) -> None:
    tile = TILES[mode]
    st.markdown(f"## {tile['icon']} {tile['title']}")
    st.caption(tile["pitch"])
    if mode in ("setup", "live", "reset"):
        _lab_strip(h, stt, mode=mode)


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

# Full screen needs a user click (browsers block it on load). Icon only, pinned to the top-right of the
# main pane so the sidebar stays tight — Cipherops sits next to "How to use this lab" / Home as before.
_FULLSCREEN_HTML = """
<style>
  html, body { margin: 0; background: transparent; overflow: hidden; }
  button {
    width: 32px; height: 32px; border-radius: 8px; padding: 0; cursor: pointer;
    font-size: 16px; line-height: 1; color: #31333f;
    background: rgba(255,255,255,.92); border: 1px solid rgba(49,51,63,.18);
  }
  button:hover { border-color: #ff4b4b; color: #ff4b4b; }
  @media (prefers-color-scheme: dark) {
    button { color: #fafafa; background: rgba(38,39,48,.92); border-color: rgba(250,250,250,.2); }
    button:hover { border-color: #ff4b4b; color: #ff4b4b; }
  }
</style>
<button id="b" title="Full screen" aria-label="Full screen">&#x26F6;</button>
<script>
  (function () {
    const frame = window.frameElement;
    if (frame) {
      Object.assign(frame.style, {
        position: "fixed", top: "4.1rem", right: "1.25rem",
        width: "34px", height: "34px", zIndex: "998",
        border: "none", background: "transparent",
      });
      // Collapse the Streamlit slot so this control never pushes page content down.
      const slot = frame.closest("[data-testid='stElementContainer'], .stElementContainer, .element-container");
      if (slot) Object.assign(slot.style, { height: "0", margin: "0", padding: "0", overflow: "visible" });
    }
    const b = document.getElementById("b");
    try {
      const doc = window.parent.document;
      const sync = () => {
        const on = !!doc.fullscreenElement;
        b.textContent = on ? "\\u2715" : "\\u26F6";
        b.title = on ? "Exit full screen" : "Full screen";
        b.setAttribute("aria-label", b.title);
      };
      b.onclick = () => (doc.fullscreenElement ? doc.exitFullscreen() : doc.documentElement.requestFullscreen());
      doc.addEventListener("fullscreenchange", sync);
      sync();
    } catch (e) {
      b.title = "Press F11 for full screen";
      b.setAttribute("aria-label", b.title);
      b.disabled = true;
    }
  })();
</script>
"""


def _fullscreen_icon() -> None:
    _embed_html(_FULLSCREEN_HTML, height=1)


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
        "3. **Benchmark** — three dataset sizes, repeated trials; needs only the images, "
        "not Prepare or a running lab  \n"
        "4. **Compare** — MTL vs SLH-DSA and the other modes, side by side  \n"
        "5. **Reset** — clear only what you choose"
    )
    st.sidebar.markdown("---")
    r = readiness(stt)
    st.sidebar.markdown("### Lab readiness")
    for ok, text in ((r["images"], "Images built"), (r["prepared"], "Zones signed"),
                     (r["running"], "Containers running")):
        st.sidebar.markdown(f"{'🟢' if ok else '⚪'}  {text}")
    sc = _scenario_list(h)
    if sc:
        st.sidebar.markdown(f"🔵  Scenarios **{', '.join(sc)}**")
    if r["active"] and r["running"]:
        st.sidebar.markdown(f"▶️  Active **{r['active']}**")
    st.sidebar.markdown("---")
    _hint("Open a tile to see its settings here. Each tile has its own Results view.")
    if st.sidebar.button("Refresh status", width="stretch", key="sb_refresh_home"):
        st.rerun()


def _step_label(n: int, title: str, state: str) -> str:
    mark = {"done": "🟢", "partial": "🟡"}.get(state, "⚪")
    return f"{mark}  **Step {n}** · {title}"


def _finish_prepare_job(h: driver.LabHandle) -> None:
    """Take over a Prepare job that has just ended: update this session and the Activity log, once.

    The worker has already saved the session summary to disk; this adds what only the page can do
    (open the signing replay, log the result). ``handled`` is stored with the job, so a second browser
    tab, or a later session, does not repeat it.
    """
    stt = prepare_job.status(h)
    state = stt.get("state")
    if state not in ("done", "failed", "stopped") or stt.get("handled"):
        return
    prepare_job.mark_handled(h)
    scen_txt = ", ".join(stt.get("scenarios") or [])
    if state != "done":
        msg = str(stt.get("error") or "Signing did not finish.")[-2000:]
        st.sidebar.error(msg[:600])
        activity("err", "Signing failed", msg, phase="prepare", source="prepare", h=h)
        return
    secs = float(stt.get("wall_s") or 0)
    summary = stt.get("summary") or driver.prepare_summary(h, wall_s=secs)
    ss = st.session_state
    ss.prepare_wall_s = secs
    ss.show_prepare_metrics = True
    ss.replay_fresh = True  # Setup → Overview opens the signing replay
    ss.prepare_summary = summary
    log = prepare_job.log_text(h)
    ss.last_log = log[-8000:]
    _log_chunks(log, phase="prepare", source="prepare", title="prepare")
    n_scen = len(summary.get("scenarios") or stt.get("scenarios") or [])
    activity("ok", f"Zones signed ({secs:.0f}s)",
             f"Prepared {n_scen} scenario(s): {scen_txt}. Watch the signing replay in Setup, "
             "or open Results for sign times.", phase="prepare", source="prepare", h=h)
    activity("info", "Prepare paths",
             f"work: `{summary['work_dir']}`\nzones: `{summary['zones_dir']}`\n"
             f"active: `{summary['active_dir']}`\ncompose: `{summary['compose']}`",
             phase="prepare", source="prepare", h=h, tech=True)
    st.sidebar.success(f"Done · {secs:.0f}s")


def _warn_unvalidated(stack: str, scenarios) -> None:
    bad = driver.unvalidated_scenarios(stack, scenarios)
    if bad:
        st.sidebar.warning(
            f"On **{stack}**, {', '.join(bad)} is not validated by the resolver (SERVFAIL), so it cannot be compared "
            "with MTL here. Use **draft06** for the MTL vs non-MTL comparison, or untick it.")


def _finish_build_job(h: driver.LabHandle) -> None:
    """Take over a build that has just ended: log the result in the Activity log, once (``handled`` is stored)."""
    stt = build_job.status()
    state = stt.get("state")
    if state not in ("done", "failed", "stopped") or stt.get("handled"):
        return
    build_job.mark_handled()
    log = build_job.log_text(8000)
    st.session_state.last_log = log
    _log_chunks(log, phase="build", source="compose", title="build")
    secs = float(stt.get("finished") or time.time()) - float(stt.get("started") or time.time())
    if state == "done":
        activity("ok", f"Build done ({secs:.0f}s)", f"Image set {stt.get('stack')}", phase="build", source="compose", h=h)
        st.sidebar.success(f"Images built · {secs:.0f}s")
    else:
        msg = str(stt.get("error") or "The build did not finish.")[-2000:]
        st.sidebar.error(msg[:600])
        activity("err", "Build failed", msg, phase="build", source="compose", h=h)


def sidebar_setup(h: driver.LabHandle, stt: dict) -> None:
    _sidebar_brand("setup")
    st.sidebar.markdown("### Setup")
    bench_busy = suite_mod.running_suite()
    if bench_busy:
        st.sidebar.warning(f"Benchmark {bench_busy['id']} is using the lab. Build, Prepare, Start and Stop are "
                           "paused until it finishes or is cancelled.")

    r = readiness(stt)
    prepared_session = r["prepared"] and prepare_metrics_visible(h)
    _hint("Green means ready. Yellow means found on disk from an earlier session.")

    # —— Step 1: images (everything else runs inside them, so this comes first) ——
    _finish_build_job(h)
    building = build_job.is_running()
    st.sidebar.markdown(_step_label(1, "Images", "done" if r["images"] else "none"))
    _hint("Choose the DNS stack version, then build it. Prepare, Start and the benchmark all run inside these images.")
    stacks = driver.list_stacks()
    stack = sb(
        st.sidebar.selectbox, "stack", driver.DEFAULT_STACK, "Image version",
        options=stacks, format_func=driver.stack_label,
        help="Which pinned Verisign DNS stack to build and run. "
             "draft06 = condensed-by-default (EDNS 65050). "
             "latest = always-full MTL, same MTL commit as the main Cipherops library report. "
             "Change this, then Build images (and Prepare again for Live).",
    )
    pins = driver.stack_pins(stack)
    if pins:
        mtl = (pins.get("MTL_COMMIT") or "")[:12]
        oqs = pins.get("LIBOQS_TAG") or "?"
        _hint(f"Pins for **{stack}**: MTL `{mtl}…` · liboqs {oqs}. Build this version before Prepare / Benchmark.")
    img_mode = sb(st.sidebar.radio, "image_mode", "Build locally", "Image source",
                  options=["Build locally", "Pull from registry"])
    if img_mode.startswith("Pull"):
        reg = sb(
            st.sidebar.text_input, "registry", "", "Registry", placeholder="ghcr.io/your-org/cipherops",
            help="Pre-built images named cipherops-eco-nsd / unbound / tools.",
        )
        if st.sidebar.button("Pull images", key="btn_pull", width="stretch", disabled=bool(bench_busy or building)):
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
        if building:
            _hint("Building in the background. The log is on the Setup page; you can keep using the dashboard.")
        if st.sidebar.button("Build images" if not building else "Building…", key="btn_build", width="stretch",
                             disabled=bool(bench_busy or building)):
            activity("step", "Build images", f"Image set {h.stack}", phase="build", source="compose", h=h)
            try:
                build_job.start(h.stack)  # returns at once; Setup shows the log live
            except Exception as e:  # noqa: BLE001
                st.sidebar.error(str(e)[:600])
                activity("err", "Build failed to start", str(e)[:2000], phase="build", source="compose", h=h)
            st.rerun()

    # —— Step 2: prepare (zone design, then sign) ——
    prep_state = "done" if prepared_session else ("partial" if r["prepared"] else "none")
    st.sidebar.markdown(_step_label(2, "Prepare", prep_state))
    _hint("Design the zones, then sign them for each selected scenario.")
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
    if not sc:
        st.sidebar.warning("Select at least one scenario")
    _warn_unvalidated(stack, sc)

    _finish_prepare_job(h)
    signing = prepare_job.is_running(h)
    no_images = not r["images"]
    if no_images:
        _hint("Build or pull the images (step 1) first.")
    if signing:
        _hint("Signing is running. Watch it live in Setup.")
    if st.sidebar.button("Prepare", key="btn_prep", width="stretch",
                         disabled=not sc or bool(shape_errors) or signing or bool(bench_busy) or building or no_images):
        _apply_ui_config(h)
        jobs = int(cfg("jobs", 2))
        scen_txt = ", ".join(sc)
        activity("step", "Signing zones", f"Size {size} · {scen_txt}", phase="prepare", source="prepare", h=h)
        try:
            prepare_job.start(h, jobs=jobs, scenarios=list(sc))  # returns at once; Setup shows it live
            st.session_state.pop("replay_fresh", None)
        except Exception as e:  # noqa: BLE001
            st.sidebar.error(str(e)[:600])
            activity("err", "Signing failed to start", str(e)[:2000], phase="prepare", source="prepare", h=h)
        st.rerun()

    # —— Step 3: start / stop ——
    st.sidebar.markdown(_step_label(3, "Start", "done" if r["running"] else "none"))
    _hint("Start root, TLD, leaf, and resolver containers. Only one lab runs at a time, "
          "so starting stops any other zone shape.")
    b3a, b3b = st.sidebar.columns(2)
    if b3a.button("Start", key="btn_up", width="stretch", disabled=bool(bench_busy or signing or building or no_images)):
        activity("step", "Starting the lab", f"Image set {h.stack}", phase="compose", source="compose", h=h)
        with st.spinner("Starting…"):
            try:
                log = driver.up(h)
                st.session_state.last_log = log[-4000:]
                st.session_state.pop("last_start_error", None)
                _log_chunks(log, phase="compose", source="compose", title="up")
                activity("ok", "Lab is running", "DNS servers and resolver are up.",
                         phase="compose", source="compose", h=h)
            except Exception as e:  # noqa: BLE001
                msg = str(e)
                st.session_state.last_start_error = msg[-4000:]
                st.sidebar.error(msg[:800])
                activity("err", "Start failed", msg[-3000:], phase="compose", source="compose", h=h)
        st.rerun()
    if b3b.button("Stop", key="btn_down", width="stretch", disabled=bool(bench_busy)):
        with st.spinner("Stopping…"):
            try:
                driver.down(h)
                st.session_state.pop("last_start_error", None)
                activity("ok", "Lab stopped", "", phase="compose", source="compose", h=h)
            except Exception as e:  # noqa: BLE001
                st.sidebar.error(str(e)[:600])
                activity("err", "Stop failed", str(e)[:2000], phase="compose", source="compose", h=h)
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
        if r["running"] and scenario and scenario != active and not suite_mod.running_suite():
            udp = int(cfg("udp", 1232))
            activity("step", f"Activate {scenario}", "", phase="activate", source="compose", h=h)
            st.toast(f"Switching the lab to {scenario}: loading its zones and restarting the root, TLD and leaf "
                     "servers and the resolver. This takes a few seconds.", icon="⏳")
            with st.spinner(f"Switching to {scenario}… (reloading root, TLD, leaf and resolver)"):
                try:
                    msg = driver.activate(h, scenario, udp=udp)
                    st.session_state.query_log = []
                    for k in ("last_query", "last_stats", "pcap_story_choice", "pcap_seq_choice", *_PCAP_KEYS):  # they describe the previous scenario
                        st.session_state.pop(k, None)
                    _log_chunks(msg, phase="activate", source="compose", title="activate")
                    activity("ok", f"{scenario} live", "", phase="activate", source="compose", h=h)
                    st.toast(f"{scenario} is live. Run a query to see its answer.", icon="✅")
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
    st.sidebar.markdown("### Resolver cache")
    if r["running"]:
        _hint("Empties the resolver. The next lookup is cold. Takes a few seconds.")
    else:
        _hint("Start the lab in Setup before flushing.")
    if st.sidebar.button("Flush cache", key="btn_flush_cache", width="stretch", disabled=not r["running"]):
        activity("step", "Flush cache", "", phase="cache", source="unbound", h=h)
        with st.spinner("Flushing the resolver…"):
            try:
                driver.flush(h)
                activity("ok", "Resolver cache empty", "The next lookup is cold.", phase="cache", source="unbound", h=h)
                st.sidebar.success("Cache empty. The next lookup is cold.")
            except Exception as e:  # noqa: BLE001
                st.sidebar.error(str(e)[:600])
                activity("err", "Flush failed", str(e)[:2000], phase="cache", source="unbound", h=h)

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


SUITE_SIZE_CHOICES = [20, 50, 500, 5000]
SUITE_DEFAULT_SIZES = list(suite_mod.BENCH_SIZES)


def _size_label(n: int) -> str:
    return f"{n:,} names" + (" (quick check)" if n == suite_mod.SMOKE_SIZE else "")


def sidebar_benchmark(h: driver.LabHandle, stt: dict) -> None:
    _sidebar_brand("benchmark")
    r = readiness(stt)
    suites = suite_mod.list_suites()
    done = [s for s in suites if s["complete"]]
    live = suite_mod.running_suite()
    st.sidebar.markdown("### Benchmark")
    if live:
        st.sidebar.markdown("🔵  A benchmark is running")
    else:
        st.sidebar.markdown(f"🟢  {len(done)} saved benchmark(s)" if done else "⚪  No benchmark yet")
    _hint(
        "Runs on its own: for each dataset size it signs the zones, repeats signing and verification, "
        "starts the lab, measures, and stops it. It only needs the built images (Setup, step 1)."
    )
    bench_stack = cfg("stack", driver.DEFAULT_STACK)
    _hint(f"Uses **Image version `{bench_stack}`** from Setup — build that stack before you run.")

    st.sidebar.markdown("**Run name**")
    label = sb(
        st.sidebar.text_input, "run_label", "", "Name this benchmark",
        placeholder="e.g. panel-final", max_chars=30,
        help="Stored with the date and time, so you can tell benchmarks apart later.",
    )
    clean = driver.sanitize_label(label)[:30]
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    _hint(f"Saved as {stamp}{'_' + clean if clean else ''} (time = when you press Run)")

    st.sidebar.markdown("**What to measure**")
    sizes = sb(st.sidebar.multiselect, "bench_sizes", SUITE_DEFAULT_SIZES, "Dataset sizes",
               options=SUITE_SIZE_CHOICES, format_func=_size_label,
               help="Data names in the whole hierarchy. PS-036 asks for three sizes: 50, 500 and 5,000.")
    sc = sb(st.sidebar.multiselect, "bench_scenarios", ["ecdsa", "slh-dsa", "mtl"], "Scenarios",
            options=list(driver.SCENARIO_ALGS),
            help="slh-dsa is the PQC algorithm without MTL, mtl is the same algorithm with MTL. "
                 "ecdsa is a classical reference.")
    sb(st.sidebar.number_input, "bench_trials", 3, "Measurement trials", min_value=1, max_value=10,
       help="Each trial replays the workload with a cold cache, then again warm.")
    sb(st.sidebar.number_input, "bench_sign_trials", suite_mod.DEFAULT_SIGN_TRIALS, "Signing trials",
       min_value=1, max_value=10, help="How often signing and verification are repeated on sample zones.")
    sb(st.sidebar.number_input, "bench_sample", suite_mod.DEFAULT_SAMPLE_NAMES, "Signing sample (names)",
       min_value=10, max_value=500, step=10,
       help="Size of the sample zone for the signing trials. The dataset-wide time is extrapolated from "
            "it and labelled as an estimate; the full zones are signed once as well.")
    sb(st.sidebar.number_input, "bench_jobs", 1, "Parallel signing jobs", min_value=1, max_value=4,
       help="Zones signed at the same time when the full dataset is signed. 1 gives clean timings; more is "
            "faster but inflates the timing of that one full run (the repeated sign trials always run alone).")
    sb(st.sidebar.number_input, "bench_queries", 500, "Lookups per pass", min_value=10, max_value=5000,
       help="How many lookups each cold and warm pass replays.")
    nets = sb(st.sidebar.multiselect, "bench_networks", ["lan"], "Networks", options=["lan", "wan", "lossy"],
              help="lan = local · wan = added delay · lossy = delay plus packet loss.")
    sb(st.sidebar.selectbox, "bench_udp", 1232, "UDP size limit", options=[1232, 4096],
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
            for i, (field, flabel) in enumerate(PROFILE_FIELDS):
                with cols[i % 2]:
                    if field == "loss_pct":
                        sb(st.number_input, f"{prof}_{field}", float(base[field]), flabel,
                           min_value=0.0, max_value=20.0, step=0.5, format="%.1f")
                    else:
                        sb(st.number_input, f"{prof}_{field}", int(base[field]), flabel,
                           min_value=0, max_value=500, step=1)
    if not _workload_is_default():
        st.sidebar.caption("Custom workload or network numbers are in use.")
        st.sidebar.button("Restore defaults", on_click=_restore_workload, key="btn_restore_wl",
                          width="stretch")

    _warn_unvalidated(cfg("stack", "draft06"), sc)
    ready = bool(sizes and sc and nets) and r["images"] and not live and not build_job.is_running()
    if not r["images"]:
        st.sidebar.warning("Build the images first (Setup, step 1).")
    if r["running"] and not live:
        st.sidebar.caption("The lab running in Setup will be stopped while the benchmark uses the containers.")
    if st.sidebar.button("Run benchmark", key="btn_bench", type="primary", width="stretch", disabled=not ready):
        params = {
            "label": clean, "stack": cfg("stack", "draft06"), "sizes": sorted(int(n) for n in sizes),
            "scenarios": list(sc), "trials": int(cfg("bench_trials", 3)),
            "sign_trials": int(cfg("bench_sign_trials", suite_mod.DEFAULT_SIGN_TRIALS)),
            "sample_names": int(cfg("bench_sample", suite_mod.DEFAULT_SAMPLE_NAMES)),
            "n_queries": int(cfg("bench_queries", 500)), "networks": list(nets),
            "udp": int(cfg("bench_udp", 1232)), "jobs": int(cfg("bench_jobs", 1)),
            "workload": _workload(), "profiles": _profiles(),
        }
        try:
            sid = suite_mod.start(params)
            st.session_state.bench_suite_pick = sid
            activity("step", f"Benchmark started · {sid}", json.dumps(params)[:1500], phase="run", source="suite",
                     h=h)
        except Exception as e:  # noqa: BLE001
            st.sidebar.error(str(e)[:600])
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
    if mode == "benchmark":
        if suite_mod.running_suite():
            return _chip("Running", "info")
        if not r["images"]:
            return _chip("Needs images", "warn")
        n = len([s for s in suite_mod.list_suites() if s["complete"]])
        return _chip(f"Ready · {n} saved" if n else "Ready", "ok")
    if mode == "live":
        if not r["ready"]:
            return _chip("Needs Setup", "warn")
        return _chip(f"Live · {r['active']}", "ok") if r["active"] else _chip("Ready", "ok")
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
        st.info("**Start with Setup** to build the images. Live also needs the lab signed and running; "
                "Benchmark only needs the images.")

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
                elif mode == "live":
                    emphasise = r["ready"]
                elif mode == "benchmark":
                    emphasise = r["images"]
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


def _embed_html(html: str, height: int | str = "content") -> None:
    """Show a self-contained HTML page in an iframe (``st.iframe`` on current Streamlit)."""
    if hasattr(st, "iframe"):
        st.iframe(html, height=height)
    else:  # older Streamlit: needs a fixed height
        import streamlit.components.v1 as components
        components.html(html, height=int(height) if isinstance(height, int) else 780)


def _clock(seconds: float) -> str:
    m, s = divmod(int(max(0, seconds)), 60)
    return f"{m}:{s:02d}"


_STATE_TEXT = {"waiting": "waiting", "signing": "signing…", "done": "signed"}


@st.fragment(run_every=1.0)
def _prepare_live_body(h: driver.LabHandle) -> None:
    """Polls the Prepare job once a second and redraws the monitor. Hands over when the job ends."""
    job = prepare_job.status(h)
    if job.get("state") not in prepare_job.ACTIVE_STATES:
        st.rerun()  # whole page: the sidebar takes over the result and the replay opens
        return
    started = float(job.get("started") or time.time())
    live = prepare_job.live_state(prepare_job.events(h), expected=job.get("scenarios"))
    elapsed = time.time() - started

    if not live["scenarios"]:
        st.progress(0.0, text=f"Starting the signing container… {_clock(elapsed)}")
    else:
        done, total = live["zones_done"], live["zones_total"]
        st.progress(min(1.0, live["fraction"]), text=f"{done} of {total} zones signed · {_clock(elapsed)} elapsed")

        pills = []
        for x in live["scenarios"]:
            pills.append(f"**{x['scenario']}** {_STATE_TEXT[x['state']]} ({x['done']}/{x['total']})")
        pills += [f"**{s}** waiting" for s in live["pending"]]
        st.markdown("  ·  ".join(pills))

        cur = next(x for x in live["scenarios"] if x["scenario"] == live["current"])
        algs = cur["algorithms"]
        if algs:
            st.caption("Signing **{}** with: ".format(cur["scenario"]) + " · ".join(
                f"{prepare_job.TIER_LABEL[t].lower()} {algs[t]}" for t in prepare_job.TIER_ORDER if t in algs))

        cols = st.columns(len(prepare_job.TIER_ORDER))
        for col, tier in zip(cols, prepare_job.TIER_ORDER):
            t = cur["tiers"].get(tier) or {"total": 0, "done": 0, "signing": 0}
            col.metric(prepare_job.TIER_LABEL[tier], f"{t['done']} / {t['total']}",
                       f"{t['signing']} signing now" if t["signing"] else None, delta_color="off")

        left, right = st.columns([3, 2])
        with left:
            # natural size: stretching a small graph to the column makes the boxes huge and the text tiny
            st.graphviz_chart(prepare_job.live_dot(cur))
        with right:
            tier_rank = {t: i for i, t in enumerate(prepare_job.TIER_ORDER)}
            rows = []
            for z in sorted(cur["zones"], key=lambda z: (tier_rank.get(z["tier"], 9), z["origin"])):
                if z["state"] == "done":
                    took = f"{float(z.get('sign_s') or 0):.1f} s"
                elif z["state"] == "signing" and z.get("elapsed") is not None:
                    took = f"{z['elapsed']:.0f} s…"
                else:
                    took = ""
                rows.append({"Zone": z["origin"], "Tier": prepare_job.TIER_LABEL.get(z["tier"], z["tier"]),
                             "State": _STATE_TEXT[z["state"]],
                             "RRSIGs": int(z["rrsigs"]) if z.get("rrsigs") is not None else None,
                             "Sign time": took})
            st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch", height=min(420, 38 + 35 * len(rows)))

    st.caption("Zones sign in parallel (Sign jobs), tier by tier: leaf zones first, then each TLD with its "
               "children's DS records, then the root. RRSIG counts and times are measured as each zone finishes.")
    with st.expander("Signer output"):
        st.code(prepare_job.log_text(h, 4000) or "(nothing printed yet)", language="text")
    if st.button("Cancel signing", key="btn_prep_cancel"):
        prepare_job.cancel(h)
        activity("info", "Signing cancelled", "", phase="prepare", source="prepare", h=h)
        st.rerun()


@st.fragment(run_every=2.0)
def _build_live_body() -> None:
    """Polls the image build every two seconds and shows its log. Hands over when it ends."""
    job = build_job.status()
    if job.get("state") not in build_job.ACTIVE_STATES:
        st.rerun()  # whole page: the sidebar logs the result
        return
    elapsed = time.time() - float(job.get("started") or time.time())
    st.progress(0.0, text=f"Building images for {job.get('stack')} · {_clock(elapsed)} elapsed")
    st.caption("A first build compiles OpenSSL, liboqs, MTL, NSD and Unbound from source and can take tens of "
               "minutes. Later builds reuse Docker's cache and take seconds. You can leave this page.")
    st.code(build_job.log_text(5000) or "(starting…)", language="text")
    if st.button("Cancel build", key="btn_build_cancel"):
        build_job.cancel()
        activity("info", "Build cancelled", "", phase="build", source="compose")
        st.rerun()


def build_live_panel() -> None:
    st.markdown("### Building images")
    _build_live_body()


def prepare_live_panel(h: driver.LabHandle) -> None:
    st.markdown("### Signing live")
    _prepare_live_body(h)


def setup_replay(h: driver.LabHandle, *, key: str) -> None:
    """Animated replay of how Prepare signed the hierarchy (built from the Prepare manifests on disk)."""
    manifests = driver.list_manifests(h) if (prepare_metrics_visible(h) and h.prepared()) else {}
    if not manifests:
        st.info("The signing replay appears here after you run Prepare (Step 2 in the sidebar).")
        return
    names = compare.order_scenarios(manifests)
    pick = names[0]
    if len(names) > 1:
        pick = st.radio(
            "Scenario", names, horizontal=True, key=f"replay_pick_{key}",
            index=names.index("mtl") if "mtl" in names else 0,
            help="Each scenario signs the same zones. Compare how many signatures each one needs.",
        )
    size_key = cfg("zone_size", "small")
    size_label = driver.ZONE_SIZE_PRESETS.get(size_key, {}).get("label", str(size_key))
    scene = prepare_story.build_scene(
        manifests[pick], lab=h.lab, scenario=pick,
        zones_dir=h.work / "zones" / pick, size_label=size_label,
    )
    _embed_html(prepare_story.render_html(scene), height="content")
    st.caption(
        "**Want more records?** Change **Zone size** in the sidebar (Small, Medium, Large, or **Custom…** for "
        "TLDs, leaf zones and names per leaf zone), then press **Prepare**. The replay always shows the last Prepare."
    )
    st.caption(
        "Time is compressed so every tier takes the same few seconds; the real signing times are on the labels. "
        "Record counts are the RRSIGs found in the signed zone files; the tree is drawn from that count "
        "(one leaf per signed RRset, one perfect tree per 1-bit of the count)."
    )


def setup_overview(h: driver.LabHandle, stt: dict) -> None:
    imgs = stt.get("images") or {}
    containers = stt.get("containers") or {}
    r = readiness(stt)

    if st.session_state.get("replay_fresh") and h.prepared():
        with st.container(border=True):
            top, hide = st.columns([6, 1])
            top.markdown("**Signing replay** · how Prepare just signed the hierarchy")
            hide.button("Hide", key="hide_replay", on_click=lambda: st.session_state.pop("replay_fresh", None))
            setup_replay(h, key="fresh")

    err = st.session_state.get("last_start_error")
    if err:
        with st.container(border=True):
            st.error("**Start lab failed** (full Docker message below). Fix the conflict, then Start again.")
            st.code(err[-2500:], language="text")
            if st.button("Dismiss start error", key="dismiss_start_err"):
                st.session_state.pop("last_start_error", None)
                st.rerun()

    sc = _scenario_list(h)
    c = st.columns(4)
    c[0].metric("Docker images", f"{sum(imgs.values())}/{len(imgs) or 3}")
    c[1].metric("Prepared", "yes" if r["prepared"] else "no")
    c[2].metric("Containers up", str(sum(1 for v in containers.values() if v)))
    scen_label = "Scenario" if len(sc) <= 1 else "Scenarios"
    c[3].metric(scen_label, ", ".join(sc) if sc else (r["active"] or "—"))
    active_note = f" · active **{r['active']}**" if r["active"] and r["running"] else ""
    st.caption(
        f"Lab **{h.lab}** · zone size **{cfg('zone_size', 'small')}** · "
        f"scenarios **{', '.join(sc) or '—'}**{active_note}"
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
    if build_job.is_running():
        build_live_panel()
        return
    if prepare_job.is_running(h):
        # Signing is in progress: show it live. The other tabs describe the previous Prepare, so they
        # wait until it ends (the page reruns by itself and opens the replay).
        prepare_live_panel(h)
        return
    overview, replay, results, activity = st.tabs(["Overview", "Signing replay", "Results", "Activity log"])
    with overview:
        setup_overview(h, stt)
    with replay:
        setup_replay(h, key="tab")
    with results:
        setup_results(h)
    with activity:
        activity_tab(h)


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
    m[2].metric("Max answer", decode.format_bytes(summary["max_bytes"]),
                help="Largest DNS message in this diagram (reassembled length, not one TCP segment).")
    m[3].metric("Span", f"{summary['span_ms']} ms",
                help="Last drawn hop time minus first — pcap timeline width, not Queries latency_ms.")
    m[4].metric("MTL-FULL", summary["mtl_full"])
    st.caption(
        "Solid = query · dashed = response · amber = MTL-FULL. "
        "Each label sits on the **sender**. Arrows are in capture time order: a large TCP "
        "answer can finish after the next query has already gone out, so a late Root arrow "
        "is still Root’s answer (often a negative proof), not the SLD’s. "
        "Hover an arrow for exact bytes, t, and packet number."
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
        t_start = time.perf_counter()
        # Visible progress next to the button: each step is written as it starts, with how long the last one took.
        box = st.status(f"Running `{qname} {qtype}` · {path}", expanded=True)
        step_t: list = [None]

        def step(text: str | None) -> None:
            """Close the previous step with its duration, then announce the next one (None just closes)."""
            now = time.perf_counter()
            if step_t[0] is not None:
                box.write(f"   ↳ {now - step_t[0]:.1f} s")
            step_t[0] = now if text else None
            if text:
                box.write(text)
                box.update(label=text)

        try:
            if recurse:
                try:
                    step("1 · Reading the resolver's counters before the lookup")
                    driver.unbound_stats(h)
                except Exception:  # noqa: BLE001
                    pass
            if capture:
                step(f"2 · Starting packet capture on {'Unbound' if recurse else 'the client'}")
                pcap_path = driver.start_capture(h, server=server, label=cfg("capture_label", ""))
            step(f"3 · Sending the query to {server}" + (" (Unbound resolves it from the root down)" if recurse else ""))
            row = driver.probe(
                h, qname, qtype, server=server, mtl_full=mtl_full, dnssec=dnssec, recurse=recurse,
            )
            box.write(f"   answered in {row.get('latency_ms', 0):.1f} ms · {row.get('rcode')}"
                      f" · AD={'yes' if row.get('ad') else 'no'}")
            row.update(scenario=h.active_scenario(), path=path, at=time.strftime("%H:%M:%S"))
            if recurse:
                try:
                    step("4 · Reading the resolver's counters after the lookup")
                    row["unbound_stats"] = driver.unbound_stats_delta({}, driver.unbound_stats(h))
                except Exception:  # noqa: BLE001
                    row["unbound_stats"] = {}
            dropped = 0
            if capture:
                step("5 · Stopping the capture and decoding the packets")
                pcap_path, dropped = driver.stop_capture(h)
                if pcap_path and Path(pcap_path).exists():
                    try:
                        df = decode.decode_pcap(pcap_path)
                        st.session_state.last_story = decode.build_story(df)
                        st.session_state.last_wire = decode.wire_summary(df)
                        box.write(f"   {len(df)} packets captured")
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
            if pcap_path:
                st.session_state.pcap_focus = str(pcap_path)  # Results opens on this query's capture
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
            step(None)
            box.update(label=f"Done in {time.perf_counter() - t_start:.1f} s · {row.get('rcode')} · "
                             f"AD={'yes' if row.get('ad') else 'no'} · {size:,} B", state="complete", expanded=False)
        except Exception as e:  # noqa: BLE001
            box.update(label="Query failed", state="error", expanded=True)
            st.error(str(e)[:800])
            activity("err", "Query failed", str(e)[:2000], phase="probe", source="probe", h=h)
            if capture:
                try:
                    driver.stop_capture(h)
                except Exception:  # noqa: BLE001
                    pass

    row = st.session_state.get("last_query")
    if row:
        shown = row.get("scenario")
        st.markdown(f"**Last result** · `{row.get('qname')} {row.get('qtype')}` · {row.get('path', '')} · "
                    f"scenario **{shown or '?'}** · {row.get('at', '')}")
        now = h.active_scenario()
        if shown and now and shown != now:
            st.warning(f"This result was taken on **{shown}**; the lab is now on **{now}**. Run the query again.")
        elif (row.get("qname"), row.get("qtype")) != (qname, qtype) or row.get("path") != path:
            st.caption("The query above has changed since this result. Press Run query to refresh it.")
        m = st.columns(5)
        m[0].metric("RCODE", row.get("rcode", "—"))
        m[1].metric("AD", "YES" if row.get("ad") else "no")
        m[2].metric("Transport", row.get("transport", "—"))
        m[3].metric("Bytes", f"{(row.get('tcp_response_bytes') or row.get('response_bytes') or 0):,}")
        m[4].metric("Latency", f"{row.get('latency_ms', 0):.1f} ms")
        st.caption("Full history, packet decode and sequence diagram are in the Results tab.")


def dig_panel(h: driver.LabHandle, stt: dict) -> None:
    st.caption("Run dig from the client container. Without an @server it asks Unbound (10.53.0.53).")
    if not _gate(stt, "dig"):
        return

    presets = driver.dig_presets(h)
    if "dig_cmd" not in st.session_state:
        st.session_state.dig_cmd = presets[0]
    st.selectbox(
        "Examples", presets, key="dig_preset",
        on_change=lambda: st.session_state.update(dig_cmd=st.session_state.dig_preset),
    )
    with st.form("dig_form", border=False):
        line = st.text_input("$", key="dig_cmd")
        c1, c2 = st.columns([1, 3])
        capture = c2.checkbox("Capture packets (shows up in Results)", value=True, key="dig_capture")
        run = c1.form_submit_button("Run dig", type="primary")

    if run:
        pcap_path = None
        try:
            argv = driver.dig_argv(line)
        except ValueError as e:
            st.error(str(e))
        else:
            activity("step", f"dig {line}", phase="probe", source="dig", h=h)
            try:
                if capture:
                    server = next(p[1:] for p in argv if p.startswith("@"))
                    pcap_path = driver.start_capture(h, server=server, label=cfg("capture_label", ""))
                res = driver.dig(h, line)
                if capture:
                    pcap_path, _ = driver.stop_capture(h)
                    st.session_state.last_pcap = str(pcap_path) if pcap_path else None
                    if pcap_path:
                        st.session_state.pcap_focus = str(pcap_path)
                st.session_state.setdefault("dig_log", []).insert(0, res)
                activity("ok" if res["exit"] == 0 else "err", res["command"],
                         res["output"][:2000], phase="probe", source="dig", h=h)
            except Exception as e:  # noqa: BLE001
                st.error(str(e)[:800])
                activity("err", "dig failed", str(e)[:2000], phase="probe", source="dig", h=h)
                if capture:
                    try:
                        driver.stop_capture(h)
                    except Exception:  # noqa: BLE001
                        pass

    log = st.session_state.get("dig_log", [])
    if log:
        st.code("\n\n".join(f"$ {r['command']}\n{r['output']}" for r in log[:10]), language="text")
        if st.button("Clear terminal"):
            st.session_state.dig_log = []
            st.rerun()
    else:
        st.caption("No output yet.")


def cache_panel(h: driver.LabHandle, stt: dict) -> None:
    st.caption("Compare a first lookup (cold cache) with repeats (warm cache). Flush cache in the sidebar empties the resolver on its own.")
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
    captures = driver.list_pcaps(h)
    options = [str(p) for p in captures]
    last = st.session_state.get("last_pcap")
    if last and last not in options and Path(last).exists():
        options = [last] + options
    return options


def _pcap_folder_banner(h: driver.LabHandle, options: list[str]) -> None:
    """Make the active results folder obvious; offer a one-click jump if captures sit elsewhere."""
    st.caption(
        f"Captures for lab **`{h.tag}`** · folder "
        f"`results/{h.tag}/live-dashboard` · **{len(options)}** file(s). "
        f"Image version **{h.stack}** · zone **{cfg('zone_size', 'small')}**."
    )
    inv = driver.live_capture_inventory()
    others = [r for r in inv if r["tag"] != h.tag]
    if not others:
        return
    with st.expander(
        f"Other labs still have captures ({sum(r['count'] for r in others)} file(s)) — "
        "not deleted; this page only lists the active lab",
        expanded=not options,
    ):
        for r in others[:8]:
            label = f"**{r['tag']}** · {r['count']} pcap(s) · newest `{r['names'][0] if r['names'] else '?'}`"
            c1, c2 = st.columns([4, 1])
            c1.markdown(label)
            can_switch = bool(r.get("stack") and r.get("zone_size"))
            if can_switch and c2.button("Open", key=f"open_lab_{r['tag']}"):
                _store()["stack"] = r["stack"]
                _store()["zone_size"] = r["zone_size"]
                st.session_state.w_stack = r["stack"]
                st.session_state.w_zone_size = r["zone_size"]
                st.session_state.pop("lab_handle", None)
                for k in _PCAP_KEYS:
                    st.session_state.pop(k, None)
                st.rerun()


def _pcap_name(p: str) -> str:
    return Path(p).name


@st.cache_data(show_spinner=False, max_entries=16)
def _decoded(path: str, mtime_ns: int) -> pd.DataFrame:
    """Decode a capture once per file version; reruns (tab clicks, polling) reuse the result."""
    return decode.decode_pcap(path)


@st.cache_data(show_spinner=False, max_entries=16)
def _sequence(path: str, mtime_ns: int) -> list:
    df = _decoded(path, mtime_ns)
    return decode.build_sequence_steps(df) if not df.empty else []


def _mtime_ns(path: str) -> int:
    try:
        return Path(path).stat().st_mtime_ns
    except OSError:
        return 0


def _sync_pcap_choices(options: list[str]) -> None:
    """Point both capture pickers at the capture of the query just run; otherwise keep the user's pick;
    otherwise (nothing picked, or the picked file is gone) the newest capture."""
    focus = st.session_state.pop("pcap_focus", None)
    for key in ("pcap_story_choice", "pcap_seq_choice"):
        if focus in options:
            st.session_state[key] = focus
        elif st.session_state.get(key) not in options and options:
            st.session_state[key] = options[0]


def _query_for_pcap(pcap: str) -> dict | None:
    for r in reversed(st.session_state.get("query_log") or []):
        if r.get("pcap") == pcap:
            return r
    return None


def _capture_context(pcap: str) -> str:
    q = _query_for_pcap(pcap)
    if not q:
        return f"`{Path(pcap).name}` (a dig or earlier capture; no saved query is linked to it)"
    return (f"`{q.get('qname')} {q.get('qtype')}` · {q.get('path', '')} · scenario **{q.get('scenario') or '?'}** · "
            f"{q.get('at', '')} · {q.get('rcode', '')}")


def pcap_decode_view(h: driver.LabHandle, options: list[str]) -> None:
    if not options:
        st.caption("No captures yet — run a Live query with Capture on.")
        return
    choice = st.selectbox("Capture", options, key="pcap_story_choice", format_func=_pcap_name)
    st.caption(_capture_context(choice))
    hide_tcp = st.checkbox("Hide TCP handshake noise", value=True, key="pcap_hide_tcp")
    df = _decoded(choice, _mtime_ns(choice))
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
    cols = [c for c in ["#", "ms", "phase_label", "hop", "proto", "bytes", "dns_bytes",
                        "summary", "ad", "rrsigs"] if c in show.columns]
    st.caption(
        "**bytes** = this IP/UDP/TCP payload on the wire · "
        "**dns_bytes** = DNS message length (TCP length prefix / UDP DNS size). "
        "Large MTL answers often span several TCP segments — do not read Max answer from a single **bytes** cell."
    )
    # Force horizontal scroll: Streamlit squeezes wide text columns unless widths are set.
    cfg = {
        "summary": st.column_config.TextColumn("summary", width="large"),
        "rrsigs": st.column_config.TextColumn("rrsigs", width="medium"),
        "phase_label": st.column_config.TextColumn("phase_label", width="medium"),
        "hop": st.column_config.TextColumn("hop", width="medium"),
        "bytes": st.column_config.NumberColumn("bytes", help="Wire payload in this packet/segment"),
        "dns_bytes": st.column_config.NumberColumn(
            "dns_bytes", help="Reassembled DNS message length when known"),
    }
    st.dataframe(
        show[cols], width="stretch", hide_index=True, height=420,
        column_config={k: v for k, v in cfg.items() if k in cols},
    )


def pcap_sequence_view(h: driver.LabHandle, options: list[str]) -> None:
    if not options:
        st.caption("No captures yet — run a Live query with Capture on.")
        return
    seq_choice = st.selectbox("Capture", options, key="pcap_seq_choice", format_func=_pcap_name)
    st.caption(_capture_context(seq_choice))
    steps = _sequence(seq_choice, _mtime_ns(seq_choice))
    if not steps:
        if _decoded(seq_choice, _mtime_ns(seq_choice)).empty:
            st.warning("This capture has no DNS packets.")
        else:
            st.warning("Decoded the capture, but no Client/Unbound/Root/TLD/SLD hops "
                       "were recognized for a sequence diagram.")
        return
    st.session_state.last_seq_steps, st.session_state.last_seq_pcap = steps, seq_choice
    st.caption(f"{len(steps)} messages from this capture")
    show_sequence_diagram(steps)


def live_results(h: driver.LabHandle) -> None:
    queries, packets, sequence = st.tabs(["Queries", "Packet decode", "Sequence diagram"])
    options = _pcap_options(h)
    _sync_pcap_choices(options)
    _pcap_folder_banner(h, options)
    # Re-hydrate query log from disk after refresh (session_state is empty; session.json is not).
    if "query_log" not in st.session_state:
        st.session_state.query_log = list(driver.load_session(h).get("queries") or [])
    with queries:
        qlog = driver.session_queries(h, st.session_state.get("query_log"))
        if qlog and not st.session_state.get("query_log"):
            st.session_state.query_log = list(qlog)
        if qlog:
            cur = st.session_state.get("last_query") or qlog[-1]
            st.markdown(f"**Current query** · `{cur.get('qname')} {cur.get('qtype')}` · {cur.get('path', '')} · "
                        f"scenario **{cur.get('scenario') or '?'}** · {cur.get('rcode', '')} · "
                        f"AD={'yes' if cur.get('ad') else 'no'} · {cur.get('at', '')}")
            qdf = pd.DataFrame(qlog).iloc[::-1]  # newest first
            cols = [c for c in ["at", "scenario", "path", "qname", "qtype", "rcode", "ad", "latency_ms",
                                "response_bytes", "tcp_response_bytes", "transport"] if c in qdf.columns]
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
    query, dig_tab, cache, results = st.tabs(["Query", "dig terminal", "Cold vs warm", "Results"])
    with query:
        query_panel(h, stt)
    with dig_tab:
        dig_panel(h, stt)
    with cache:
        cache_panel(h, stt)
    with results:
        live_results(h)
    _activity_expander(h)


# ─────────────────────────── BENCHMARK ───────────────────────────

def _suite_params() -> dict:
    return {
        "sizes": sorted(int(n) for n in (cfg("bench_sizes") or SUITE_DEFAULT_SIZES)),
        "scenarios": list(cfg("bench_scenarios") or ["ecdsa", "slh-dsa", "mtl"]),
        "trials": int(cfg("bench_trials", 3)),
        "sign_trials": int(cfg("bench_sign_trials", suite_mod.DEFAULT_SIGN_TRIALS)),
        "sample_names": int(cfg("bench_sample", suite_mod.DEFAULT_SAMPLE_NAMES)),
        "n_queries": int(cfg("bench_queries", 500)),
        "jobs": int(cfg("bench_jobs", 1)),
        "networks": list(cfg("bench_networks") or ["lan"]),
        "udp": int(cfg("bench_udp", 1232)),
    }


def _bench_plan() -> None:
    p = _suite_params()
    label = driver.sanitize_label(cfg("run_label", ""))[:30]
    with st.container(border=True):
        st.markdown("**Planned benchmark**")
        a = st.columns(5)
        a[0].metric("Dataset sizes", len(p["sizes"]))
        a[1].metric("Scenarios", len(p["scenarios"]))
        a[2].metric("Measurement trials", p["trials"])
        a[3].metric("Signing trials", p["sign_trials"])
        a[4].metric("Lookups / pass", p["n_queries"])
        rows = []
        for n in p["sizes"]:
            s = driver.shape_stats(suite_mod.bench_shape(n), p["scenarios"], p["jobs"])
            rows.append({"Dataset": _size_label(n), "Zones": s["zones"], "Leaf zones": suite_mod.bench_shape(n)["sld_count"],
                         "Est. RRSIGs": s["est_rrsigs"],
                         "Est. signing": driver.format_duration(suite_mod.estimate_seconds(
                             [n], p["scenarios"], p["jobs"], p["sign_trials"], p["sample_names"]))})
        if rows:
            st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)
        total = suite_mod.estimate_seconds(p["sizes"], p["scenarios"], p["jobs"], p["sign_trials"], p["sample_names"])
        passes = len(p["scenarios"]) * len(p["networks"]) * p["trials"] * 2 * max(1, len(p["sizes"]))
        st.caption(
            f"Signing and sign trials about **{driver.format_duration(total)}** in total, plus measuring "
            f"({passes} capture passes, about {passes * p['n_queries']:,} lookups). "
            f"Name **{label or '(none: date and time only)'}** · networks {', '.join(p['networks'])} · "
            f"UDP limit {p['udp']}"
        )
        w = _workload()
        st.caption(
            f"Workload: NXDOMAIN **{round(w['nx_fraction'] * 100)}%** · zone skew **{w['zone_zipf_s']:g}** · "
            f"name skew **{w['name_zipf_s']:g}** · timeout **{w['timeout_s']:g} s**"
            + ("" if _workload_is_default() else " · _custom values_")
        )
        shown = {n: {**driver.PROFILE_DEFAULTS[n], **_profiles().get(n, {})} for n in p["networks"]}
        if shown:
            st.dataframe(
                pd.DataFrame(shown).T.rename(columns=dict(PROFILE_FIELDS)).rename_axis("network"),
                width="stretch",
            )


def _cancel_suite(suite_id: str) -> None:
    suite_mod.cancel(suite_id)
    activity("warn", f"Benchmark cancelled · {suite_id}", phase="run", source="suite")


@st.fragment(run_every=3)
def _suite_progress(suite_id: str) -> None:
    s = suite_mod.status(suite_id)
    state = s.get("state", "unknown")
    if state not in ("running", "starting"):
        st.rerun()  # whole page: the sidebar and Results pick up the finished suite
    total = max(1, int(s.get("total", 1)))
    done = int(s.get("done", 0))
    elapsed = time.time() - float(s.get("started") or time.time())
    with st.container(border=True):
        st.markdown(f"**Benchmark running** · {suite_id}")
        st.progress(min(done / total, 1.0), text=f"{done} of {total} steps · {s.get('step', '')}")
        st.caption(f"Elapsed {driver.format_duration(elapsed).lstrip('~')}. You can leave this page; the benchmark "
                   "keeps running and the Results tab fills in when it finishes.")
        st.button("Cancel benchmark", on_click=_cancel_suite, args=(suite_id,), key="btn_cancel_suite")
        log = SUITES_DIR / suite_id / "progress.log"
        if log.is_file():
            with st.expander("Progress log"):
                st.code(log.read_text(encoding="utf-8", errors="replace")[-3000:], language="text")


def benchmark_run(h: driver.LabHandle, stt: dict) -> None:
    r = readiness(stt)
    live = suite_mod.running_suite()
    if live:
        _suite_progress(live["id"])
        return
    last = next(iter(suite_mod.list_suites()), None)
    if last and last["state"] in ("failed", "stopped", "cancelled"):
        s = suite_mod.status(last["id"])
        st.warning(f"The last benchmark ({last['title']}) {s.get('state')}: {s.get('error') or s.get('step', '')}")
    if not r["images"]:
        st.warning("The lab images are not built yet. Build them once in **Setup** (step 1); the benchmark "
                   "does the rest itself.")
        st.button("Go to Setup", on_click=_go, args=("setup",), key="bench_to_setup")
    st.caption("Set the options in the sidebar, then press **Run benchmark**. It signs, starts and stops the "
               "lab on its own, one dataset size after another.")
    _bench_plan()


def _fmt_ci(med: float | None, lo: float | None, hi: float | None) -> str:
    if med is None or pd.isna(med):
        return "—"
    base = compare.fmt_seconds(med)
    if lo is None or hi is None or pd.isna(lo) or pd.isna(hi) or lo == hi:
        return base
    return f"{base} ({compare.fmt_seconds(lo)}–{compare.fmt_seconds(hi)})"


def _signing_stats_table(stats: pd.DataFrame) -> pd.DataFrame:
    return pd.DataFrame({
        "Scenario": stats["scenario"],
        "Trials": stats["trials"],
        "Sample (names)": stats["sample_names"],
        "Sign per RRSIG (ms)": stats["sign_ms_per_rrsig"].round(3),
        "Fixed per zone (s)": stats["sign_fixed_s"].round(3),
        "Dataset sign, estimated (95% CI)": [_fmt_ci(m, a, b) for m, a, b in
                                             zip(stats["est_sign_s"], stats["est_sign_lo"], stats["est_sign_hi"])],
        "Dataset verify, estimated (95% CI)": [_fmt_ci(m, a, b) for m, a, b in
                                               zip(stats["est_verify_s"], stats["est_verify_lo"], stats["est_verify_hi"])],
        "Full zones sign, measured once": stats["full_sign_s"].map(compare.fmt_seconds),
        "Full zones verify, measured once": stats["full_verify_s"].map(compare.fmt_seconds),
        "Signed size": stats["signed_bytes"].map(compare.fmt_bytes),
    })


def _suite_settings(sd: dict) -> None:
    s = sd["suite"]
    with st.expander("Settings and environment recorded for this benchmark"):
        st.markdown(
            f"**Dataset sizes** {', '.join(f'{n:,}' for n in s['sizes'])} data names · **Scenarios** "
            f"{', '.join(s['scenarios'])} · **Stack** {s['stack']}  \n"
            f"**Measurement trials** {s['trials']} (cold then warm) · **Lookups per pass** {s['n_queries']} · "
            f"**Networks** {', '.join(s['networks'])} · **UDP limit** {s['udp']}  \n"
            f"**Signing trials** {s['sign_trials']} on samples of {s['sample_names']} names (dataset time is an "
            f"extrapolation, the full zones are also signed once)"
        )
        wl = s.get("workload") or driver.WORKLOAD_DEFAULTS
        st.markdown(
            f"**Workload** NXDOMAIN {round(float(wl['nx_fraction']) * 100)}% · zone skew {wl['zone_zipf_s']} · "
            f"name skew {wl['name_zipf_s']} · timeout {wl['timeout_s']} s · seeded (same seed for every scenario)"
        )
        hier = [{"Dataset": f"{n:,}", "Leaf zones": suite_mod.bench_shape(n)["sld_count"],
                 "Names per leaf zone": ", ".join(str(x) for x in suite_mod.bench_shape(n)["sld_sizes"])}
                for n in s["sizes"]]
        st.dataframe(pd.DataFrame(hier), width="stretch", hide_index=True)
        first = next(iter(sd["runs"].values()), {})
        env = first.get("environment") or {}
        if env:
            dock = env.get("docker") or {}
            st.markdown(
                f"**Environment** Docker {dock.get('ServerVersion')} · {dock.get('NCPU')} CPUs · "
                f"{round((dock.get('MemTotal') or 0) / 1024 ** 3, 1)} GiB · host {s.get('host', {}).get('platform', '')}  \n"
                f"**Pinned images** " + ", ".join(sorted({(v.get('image') or '') for v in (env.get('images') or {}).values()}))
            )
        cpus = ((first.get("lab") or {}).get("cpusets")) or {}
        if cpus:
            st.caption(f"CPU pinning: {cpus}")
        profs = {n: v for n, v in (s.get("profiles") or {}).items() if n in s["networks"]}
        if profs:
            st.dataframe(pd.DataFrame(profs).T.rename_axis("network"), width="stretch")


def benchmark_results(h: driver.LabHandle) -> None:
    suites = [s for s in suite_mod.list_suites() if s["complete"]]
    if not suites:
        st.info("No finished benchmark yet. Choose the options in the sidebar and press **Run benchmark**.")
        return
    by = {s["id"]: s for s in suites}
    if st.session_state.get("bench_suite_pick") not in by:
        st.session_state.pop("bench_suite_pick", None)
    pick = st.selectbox("Benchmark", list(by), key="bench_suite_pick", format_func=lambda i: by[i]["title"])
    sd = compare.load_suite(by[pick]["path"])
    if sd is None:
        st.warning("This benchmark has no stored results.")
        return
    s = sd["suite"]
    m = st.columns(4)
    m[0].metric("Name", s.get("label") or "—")
    m[1].metric("Started", by[pick]["when"])
    m[2].metric("Duration", driver.format_duration(s.get("seconds", 0)).lstrip("~"))
    m[3].metric("Dataset sizes", ", ".join(f"{n:,}" for n in sd["datasets"]))
    _suite_settings(sd)
    st.button("Open in Compare →", on_click=_open_in_compare, args=(pick,), key="bench_to_compare")

    stats = compare.signing_trial_stats(sd["trials"], sd["full"])
    tabs = st.tabs([f"{n:,} names" for n in sd["datasets"]])
    for tab, n in zip(tabs, sd["datasets"]):
        with tab:
            st.markdown("**Signing and verification**")
            ds = stats[stats["dataset"] == n]
            if ds.empty:
                st.caption("No signing data.")
            else:
                st.dataframe(_signing_stats_table(ds), width="stretch", hide_index=True)
                jobs = int(s.get("jobs", 1))
                st.caption("Estimated = from the repeated sample trials (run one at a time), extrapolated to every "
                           "zone of the dataset. Measured once = the full zones that the lab served, signed one time "
                           f"with {jobs} parallel job(s)"
                           + ("" if jobs == 1 else "; with more than one job these timings are inflated by contention")
                           + ".")
            summary = sd["bench"].get(n)
            if summary is not None and not summary.empty:
                st.markdown("**Resolver measurements**")
                cols = [c for c in ["scenario", "profile", "pass", "udp_limit", "trials", "median_ms", "p95_ms",
                                    "upstream_bytes", "upstream_queries", "upstream_truncated", "validated_pct",
                                    "servfail", "timeouts"] if c in summary.columns]
                st.dataframe(summary[cols], width="stretch", hide_index=True)
                _bench_charts(summary)
    report_html = by[pick]["path"] / "report.html"
    report_md = by[pick]["path"] / "report.md"
    if not report_html.is_file() or not report_md.is_file():
        try:
            from live_lab import suite_report
            suite_report.write(by[pick]["path"])
            report_html = by[pick]["path"] / "report.html"
            report_md = by[pick]["path"] / "report.md"
        except Exception as e:  # noqa: BLE001
            st.caption(f"Report not generated yet: {e}")
    d0, d1, d2 = st.columns(3)
    if report_html.is_file():
        d0.download_button("Download report (HTML)", data=report_html.read_bytes(),
                           file_name=f"{pick}-report.html", mime="text/html", key="bench_dl_report_html")
    elif report_md.is_file():
        d0.download_button("Download report (Markdown)", data=report_md.read_text(encoding="utf-8"),
                           file_name=f"{pick}-report.md", mime="text/markdown", key="bench_dl_report_md")
    d1.download_button("Download signing trials (CSV)", data=sd["trials"].to_csv(index=False),
                       file_name=f"{pick}-signing-trials.csv", mime="text/csv", key="bench_dl_trials")
    d2.download_button("Download full-zone signing (CSV)", data=sd["full"].to_csv(index=False),
                       file_name=f"{pick}-signing-full.csv", mime="text/csv", key="bench_dl_full")
    if report_html.is_file():
        st.caption(f"Reproducible report on disk: `{report_html}` (also `report.md` and `figures/`).")


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


def _open_in_compare(suite_id: str) -> None:
    _store()["cmp_source"] = "suite"
    _store()["cmp_suite"] = suite_id
    st.session_state.pop("w_cmp_source", None)
    st.session_state.pop("w_cmp_suite", None)
    _go("compare")


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
    suites = [s for s in suite_mod.list_suites() if s["complete"]]
    source = "lab"
    if suites:
        source = sb(st.sidebar.radio, "cmp_source", "suite", "Source", options=["suite", "lab"],
                    format_func=lambda x: {"suite": "Benchmark (dataset sizes)", "lab": "A single lab (Live / older runs)"}[x])
    summary, names = None, []
    if source == "suite":
        _hint("Everything comes from one finished benchmark: signing trials, bytes and cache, per dataset size.")
        by_s = {s["id"]: s for s in suites}
        sid = sb(st.sidebar.selectbox, "cmp_suite", next(iter(by_s)), "Benchmark", options=list(by_s),
                 format_func=lambda i: by_s[i]["title"])
        sd = compare.load_suite(by_s[sid]["path"]) if sid in by_s else None
        datasets = sd["datasets"] if sd else []
        ds = sb(st.sidebar.selectbox, "cmp_dataset", datasets[len(datasets) // 2] if datasets else None,
                "Dataset size", options=datasets, format_func=lambda n: f"{n:,} names")
        summary = sd["bench"].get(ds) if sd else None
        if sd:
            names = list(sd["trials"]["scenario"].unique()) if not sd["trials"].empty else []
    else:
        _hint("Signing numbers come from the lab's last Prepare; bytes and cache from a saved benchmark run.")
        labs = [x["tag"] for x in driver.list_labs()]
        default_lab = h.tag if h.tag in labs else (labs[0] if labs else h.tag)
        tag = sb(st.sidebar.selectbox, "cmp_lab", default_lab, "Lab", options=labs or [h.tag],
                 help="Any lab folder that has signing data or saved runs.")
        runs = [r for r in driver.list_runs(h, tag) if (r["path"] / "summary.csv").is_file()]
        by = {r["folder"]: r for r in runs}
        folder = sb(st.sidebar.selectbox, "cmp_run", next(iter(by), None), "Benchmark run", options=list(by),
                    format_func=lambda f: by[f]["title"],
                    help="Bytes, truncation, cache and latency come from this run.")
        summary = _cmp_summary(tag, folder)
        names = list(compare.signing_by_scenario(driver.manifest_rows(h, tag)).scenario)

    if summary is not None and not summary.empty:
        profiles = [str(p) for p in summary["profile"].dropna().unique()] if "profile" in summary else []
        sb(st.sidebar.selectbox, "cmp_profile", profiles[0] if profiles else None, "Network", options=profiles)
        udps = [int(u) for u in summary["udp_limit"].dropna().unique()] if "udp_limit" in summary else []
        sb(st.sidebar.selectbox, "cmp_udp", udps[0] if udps else None, "UDP size limit", options=udps)

    names += list(summary["scenario"].unique()) if summary is not None else []
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
    base, cand = cfg("cmp_base"), cfg("cmp_cand")
    use_suite = any(s["complete"] for s in suite_mod.list_suites()) and cfg("cmp_source", "suite") == "suite"
    sd = None
    prof, udp = cfg("cmp_profile"), cfg("cmp_udp")

    if use_suite:
        by_s = {s["id"]: s for s in suite_mod.list_suites() if s["complete"]}
        sd = compare.load_suite(by_s[cfg("cmp_suite")]["path"]) if cfg("cmp_suite") in by_s else None
        ds = cfg("cmp_dataset")
        if sd is None or ds is None:
            st.info("Pick a finished benchmark and a dataset size in the sidebar.")
            return
        df = compare.suite_frame(sd, int(ds), prof, udp)
        man_rows = sd["full"][sd["full"]["dataset"] == ds].to_dict("records") if not sd["full"].empty else []
        n_trials = int(df["sign_trials"].max()) if "sign_trials" in df and df["sign_trials"].notna().any() else 0
        st.caption(f"Benchmark **{by_s[cfg('cmp_suite')]['title']}** · **{int(ds):,} data names** · "
                   f"network {prof}, UDP {udp} · signing and verification are estimated from {n_trials} trial(s) "
                   "on sample zones; bytes and cache are measured in the resolver run")
    else:
        tag, folder = cfg("cmp_lab"), cfg("cmp_run")
        man_rows = driver.manifest_rows(h, tag)
        sign = compare.signing_by_scenario(man_rows)
        summary = _cmp_summary(tag, folder)
        bench = compare.bench_by_scenario(summary, prof, udp) if summary is not None \
            else compare.bench_by_scenario(pd.DataFrame())
        df = compare.merge(sign, bench, compare.analytical_by_scenario(man_rows))
        if not df.empty:
            run_title = next((r["title"] for r in driver.list_runs(h, tag) if r["folder"] == folder), None)
            src_sign = f"last Prepare of **{tag}**" if not sign.empty else "no signing data for this lab"
            src_bench = f"run **{run_title}** ({prof}, UDP {udp})" if not bench.empty \
                else "no benchmark run with results for this lab"
            st.caption(f"Signing and verification: {src_sign} · Bytes, truncation, cache: {src_bench}")

    if df.empty:
        st.info("Nothing to compare yet. Run a **benchmark** in the Benchmark tile.")
        st.button("Go to Benchmark", on_click=_go, args=("benchmark",), key="cmp_to_bench")
        return

    if not (base and cand):
        st.warning("Pick a candidate and a baseline in the sidebar.")
        return

    st.markdown(f"#### {cand} vs {base}")
    cards = compare.headline(df, base, cand)
    if use_suite:
        cards[0]["help"] = "Estimated from repeated sample trials, extrapolated to the whole dataset (95% CI in the table)"
        cards[1]["help"] = "ldns-verify-zone, estimated the same way (offline check, not the resolver)"
    cols = st.columns(len(cards))
    for col, c in zip(cols, cards):
        col.metric(c["label"], c["value"], c["delta"], delta_color="off", delta_arrow="off", help=c["help"])
    missing = [c["label"] for c in cards if c["value"] == "—"]
    if missing:
        st.caption("No data for: " + ", ".join(missing) + ". "
                   "Signing and verification need Prepare for both scenarios; the rest need both in the benchmark run.")

    tab_names = ["At a glance", "Signing & size", "Bytes on the wire", "Cache & latency", "All numbers"]
    if use_suite:
        tab_names.insert(1, "Across sizes")
    made = st.tabs(tab_names)
    glance, signing, wire, cache, allnums = (made[0], *made[-4:])
    across = made[1] if use_suite else None

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
        if use_suite:
            st.markdown(":blue-badge[Estimated] sign and verify time from the repeated sample trials · "
                        ":green-badge[Measured] signed size and the single full signing run")
        else:
            st.markdown(":green-badge[Measured] from the last Prepare")
        sg = df.dropna(subset=["sign_s"]) if "sign_s" in df else df
        if sg.empty:
            st.info("No signing data: run Prepare in Setup.")
        else:
            c1, c2 = st.columns(2)
            long = sg.melt(id_vars="scenario", value_vars=["sign_s", "verify_s"], var_name="what", value_name="seconds")
            long["what"] = long["what"].map({"sign_s": "Sign zones", "verify_s": "Verify zones"})
            if use_suite:
                long = long.merge(sg[["scenario", "sign_lo_s", "sign_hi_s"]], on="scenario", how="left")
                is_sign = long["what"] == "Sign zones"
                long["err_hi"] = (long["sign_hi_s"] - long["seconds"]).where(is_sign)
                long["err_lo"] = (long["seconds"] - long["sign_lo_s"]).where(is_sign)
                f1 = px.bar(long, x="scenario", y="seconds", color="what", barmode="group", log_y=True,
                            error_y="err_hi", error_y_minus="err_lo", category_orders={"scenario": scen_order},
                            title="Signing and verification time, estimated (s, log; bars = 95% CI)")
            else:
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
            if use_suite:
                stt_ = compare.signing_trial_stats(sd["trials"], sd["full"])
                stt_ = stt_[stt_["dataset"] == int(ds)]
                st.markdown("**Signing trials in detail**")
                st.dataframe(_signing_stats_table(stt_), width="stretch", hide_index=True)
                st.caption("Estimated: each trial signs two sample zones; a line through them gives a fixed cost per "
                           "zone and a cost per RRSIG, applied to every zone of the dataset. Measured once: the full "
                           "zones the lab served, signed one time. Compare the two to judge the extrapolation.")
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

    if across is not None:
        with across:
            sc_all = compare.scaling_frame(sd, prof, udp)
            order = compare.order_scenarios(sc_all["scenario"].unique())
            st.markdown(f"##### {cand} vs {base} at every dataset size")
            rows = []
            for d in sd["datasets"]:
                cs = compare.headline(sc_all[sc_all["dataset"] == d].reset_index(drop=True), base, cand)
                rows.append({"Dataset": f"{d:,} names", **{c["label"]: c["value"] for c in cs}})
            st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)
            st.caption("Each cell reads as 'candidate is N times better than baseline' for that metric and dataset.")
            panels = [("sign_s", "Signing time, estimated (s)"), ("verify_s", "Zone verification, estimated (s)"),
                      ("signed_bytes", "Signed size (bytes)"), ("upstream_bytes", "Bytes on the wire, cold pass"),
                      ("cache_rrset", "Resolver RRset cache (bytes)")]
            left, right = st.columns(2)
            for i, (col, title) in enumerate(panels):
                data = sc_all.dropna(subset=[col])
                if data.empty:
                    continue
                f = px.line(data, x="dataset", y=col, color="scenario", markers=True, log_x=True, log_y=True,
                            color_discrete_map=colors, category_orders={"scenario": order}, title=title)
                f.update_xaxes(title="Data names", tickvals=sd["datasets"])
                (left if i % 2 == 0 else right).plotly_chart(_plot_cfg(f, 340), width="stretch")
            st.caption("Both axes are logarithmic: a straight line is power-law growth, and a constant gap between "
                       "two lines is a constant ratio. Sign and verify times are estimates; the rest are measured.")

    with allnums:
        t = compare.table(df)
        st.dataframe(t, width="stretch", hide_index=True)
        st.download_button("Download comparison (CSV)", data=df.to_csv(index=False), key="cmp_dl",
                           file_name=f"comparison-{cfg('cmp_suite') if use_suite else cfg('cmp_lab')}.csv", mime="text/csv")


# ─────────────────────────── RESET ───────────────────────────

def _fmt_size(n: int) -> str:
    return decode.format_bytes(n) if n else "0 B"


def _do_reset() -> None:
    """Callback for the Reset button: runs before the page redraws, so the preview is fresh."""
    ss = st.session_state
    h = _handle()
    scopes = {k: bool(ss.get(f"rs_{k}")) for k in
              ("session", "activity", "pcaps", "runs", "suites", "flush", "work")}
    if not any(scopes.values()):
        return
    removed = driver.clear_demo_data(
        h, session=scopes["session"], activity=scopes["activity"], pcaps=scopes["pcaps"],
        hide_prepare_metrics=True, work=scopes["work"], benchmarks=scopes["runs"], suites=scopes["suites"],
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
    if scopes["runs"] or scopes["work"] or scopes["suites"]:
        for k in ("last_run_dir", "bench_run_pick", "bench_flash", "bench_suite_pick"):
            ss.pop(k, None)
    names = {"session": "dashboard session", "activity": "activity log", "pcaps": "packet captures",
             "runs": "saved lab runs", "suites": "benchmarks of all dataset sizes", "flush": "resolver cache", "work": "signed zones and lab work"}
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
        _scope_row("runs", "Saved lab runs (older)",
                   f"{pv['runs']} run(s) · {_fmt_size(pv['run_bytes'])} for lab {h.tag}.", default=False)
        _scope_row("suites", "Benchmarks (dataset sizes)",
                   f"{pv['suites']} benchmark(s) · {_fmt_size(pv['suite_bytes'])} with their signed zones and runs."
                   if not suite_mod.running_suite() else "A benchmark is running; wait or cancel it first.",
                   default=False, disabled=bool(suite_mod.running_suite()) or not pv["suite_bytes"])
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
    chosen = [k for k in ("session", "activity", "pcaps", "runs", "suites", "flush", "work") if ss.get(f"rs_{k}")]
    destructive = [k for k in ("pcaps", "runs", "suites", "work") if ss.get(f"rs_{k}")]
    if destructive:
        wording = {"pcaps": f"{pv['pcaps']} capture file(s)", "runs": f"{pv['runs']} saved lab run(s)",
                   "suites": f"{pv['suites']} benchmark(s) of all dataset sizes",
                   "work": "the signed zones (the lab will stop)"}
        st.warning("This permanently deletes " + ", ".join(wording[k] for k in destructive) + ".")
        confirmed = st.checkbox("I understand this cannot be undone", key="rs_confirm")
    else:
        confirmed = True
    bench_blocks = bool(suite_mod.running_suite()) and any(k in chosen for k in ("runs", "suites", "work", "flush"))
    if bench_blocks:
        st.warning("A benchmark is running. Lab, run and benchmark resets are paused until it finishes or is cancelled.")
    st.button(
        f"Reset {len(chosen)} item(s)" if chosen else "Select something to reset",
        type="primary", disabled=not chosen or not confirmed or bench_blocks,
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
    m[3].metric("Runs removed", rm.get("benchmarks", 0) + rm.get("suites", 0))
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

def _is_tech_entry(e: dict) -> bool:
    if e.get("tech"):
        return True
    detail = e.get("detail") or ""
    title = (e.get("title") or "").lower()
    # Older sessions: raw Docker dumps were logged as fenced code blocks.
    if detail.lstrip().startswith("```"):
        return True
    if title.startswith(("build", "pull", "up", "prepare", "activate")) and "(" in title:
        return True
    return False


def activity_tab(h: driver.LabHandle) -> None:
    entries = st.session_state.get("activity") or []
    top = st.columns([1, 1, 2])
    if top[0].button("Clear", key="act_clear"):
        st.session_state.activity = []
        st.rerun()
    show_tech = top[1].checkbox("Technical details", value=False, key="act_tech",
                                help="Docker and tool output for debugging. Leave off for a normal demo.")
    if not entries:
        st.caption("Nothing yet. Use the sidebar steps — this list fills in as you go.")
        return

    visible = entries if show_tech else [e for e in entries if not _is_tech_entry(e)]
    if not visible:
        st.caption("Only technical lines so far. Turn on **Technical details** to see them.")
        return

    blob = "\n\n".join(
        f"[{e['t']}] {e['level']} {e['title']}\n{e.get('detail', '')}" for e in visible
    )
    top[2].download_button(
        "Download", data=blob, file_name=f"activity-{h.tag}.txt", mime="text/plain", key="act_dl",
    )

    for e in visible[:60]:
        icon = LEVEL_ICON.get(e["level"], "•")
        with st.container(border=True):
            st.markdown(f"{icon} **{e['t']}** · {e['title']}")
            detail = e.get("detail") or ""
            if not detail:
                continue
            if detail.lstrip().startswith("```"):
                with st.expander("Tool output"):
                    st.code(detail.strip().strip("`").replace("```", "").lstrip("\n"))
            else:
                st.caption(detail[:500])


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
    _fullscreen_icon()  # symbol only, top-right; no layout cost on the sidebar or page body
    symbol, _full = _brand()
    if symbol is not None:
        st.logo(symbol, icon_image=symbol, size="large")  # top-left on Home and on every tile
    _init_nav()
    _bootstrap_cfg_from_disk()
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
    if err and mode == "setup" and not st.session_state.get("shape_errors"):
        st.sidebar.error(err)

    if mode == "home":
        home_page(h, stt)
    else:
        PAGES[mode](h, stt)


if __name__ == "__main__":
    main()
