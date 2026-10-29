"""The CipherOps home page: what this is, what to do, what it found, and whether to trust it.

Built in that order. Every number comes from a run on disk through ``evidence`` (never typed here), measured, estimated
and analytical figures stay apart, and the offline harness is presented as the primary evidence with the live lab as the
resolver-level cross-check. Display words come from ``terms``. ``render`` takes a ``Context`` so this module does not
import the app.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

import pandas as pd
import streamlit as st

from live_lab import driver, evidence, terms

ROOT = evidence.ROOT
MAX_DOWNLOAD_BYTES = 2_000_000


@dataclass
class Context:
    h: Any                                        # the lab handle
    stt: dict                                     # lab status; stt["error"] set when Docker is unreachable
    ready: dict                                   # images / prepared / running / ready
    go: Callable[[str, dict | None], None]        # open a tile, optionally presetting its controls
    lab_strip: Callable[[], None]                 # draws the lab chips
    brand: Any = None                             # logo image or None
    results_dir: Path = evidence.RESULTS_DIR
    suites_dir: Path = evidence.SUITES_DIR


# ─────────────────────────── evidence, cached on file modification times ───────────────────────────

@st.cache_data(show_spinner=False)
def _evidence(fp: tuple, prepared: bool, running: bool, results_dir: str, suites_dir: str, lab_dir: str) -> dict:
    off = evidence.offline_runs(Path(results_dir))
    live = evidence.live_runs(Path(suites_dir))
    caps = evidence.captures(Path(lab_dir))
    out = {"offline": off, "live": live, "caps": caps, "cards": [], "live_cards": [], "live_notes": [],
           "card_error": ""}
    if off:
        try:
            out["cards"] = evidence.offline_cards(off[0])
        except Exception as e:  # noqa: BLE001 - a broken run must not break the home page
            out["card_error"] = f"{type(e).__name__}: {str(e)[:160]}"
    if live:
        try:
            out["live_cards"], out["live_notes"] = evidence.live_cards(live[0])
        except Exception as e:  # noqa: BLE001
            out["card_error"] = out["card_error"] or f"{type(e).__name__}: {str(e)[:160]}"
    out["rows"] = evidence.checklist(off, live, caps, {"prepared": prepared, "running": running})
    return out


@st.cache_data(ttl=30, show_spinner=False)
def _repo_state() -> tuple[str, bool]:
    try:
        sha = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=str(ROOT), text=True, timeout=3).strip()
        dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=str(ROOT), text=True, timeout=3).strip())
        return sha, dirty
    except Exception:  # noqa: BLE001
        return "", False


def _file_bytes(path: Path) -> bytes | None:
    try:
        return path.read_bytes() if 0 < path.stat().st_size <= MAX_DOWNLOAD_BYTES else None
    except OSError:
        return None


def _download(label: str, path: Path, key: str, mime: str = "text/plain") -> None:
    data = _file_bytes(path)
    if data is None:
        st.caption(f"`{evidence._rel(path, ROOT)}` (open it from the folder)")
        return
    st.download_button(label, data=data, file_name=path.name, mime=mime, key=key, width="stretch",
                       icon=":material/download:")


# ─────────────────────────── 1. header ───────────────────────────

def _header(ctx: Context) -> None:
    cols = st.columns([1, 5], vertical_alignment="center")
    if ctx.brand is not None:
        cols[0].image(ctx.brand, width=96)
    with cols[1]:
        st.markdown(f"# {terms.APP_NAME}")
        st.markdown(f"**{terms.QUESTION}**")
        links = " · ".join(f"[{n}]({u})" for n, u in terms.LINKS.items())
        st.caption(f"{links} · {terms.EVENT} · {terms.TEAM}")


# ─────────────────────────── 2. what brings you here ───────────────────────────

VISITOR_ICONS = {"evaluator": ":material/fact_check:", "presenter": ":material/slideshow:",
                 "reproducer": ":material/replay:", "explainer": ":material/school:"}


def _paths(visitor: str, ev: dict) -> list[dict]:
    """The ordered path for a visitor. A step with a ``tile`` gets a button to it; ``settings`` preset its controls."""
    has_live = bool(ev["live"])
    return {
        "evaluator": [
            {"text": "Read the headline results below and download the newest offline report."},
            {"text": "Check the deliverables checklist. Each row names its proof."},
            {"text": "Results, Algorithms side by side, data from the offline harness. Open the tabs At a glance, "
                     "Signing & verification, Bytes & truncation and Cache & latency.",
             "tile": "compare", "label": "Open Results", "settings": {"cmp_view": "algorithms", "cmp_src": "offline"}},
            {"text": "Results, data from the live lab, for resolver-level evidence." if has_live else
                     "Resolver-level evidence needs a live-lab run: Live-lab benchmark, Run.",
             "tile": "compare" if has_live else "benchmark", "label": "Open live-lab results" if has_live
             else "Open Live-lab benchmark", "settings": {"cmp_view": "algorithms", "cmp_src": "live"} if has_live else None},
        ],
        "presenter": [
            {"text": "Setup: build the images, Sign zones with the draft-06 stack, start the lab.",
             "tile": "setup", "label": "Open Setup"},
            {"text": "Demonstrate, Query: one lookup with SLH-DSA-MTL, then SLH-DSA, with a cold cache.",
             "tile": "live", "label": "Open Demonstrate"},
            {"text": "Demonstrate, Results: Packet decode, then Sequence diagram.", "tile": "live",
             "label": "Open Demonstrate"},
            {"text": "Demonstrate, Cold vs warm: the ladder cache at work.", "tile": "live", "label": "Open Demonstrate"},
        ],
        "reproducer": [
            {"text": "Offline: run the gate, then the quick or the full config. The run folder lands in "
                     "`results/runs/<id>/`.", "code": "bash scripts/run_benchmark.sh preflight\n"
                                                      "bash scripts/run_benchmark.sh configs/quick.yaml"},
            {"text": "Live lab: Setup, build the images, then Live-lab benchmark, Run.", "tile": "setup",
             "label": "Open Setup"},
            {"text": "Compare the new run with the reference run: its environment.json (offline) or suite.json "
                     "(live lab) against the other.", "tile": "compare", "label": "Open Results",
             "settings": {"cmp_view": "runs", "cmp_src": "offline"}},
        ],
        "explainer": [
            {"text": "Read the short panel below: how MTL works."},
            {"text": "Learn: six animated scenes, from a poisoned cache to the packet-size problem.", "tile": "learn",
             "label": "Open Learn"},
            {"text": "Setup, Signing replay, once a lab has been signed: how each zone is signed.", "tile": "setup",
             "label": "Open Setup"},
            {"text": "Terms, at the bottom of this page."},
        ],
    }[visitor]


def _choose_visitor() -> str:
    q = st.query_params.get("visitor")
    visitor = q if q in terms_visitors() else "evaluator"
    st.markdown("## What brings you here?")
    cols = st.columns(len(evidence.VISITORS))
    for col, (vid, label) in zip(cols, evidence.VISITORS.items()):
        selected = vid == visitor
        with col:
            if st.button(label, key=f"visitor_{vid}", icon=":material/check_circle:" if selected else VISITOR_ICONS[vid],
                         type="secondary", width="stretch", help="Selected" if selected else None):
                st.query_params["visitor"] = vid
                st.rerun()
    return visitor


def terms_visitors() -> list[str]:
    return list(evidence.VISITORS)


def _show_path(ctx: Context, visitor: str, ev: dict) -> None:
    ready = {"images": ctx.ready["images"], "prepared": ctx.ready["prepared"], "running": ctx.ready["running"],
             "docker": not ctx.stt.get("error")}
    step = evidence.next_step(visitor, ready, {"offline": len(ev["offline"]), "live": len(ev["live"])})
    with st.container(border=True):
        st.markdown(f"**Your path: {evidence.VISITORS[visitor]}**")
        for i, s in enumerate(_paths(visitor, ev), 1):
            c1, c2 = st.columns([5, 2], vertical_alignment="center")
            c1.markdown(f"{i}. {s['text']}")
            if s.get("code"):
                c1.code(s["code"], language="bash")
            if s.get("tile"):
                if c2.button(s["label"], key=f"path_{visitor}_{i}", type="secondary", width="stretch"):
                    ctx.go(s["tile"], s.get("settings"))
                    st.rerun()
        if visitor == "explainer":
            with st.expander("How MTL works", expanded=True):
                st.markdown(
                    "- A signature on every record is large, and one SLH-DSA signature alone overflows a DNS packet.\n"
                    "- MTL puts every record of a zone into a Merkle tree and signs only the tree's top, the "
                    "**signed ladder**, once.\n"
                    "- Each answer then carries a short **condensed signature**: the hash path from its record to the "
                    "ladder.\n"
                    "- A resolver fetches the **full signature** (condensed signature plus ladder) once, caches the "
                    "ladder, and checks later answers with hashing alone. That is a **warm cache**.\n"
                    "- A record added after the ladder was signed needs a new ladder, so the cost moves to updates. "
                    "The Evolving zone view in Results measures this.")
    st.markdown("##### Next step")
    st.caption(step["text"])
    if step["tile"]:
        if st.button(step["label"], key="next_step", type="primary", icon=":material/arrow_forward:"):
            ctx.go(step["tile"], step.get("settings"))
            st.rerun()


# ─────────────────────────── 3. headline results ───────────────────────────

def _provenance(card: evidence.Card, key: str) -> None:
    with st.popover("Provenance", width="stretch"):
        st.caption(f"Run `{card.run.id}`")
        for p in card.proof:
            _download(f"Download {p.name}", p, f"{key}_{p.name}")
        if card.report is not None:
            _download("Download report (HTML)", card.report, f"{key}_report", "text/html")


def _card(card: evidence.Card, key: str) -> None:
    with st.container(border=True):
        st.markdown(" ".join(terms.badge(b) for b in card.badges) + f"  **{card.title}**")
        st.markdown(f"### {card.value}")
        st.caption(card.detail)
        if card.note:
            st.caption(f":material/info: {card.note}")
        meta = f"Run `{card.run.id}` · {card.run.when}"
        if card.run.trials:
            meta += f" · {card.run.trials} trials"
        st.caption(meta + (f" · {card.ci}" if card.ci else ""))
        _provenance(card, key)


def _card_grid(cards: list[evidence.Card], prefix: str) -> None:
    """Two cards per row, so a value such as '742 ms vs 33.4 s' is never cut off."""
    for start in range(0, len(cards), 2):
        cols = st.columns(2)
        for col, (i, card) in zip(cols, enumerate(cards[start:start + 2], start)):
            with col:
                _card(card, f"{prefix}{i}")


def _headline(ctx: Context, ev: dict) -> None:
    st.markdown("## What it found")
    st.markdown(f"{terms.badge('primary')} Offline harness: calls the MTL library, liboqs and OpenSSL directly.")
    if not ev["offline"]:
        st.info("No offline run is stored on this machine, so there are no results to show. Produce one with "
                "`bash scripts/run_benchmark.sh configs/quick.yaml`. Nothing here is an example figure.")
    elif ev["card_error"] and not ev["cards"]:
        st.warning(f"The newest offline run could not be summarised ({ev['card_error']}). Open its report instead.")
    elif ev["cards"]:
        run = ev["cards"][0].run
        st.caption(f"Newest finished offline run: `{run.id}` ({run.when}), "
                   f"{', '.join(terms.dataset_label(d) for d in run.sizes)}.")
        _card_grid(ev["cards"], "hc")
    st.markdown(f"{terms.badge('indicative')} Live lab: a real resolver, real packets and cache. Byte and truncation "
                "counts are measured; read timings as ratios only.")
    if not ev["live"]:
        st.caption("No live-lab benchmark on this machine yet. Live-lab benchmark, Run, produces one.")
    else:
        for note in ev["live_notes"]:
            st.warning(note + ". Failed lookups are left out of the figures and counted here.")
        if ev["live_cards"]:
            run = ev["live_cards"][0].run
            st.caption(f"Newest finished live-lab benchmark: `{run.id}` ({run.when}).")
            _card_grid(ev["live_cards"], "lc")
        else:
            st.caption("The newest live-lab benchmark has no matching SLH-DSA-MTL and SLH-DSA figures.")


# ─────────────────────────── 4. deliverables checklist ───────────────────────────

STATE_BADGE = {evidence.FOUND: ":green-badge[Evidence found]", evidence.PARTIAL: ":orange-badge[Partial]",
               evidence.MISSING: ":gray-badge[Not found on this machine]"}


def _checklist(ctx: Context, ev: dict) -> None:
    st.markdown("## PS-036 deliverables")
    rows: list[evidence.Row] = ev["rows"]
    found = sum(r.state == evidence.FOUND for r in rows)
    st.caption(f"{found} of {len(rows)} expected outcomes have evidence on this machine. Status reflects files on this "
               "machine. *Not found* means no evidence here, not that the feature is missing.")
    head = st.columns([2, 5, 1.4, 2.6])
    for c, t in zip(head, ("Status", "Expected outcome and evidence", "", "Proof")):
        c.caption(t)
    for i, r in enumerate(rows):
        c1, c2, c3, c4 = st.columns([2, 5, 1.4, 2.6], vertical_alignment="center")
        c1.markdown(STATE_BADGE[r.state])
        c2.markdown(f"**{r.requirement}**  \n" + f"<small>{r.detail}" + (f" · run <code>{r.run_id}</code>" if r.run_id else "")
                    + "</small>" + (f"  \n<small>Missing: {r.missing}</small>" if r.missing else ""), unsafe_allow_html=True)
        if c3.button("Show where", key=f"chk_{i}", type="secondary", width="stretch", help=f"Open {r.requirement} in the dashboard"):
            ctx.go(r.tile, {"cmp_view": "algorithms", "cmp_src": "offline"} if r.tile == "compare" else None)
            st.rerun()
        with c4:
            if r.proof:
                _download(r.proof[0].name, r.proof[0], f"chk_proof_{i}")
            else:
                st.caption("—")
    md = evidence.checklist_markdown(rows, datetime.now().strftime("%d %b %Y, %H:%M"))
    st.download_button("Export evidence summary (Markdown)", data=md, file_name="cipherops-evidence-summary.md",
                       mime="text/markdown", key="chk_export", icon=":material/download:")


# ─────────────────────────── 5. two measurement paths ───────────────────────────

def _two_paths(ctx: Context, ev: dict) -> None:
    st.markdown("## Two measurement paths")
    left, right = st.columns(2)
    with left, st.container(border=True, height="stretch"):
        st.markdown(f"### Offline harness {terms.badge('primary')}")
        st.markdown("Calls the MTL library, liboqs and OpenSSL directly on one pinned CPU core, with no network.")
        st.markdown("**Measures:** signing time, verification time, signature sizes, and the bytes and cache use of a "
                    "modelled DNS workload.")
        newest = ev["offline"][0] if ev["offline"] else None
        st.caption(f"Newest run: `{newest.id}` ({newest.when})" if newest else "No run on this machine yet.")
        st.code("bash scripts/run_benchmark.sh configs/quick.yaml", language="bash")
    with right, st.container(border=True, height="stretch"):
        st.markdown(f"### Live lab {terms.badge('indicative')}")
        st.markdown("A root, TLD and SLD hierarchy served by NSD, validated by Unbound, in Docker.")
        st.markdown("**Shows what the harness cannot:** resolver behaviour, truncation, TCP retry, bytes per level and "
                    "Unbound's cache counters. Containers share the host CPUs, so timings are indicative.")
        newest = ev["live"][0] if ev["live"] else None
        st.caption(f"Newest run: `{newest.id}` ({newest.when})" if newest else "No run on this machine yet.")
        st.caption("Start it from Setup.")
    st.caption("Two paths because the harness gives clean timings and sizes, while only a real resolver shows "
               "truncation, retries and cache behaviour. They run different software, so their numbers are never mixed.")


# ─────────────────────────── 6. tools ───────────────────────────

def _needs_met(tile_id: str, ctx: Context, ev: dict) -> bool:
    r, docker_ok = ctx.ready, not ctx.stt.get("error")
    return {"setup": docker_ok, "benchmark": r["images"], "live": r["prepared"] and r["running"],
            "compare": bool(ev["offline"] or ev["live"]), "learn": True, "reset": True}[tile_id]


def _tools(ctx: Context, ev: dict) -> None:
    st.markdown("## Tools")
    order = terms.TILE_ORDER
    for row in (order[:3], order[3:]):
        cols = st.columns(3)
        for col, tid in zip(cols, row):
            t = terms.TILES[tid]
            met = _needs_met(tid, ctx, ev)
            with col, st.container(border=True, height="stretch"):
                st.markdown(f"### {t['icon']} {t['title']}")
                st.markdown(f"**Use it when:** {t['use_when']}")
                st.markdown(f":gray-badge[{t['needs_chip']}] "
                            + (":green-badge[ready]" if met else ":orange-badge[not ready yet]"))
                if st.button(t["cta"], key=f"tool_{tid}", type="secondary", width="stretch"):
                    ctx.go(tid, None)
                    st.rerun()


# ─────────────────────────── 7. lab status, 8. limits, 9. terms, 10. footer ───────────────────────────

def _lab_status(ctx: Context) -> None:
    st.markdown("## Lab status")
    if ctx.stt.get("error"):
        st.warning("Docker is not reachable. Start Docker, then reload. Results, checklist and terms above do not "
                   "need it.")
    ctx.lab_strip()
    r = ctx.ready
    if r["ready"]:
        text = "The lab is ready for Demonstrate."
    elif not r["images"]:
        text = "Next for the lab: build the images in Setup, step 1."
    elif not r["prepared"]:
        text = "Next for the lab: Sign zones in Setup, step 2."
    else:
        text = "Next for the lab: start the containers in Setup, step 3."
    st.caption(text + " Only the live lab needs this; reading results does not.")


def _mtl_commits(ev: dict) -> tuple[str, str]:
    """MTL commit of the newest offline run and of the draft-06 stack, read from files."""
    offline = ""
    if ev["offline"]:
        env = evidence._read_json(ev["offline"][0].path / "environment.json")
        offline = str(env.get("software", {}).get("mtl_reference_commit", ""))[:10]
    offline = offline or str(driver.stack_pins("latest").get("MTL_COMMIT", ""))[:10]
    return offline, str(driver.stack_pins("draft06").get("MTL_COMMIT", ""))[:10]


def _limits(ev: dict) -> None:
    st.markdown("## Known limits")
    off, live = _mtl_commits(ev)
    codes = terms.edns_code_points()
    st.markdown(
        f"- **Different MTL versions.** The offline harness (MTL `{off}`) and the live lab on the draft-06 stack "
        f"(MTL `{live}`) run different versions. Never merge their numbers.\n"
        "- **Plain SLH-DSA on the latest stack.** Its Unbound answers SERVFAIL for plain SLH-DSA while the signed zone "
        "is valid. Use the draft-06 stack for the live MTL-versus-non-MTL comparison.\n"
        f"- **Placeholder code points.** The DNSSEC algorithm numbers for SLH-DSA are not IANA-assigned, and the "
        f"mtl-mode-full option is {codes[0][1]} in the offline byte model but {codes[1][1]} on the live lab's "
        "draft-06 stack. Both are lab values.\n"
        "- **Live-lab timings are indicative.** Containers are not pinned to cores. Use the offline harness for "
        "timings.")


def _terms_panel() -> None:
    with st.expander("Terms", expanded=False):
        st.dataframe(pd.DataFrame(terms.glossary_rows()), hide_index=True, width="stretch")
        st.markdown("**The mtl-mode-full option number, by path**")
        st.dataframe(pd.DataFrame([{"Path": p, "Lab code point": n, "Used for": u}
                                   for p, n, u in terms.edns_code_points()]), hide_index=True, width="stretch")
        st.caption("Neither number is assigned by IANA.")


def _footer() -> None:
    sha, dirty = _repo_state()
    st.divider()
    bits = [f"Commit `{sha}`" + (" · uncommitted changes in the working tree" if dirty else " · clean working tree")
            if sha else "Commit unavailable"]
    bits.append(f"[README]({terms.REPO_URL}/blob/main/README.md) · "
                f"[methodology]({terms.REPO_URL}/blob/main/docs/methodology.md)")
    st.caption(" · ".join(bits))


# ─────────────────────────── entry point ───────────────────────────

def render(ctx: Context) -> None:
    ev = _evidence(evidence.fingerprint(ctx.results_dir, ctx.suites_dir), bool(ctx.ready["prepared"]),
                   bool(ctx.ready["running"]), str(ctx.results_dir), str(ctx.suites_dir), str(evidence.LAB_RESULTS_DIR))
    _header(ctx)
    visitor = _choose_visitor()
    _show_path(ctx, visitor, ev)
    _headline(ctx, ev)
    _checklist(ctx, ev)
    _two_paths(ctx, ev)
    _tools(ctx, ev)
    _lab_status(ctx)
    _limits(ev)
    _terms_panel()
    _footer()
