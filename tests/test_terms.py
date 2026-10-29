"""One vocabulary: every id has a display label, the glossary is generated from it, and no raw id reaches the home page."""

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "dashboard"), str(ROOT / "src"), str(ROOT / "tests")]

from cipherops.codepoints import EDNS_MTL_MODE_FULL, MODES  # noqa: E402
from fixtures_home import make_live_suite, make_offline_run  # noqa: E402
from live_lab import compare, driver, terms  # noqa: E402

# a raw id standing alone in prose, not part of a longer name such as "mtl-mode-full" or "draft-harvey-cfrg-mtl-mode"
RAW_ID = re.compile(r"(?<![\w\-/.`])(slh-dsa-mtl|slh-dsa|mixed-mtl|mtl|ecdsa-p256|ecdsa|ed25519|rsa-2048|rsa)(?![\w\-/.`])")


def test_every_internal_algorithm_id_has_a_display_label():
    ids = set(driver.SCENARIO_ALGS) | set(MODES) | set(compare.ORDER)
    for i in ids:
        assert terms.algorithm_label(i) != i, i
        assert terms.algorithm_label(i, short=True) != i or i == "slh-dsa", i
    assert terms.algorithm_label("mtl") == terms.algorithm_label("slh-dsa-mtl") == "SLH-DSA-MTL"
    assert terms.algorithm_label("ecdsa") == "ECDSAP256SHA256 (13)" and terms.algorithm_label("ed25519") == "ED25519 (15)"
    assert terms.algorithm_label("rsa").startswith("RSASHA256") and terms.algorithm_label("mixed-mtl").startswith("Mixed")
    assert terms.algorithm_label("something-new") == "something-new"  # unknown ids stay visible


def test_labels_carry_the_ps036_and_ietf_names_for_hover_help():
    for i in ("mtl", "slh-dsa", "ecdsa", "ed25519", "rsa", "mixed-mtl"):
        assert terms.algorithm_help(i).count(".") >= 1 and len(terms.algorithm_help(i)) > 20


def test_tiles_cover_every_navigation_id_and_have_the_three_facts():
    src = (ROOT / "dashboard" / "live_lab" / "app.py").read_text()
    nav = set(re.search(r"NAV_MODES = \(([^)]*)\)", src).group(1).replace('"', "").replace(" ", "").split(",")) - {"home"}
    assert set(terms.TILES) == nav and set(terms.TILE_ORDER) == nav
    titles = [t["title"] for t in terms.TILES.values()]
    assert len(set(titles)) == len(titles)
    for t in terms.TILES.values():
        assert t["use_when"] and t["not_for"] and t["needs"] and t["needs_chip"].startswith("Needs") and t["icon"].startswith(":material/")
    assert terms.tile_title("compare") == "Results" and terms.tile_title("live") == "Demonstrate"
    assert terms.tile_title("benchmark") == "Live-lab benchmark" and terms.tile_title("reset") == "Clean up"


def test_the_two_code_points_come_from_the_code_and_differ():
    rows = terms.edns_code_points()
    assert [r[1] for r in rows] == [EDNS_MTL_MODE_FULL, driver.MTL_FULL] and rows[0][1] != rows[1][1]


def test_glossary_is_generated_and_complete():
    rows = terms.glossary_rows()
    assert {"Term", "Meaning", "PS-036 wording", "IETF / standards term"} == set(rows[0])
    names = " ".join(r["Term"] for r in rows)
    for word in ("Algorithm", "Dataset size", "Level", "Sign zones", "Software stack", "Run", "Trial", "Cold cache",
                 "Condensed signature", "mtl-mode-full", "Measured", "Primary", "Demonstrate", "Results", "Clean up"):
        assert word in names, word
    assert all(r["Meaning"] for r in rows)


def test_dataset_and_level_labels():
    assert terms.dataset_label("large", 5000, 10005) == "Large · 5,000 names · 10,005 RRsets"
    assert terms.dataset_label("small") == "Small" and terms.level_label("sld") == "SLD" and terms.level_label("tld") == "TLD"
    assert terms.stack_label("draft06") == "draft-06" and terms.stack_label("latest") == "latest"
    assert "experimental" not in " ".join(s["what"] for s in terms.STACKS.values()).lower()


def test_each_badge_kind_has_one_style_and_a_help_text():
    assert set(terms.BADGES) == set(terms.BADGE_HELP)
    assert len(set(terms.BADGES.values())) == len(terms.BADGES)
    assert "Primary" in terms.badge("primary") and "Indicative" in terms.badge("indicative")


# ─────────────────────────── the rendered home page ───────────────────────────

def _app():
    from pathlib import Path

    import streamlit as st

    from live_lab import home

    p = st.session_state["paths"]
    ctx = home.Context(h=None, stt=st.session_state["stt"], ready=st.session_state["ready"],
                       go=lambda mode, settings=None: st.session_state.setdefault("went", []).append((mode, settings)),
                       lab_strip=lambda: st.caption("lab chips"), results_dir=Path(p["results"]), suites_dir=Path(p["suites"]))
    home.render(ctx)


def _run(tmp_path, monkeypatch, *, offline=False, live=False, stt=None, ready=None, query=None):
    from streamlit.testing.v1 import AppTest

    from live_lab import evidence

    eco = tmp_path / "eco"
    monkeypatch.setattr(compare, "ECO", eco)
    monkeypatch.setattr(evidence, "LAB_RESULTS_DIR", eco / "results")
    if offline:
        make_offline_run(tmp_path / "results")
    if live:
        make_live_suite(eco / "results" / "suites", eco / "results")
    at = AppTest.from_function(_app, default_timeout=60)
    at.session_state["paths"] = {"results": str(tmp_path / "results"), "suites": str(eco / "results" / "suites")}
    at.session_state["stt"] = stt or {}
    at.session_state["ready"] = ready or {"images": False, "prepared": False, "running": False, "ready": False}
    for k, v in (query or {}).items():
        at.query_params[k] = v
    return at.run()


def _text(at) -> str:
    parts = [m.value for m in at.markdown] + [c.value for c in at.caption] + [b.label for b in at.button]
    parts += [e.label for e in at.expander] + [i.value for i in at.info] + [w.value for w in at.warning]
    parts += [e.value for e in at.error] + [d.proto.label for d in at.get("download_button")]
    return "\n".join(parts)


def test_empty_machine_shows_an_empty_state_and_no_numbers(tmp_path, monkeypatch):
    at = _run(tmp_path, monkeypatch)
    assert not at.exception
    text = _text(at)
    assert "No offline run is stored on this machine" in text and "Nothing here is an example figure" in text
    assert "run_benchmark.sh configs/quick.yaml" in text
    assert "0 of 10 expected outcomes have evidence" in text
    assert not re.search(r"\d+(\.\d+)?\s?(ms|×) ", " ".join(m.value for m in at.markdown if m.value.startswith("###")))


def test_page_has_exactly_one_primary_button_and_the_four_visitor_choices(tmp_path, monkeypatch):
    at = _run(tmp_path, monkeypatch, offline=True)
    assert not at.exception
    assert [b for b in at.button if b.proto.type == "primary"].__len__() == 1
    labels = [b.label for b in at.button]
    for visitor in ("Check the PS-036 deliverables", "Watch the demonstration", "Reproduce the benchmark",
                    "Understand MTL first"):
        assert visitor in labels


def test_with_a_run_the_cards_show_run_id_badges_and_the_checklist(tmp_path, monkeypatch):
    at = _run(tmp_path, monkeypatch, offline=True, live=True)
    assert not at.exception
    text = _text(at)
    assert "20261001T120000Z-fixture" in text and "6 trials" in text and "CI of the median over 6 trials" in text
    assert ":green-badge[Measured]" in text and ":primary-badge[Primary · pinned core]" in text
    assert ":orange-badge[Indicative · not core-pinned]" in text
    assert "9 of 10 expected outcomes" in text or "8 of 10 expected outcomes" in text
    assert "Export evidence summary" in text


def test_no_raw_internal_id_is_shown_on_the_home_page(tmp_path, monkeypatch):
    for visitor in ("evaluator", "presenter", "reproducer", "explainer"):
        at = _run(tmp_path / visitor, monkeypatch, offline=True, live=True, query={"visitor": visitor})
        assert not at.exception
        hits = RAW_ID.findall(_text(at).replace("`", " ` "))
        assert not hits, (visitor, hits)


def test_docker_down_still_renders_results_checklist_and_terms(tmp_path, monkeypatch):
    at = _run(tmp_path, monkeypatch, offline=True, stt={"error": "Cannot connect to the Docker daemon"})
    assert not at.exception
    text = _text(at)
    assert text.count("Docker is not reachable") == 1  # said once, in Lab status
    assert "Evidence found" in text and "Terms" in [e.label for e in at.expander]
    assert any(m.value.startswith("### ") and "vs" in m.value for m in at.markdown)  # headline cards are still there


def test_known_limits_are_visible_without_opening_anything(tmp_path, monkeypatch):
    text = _text(_run(tmp_path, monkeypatch))
    for phrase in ("Different MTL versions", "Plain SLH-DSA on the latest stack", "Placeholder code points",
                   "Live-lab timings are indicative", str(EDNS_MTL_MODE_FULL), str(driver.MTL_FULL)):
        assert phrase in text, phrase


def test_the_visitor_choice_is_remembered_in_the_query_string(tmp_path, monkeypatch):
    at = _run(tmp_path, monkeypatch, offline=True, query={"visitor": "reproducer"})
    assert "Your path: Reproduce the benchmark" in _text(at)
    at.button(key="visitor_presenter").click().run()
    assert at.query_params["visitor"] == ["presenter"] or at.query_params["visitor"] == "presenter"


def test_a_step_button_opens_the_tile_with_its_controls_preset(tmp_path, monkeypatch):
    at = _run(tmp_path, monkeypatch, offline=True)
    at.button(key="next_step").click().run()
    assert at.session_state["went"][-1] == ("compare", {"cmp_view": "algorithms", "cmp_src": "offline"})


def test_the_raw_id_detector_catches_ids_and_ignores_names_that_contain_them():
    assert RAW_ID.findall("uses mtl and slh-dsa here") == ["mtl", "slh-dsa"]
    assert RAW_ID.findall("the mtl-mode-full option, draft-harvey-cfrg-mtl-mode, `mtl`, results/runs/mtl.csv") == []
