"""Tests for the Signing replay scene builder (no Docker, no Streamlit, no browser)."""

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "dashboard"))

from live_lab import prepare_story as ps  # noqa: E402

MTL_ALG = "SLH-DSA-SHA2-128s-MTL-SHA2-128"


def _zone(origin, tier, n, alg=MTL_ALG, sign=0.5):
    return {"origin": origin, "tier": tier, "algorithm": alg, "n_names": 0, "rrsig_count": n,
            "sign_seconds": sign, "verify_seconds": 0.02, "signed_bytes": n * 1000,
            "ds": [f"{origin} IN DS 1 2 3 abcdef"]}


def _manifest(alg=MTL_ALG, slds=(5, 24)):
    zones = [_zone(f"zone{i:02d}.test.", "sld", n, alg) for i, n in enumerate(slds)]
    zones += [_zone("test.", "tld", 15, alg), _zone(".", "root", 13, alg)]
    return {"scenario": "mtl", "algorithms": {"root": alg, "tld": alg, "sld": alg},
            "trust_anchor": [". IN DS 9 2 3 deadbeef"], "zones": zones}


@pytest.mark.parametrize("n", [1, 2, 3, 5, 13, 24, 50, 500, 5000])
def test_ladder_rungs_cover_every_leaf_and_match_draft_rung_count(n):
    rungs = ps.ladder_rungs(n)
    assert sum(rungs) == n
    assert len(rungs) == ps.analytical.rung_count(n)
    assert rungs == sorted(rungs, reverse=True)
    assert all(r & (r - 1) == 0 for r in rungs)  # every rung is a perfect (power-of-two) subtree


def test_family_from_algorithm_names():
    assert ps.family("SLH-DSA-SHA2-128s-MTL-SHA2-128") == "mtl"
    assert ps.family("SLH_DSA_PURE_SHA2_128S") == "slh-dsa"
    assert ps.family("SLH-DSA-SHA2-128s") == "slh-dsa"
    assert ps.family("ECDSAP256SHA256") == "ecdsa"
    assert ps.family("ED25519") == "ed25519"
    assert ps.family("RSASHA256") == "rsa"
    assert ps.family("something-new") == "classical"


def test_parent_origin_uses_nearest_known_ancestor():
    known = {".", "test.", "zone00.test."}
    assert ps.parent_origin(".", known) is None
    assert ps.parent_origin("test.", known) == "."
    assert ps.parent_origin("zone00.test.", known) == "test."
    assert ps.parent_origin("a.zone00.test.", known) == "zone00.test."
    assert ps.parent_origin("x.example.", known) == "."  # no TLD zone signed: falls back to the root


def test_scene_is_bottom_up_with_bounded_timeline():
    sc = ps.build_scene(_manifest(), lab="demo")
    assert [p["tier"] for p in sc["phases"]] == ["sld", "tld", "root"]
    assert sc["duration"] == pytest.approx(ps.INTRO_S + 3 * ps.PHASE_S + ps.OUTRO_S)
    for z in sc["zones"]:
        ph = sc["phases"][z["phase"]]
        assert ph["t0"] <= z["t0"] < z["t1"] <= ph["t1"]
        assert z["t1"] + 0.9 <= ph["t1"] + 1e-9  # room for the DS hand-off before the next tier starts
    assert sc["zones"][3]["parent"] is None and sc["zones"][2]["parent"] == "."
    assert sc["zones"][0]["parent"] == "test."


def test_spotlight_is_the_largest_zone_in_each_tier():
    sc = ps.build_scene(_manifest(slds=(5, 24, 13)))
    spots = {z["tier"]: z for z in sc["zones"] if z["spotlight"]}
    assert spots["sld"]["n_leaves"] == 24
    assert sum(1 for z in sc["zones"] if z["spotlight"]) == 3
    # The spotlight zone owns the whole phase window; the others fit inside it.
    for z in sc["zones"]:
        if z["tier"] == "sld" and not z["spotlight"]:
            assert z["t1"] - z["t0"] < spots["sld"]["t1"] - spots["sld"]["t0"]


def test_timeline_length_does_not_grow_with_zone_count():
    small = ps.build_scene(_manifest(slds=(5, 24)))
    big = ps.build_scene(_manifest(slds=tuple([20] * 200)))
    assert big["duration"] == small["duration"]
    assert all(z["t1"] <= big["phases"][z["phase"]]["t1"] for z in big["zones"])


def test_mtl_story_numbers():
    sc = ps.build_scene(_manifest())
    z = next(z for z in sc["zones"] if z["origin"] == "zone01.test.")
    assert z["family"] == "mtl" and z["rungs"] == [16, 8]
    assert z["condensed_bytes"] == ps.analytical.max_condensed_signature(16, 24)
    assert z["ladder_bytes"] == ps.analytical.max_signed_ladder(16, 24, 7856)
    tot = sc["totals"]
    assert tot["rrsigs"] == 5 + 24 + 15 + 13 and tot["slow_sigs"] == 4  # one ladder signature per zone
    assert tot["sig_bytes"] < tot["sig_bytes_if_slh"]
    assert any("Only 4 SLH-DSA signatures" in line for line in sc["outro"])


def test_direct_signing_story_signs_every_rrset():
    sc = ps.build_scene(_manifest(alg="SLH-DSA-SHA2-128s"))
    assert sc["family"] == "slh-dsa"
    assert sc["totals"]["slow_sigs"] == sc["totals"]["rrsigs"]
    assert sc["totals"]["sig_bytes"] == sc["totals"]["rrsigs"] * 7856
    assert all(z["rungs"] and z["condensed_bytes"] == 0 for z in sc["zones"])


def test_scene_json_is_script_safe_and_round_trips():
    m = _manifest()
    m["zones"][0]["origin"] = "</script><!--x.test."
    sc = ps.build_scene(m)
    text = ps.scene_json(sc)
    assert "</" not in text and "<!--" not in text
    assert json.loads(text)["zones"][0]["origin"] == "</script><!--x.test."


def test_render_html_embeds_scene_and_is_self_contained():
    html = ps.render_html(ps.build_scene(_manifest(), lab="demo"))
    assert "__SCENE_JSON__" not in html
    assert '"lab":"demo"' in html
    assert "http://" not in html.replace("http://www.w3.org/2000/svg", "")  # no external assets


SIG = "20360101000000 20260101000000 1234 z. AAAA"


def _write_signed(path: Path, n_rrsigs: int) -> None:
    """A tiny signed-zone file: n RRSIG records plus NSEC3 records whose bitmap lists RRSIG (like ldns writes)."""
    lines = []
    for i in range(n_rrsigs):
        lines.append(f"h{i}.z. 3600 IN A 192.0.2.{i % 250}")
        lines.append(f"h{i}.z. 3600 IN RRSIG A 15 3 3600 {SIG}")
        lines.append(f"x{i}.z. 3600 IN NSEC3 1 0 0 - NEXT A RRSIG ")  # not an RRSIG record, must not be counted
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_rrsig_profile_counts_rrsig_records_not_nsec3_bitmaps(tmp_path):
    f = tmp_path / "z.signed"
    f.write_text("\n".join([
        "z. 3600 IN SOA ns. host. 1 7200 3600 1209600 3600",
        f"z. 3600 IN RRSIG SOA 15 3 3600 {SIG}",
        "abc.z. 3600 IN NSEC3 1 0 0 - NEXT A RRSIG ",
        f"abc.z. 3600 IN RRSIG NSEC3 15 3 3600 {SIG}",
        f"h.z. 3600 IN RRSIG A 15 3 3600 {SIG}",
    ]) + "\n", encoding="utf-8")
    p = ps.rrsig_profile(f)
    assert p == {"total": 3, "by_type": {"SOA": 1, "NSEC3": 1, "A": 1}}
    naive = sum(1 for line in f.read_text().splitlines() if "\tRRSIG\t" in line or " RRSIG " in line)
    assert naive == 4  # what the manifest's rrsig_count does: one too many here
    assert ps.rrsig_profile(tmp_path / "missing") is None


def _exact_scene(tmp_path):
    """Small lab: 2 leaf zones x 5 names (17 RRSIGs), 1 TLD (11), root (10)."""
    man = _manifest(slds=(5, 5))
    for z in man["zones"]:
        z["n_names"] = 5 if z["tier"] == "sld" else 0
        z["signed_file"] = z["origin"].strip(".") + ".signed"
        _write_signed(tmp_path / z["signed_file"], {"sld": 17, "tld": 11, "root": 10}[z["tier"]])
    return ps.build_scene(man, lab="eco-ui-small", zones_dir=tmp_path, size_label="Small (smoke)")


def test_exact_counts_replace_the_manifest_count(tmp_path):
    sc = _exact_scene(tmp_path)
    assert sc["leaves_exact"] is True
    assert {z["tier"]: z["n_leaves"] for z in sc["zones"]} == {"sld": 17, "tld": 11, "root": 10}
    z = next(z for z in sc["zones"] if z["tier"] == "sld")
    assert z["rungs"] == [16, 1]  # 17 = 16 + 1; the manifest's 24 would wrongly give 16 + 8
    assert sc["totals"]["rrsigs"] == 17 + 17 + 11 + 10


def test_plan_says_how_many_records_go_where_and_why(tmp_path):
    plan = _exact_scene(tmp_path)["plan"]
    assert plan["size"] == "Small (smoke)" and plan["names"] == 10 and plan["exact"] is True
    sld, tld, root = plan["tiers"]
    assert sld["head"] == "Leaf zones · 2 × 17 RRsets"
    assert sld["why"] == "5 names × 2 (record + NSEC3 proof) + 7 zone records"
    assert tld["head"] == "TLD · 11 RRsets"
    assert tld["why"] == "2 leaf zones × 2 (DS + NSEC3 proof) + 7 zone records"
    assert root["head"] == "Root · 10 RRsets"
    assert root["why"] == "1 TLD × 2 (DS + NSEC3 proof) + 8 zone records"


def test_plan_without_signed_files_falls_back_and_says_so():
    sc = ps.build_scene(_manifest())
    assert sc["leaves_exact"] is False
    assert all(t["why"] == "counted from the Prepare manifest" for t in sc["plan"]["tiers"])


def test_plan_groups_unequal_leaf_zones(tmp_path):
    man = _manifest(slds=(5, 25))
    for z in man["zones"]:
        z["n_names"] = {"zone00.test.": 5, "zone01.test.": 25}.get(z["origin"], 0)
        z["signed_file"] = z["origin"].strip(".") + ".signed"
        _write_signed(tmp_path / z["signed_file"], 2 * z["n_names"] + 7 if z["tier"] == "sld" else 11)
    sld = ps.build_scene(man, zones_dir=tmp_path)["plan"]["tiers"][0]
    assert sld["head"] == "Leaf zones · 1 × 17 + 1 × 57 = 74 RRsets"
    assert sld["why"] == "5 / 25 names × 2 (record + NSEC3 proof) + 7 zone records"


def test_real_signed_files_follow_two_rrsets_per_name_plus_seven():
    work = ROOT / "ecosystem" / "work"
    found = list(work.glob("*/zones/*/manifest.json")) if work.is_dir() else []
    checked = 0
    for path in found:
        man = json.loads(path.read_text(encoding="utf-8"))
        if not all((path.parent / z["signed_file"]).is_file() for z in man["zones"]):
            continue
        sc = ps.build_scene(man, zones_dir=path.parent)
        assert sc["leaves_exact"] is True
        for z in sc["zones"]:
            if z["tier"] == "sld":
                assert z["n_leaves"] == 2 * z["n_names"] + 7
        checked += 1
    if not checked:
        pytest.skip("no signed zone files on this machine")


def test_real_manifests_build_scenes():
    work = ROOT / "ecosystem" / "work"
    found = list(work.glob("*/zones/*/manifest.json")) if work.is_dir() else []
    if not found:
        pytest.skip("no Prepare output on this machine")
    for path in found:
        man = json.loads(path.read_text(encoding="utf-8"))
        sc = ps.build_scene(man, lab=path.parents[2].name, scenario=path.parent.name)
        assert sc["phases"] and sc["totals"]["rrsigs"] == sum(z["rrsig_count"] for z in man["zones"])
        assert json.loads(ps.scene_json(sc))["duration"] == sc["duration"]
