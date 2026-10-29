"""Analysis of the evolving-zone experiment, over synthetic frames with known answers."""

import pandas as pd
import pytest

from cipherops import evolution


def _frames(rounds=4, k=10, n=100, ages=(0, 1, 2)):
    rows, drows = [], []
    for t in range(5):
        for r in range(rounds + 1):
            leaves = n + r * k
            row = {"trial": t, "dataset": "small", "k": k, "round": r, "changed": n if r == 0 else k,
                   "leaf_count": leaves, "rung_count": bin(leaves).count("1"), "ladder_bytes": 8000 + 16 * r,
                   "append_ns": 1000 * k, "ladder_sign_ns": 600_000_000 + t * 1_000_000,
                   "ladder_verify_ns": 300_000, "condensed_extract_ns": 5000, "condensed_bytes_median": 172,
                   "condensed_bytes_max": 188, "condensed_bytes_mean": 175.0, "stale_tested": 0 if r == 0 else n - k,
                   "stale_ok": 0 if r == 0 else n - k - 3, "rss_bytes": 8_000_000 + r, "leaf_index_mismatch": 0,
                   "exit_code": 0, "kind": "measured"}
            for a in ages:
                if a <= r:
                    row[f"tested_age_{a}"] = n
                    row[f"ok_age_{a}"] = n - a * k
            rows.append(row)
            if r:
                drows.append({"trial": t, "k": k, "round": r, "signed": k, "sign_ns": int(k * 6e8 * (1 + 0.01 * t)),
                              "verify_ns": k * 300_000, "exit_code": 0, "kind": "measured"})
    return pd.DataFrame(rows), pd.DataFrame(drows)


def test_update_cost_pairs_the_trials_and_compares_k_signatures_with_one_ladder():
    mtl, direct = _frames(k=10)
    c = evolution.update_cost(mtl, direct).iloc[0]
    assert c.trials == 5 and c.signatures_mtl == 1 and c.signatures_direct == 10
    assert c.ratio == pytest.approx(10.0, rel=0.1) and c.ratio_lo <= c.ratio <= c.ratio_hi
    assert c.mtl_resolver_ns == 300_000 and c.direct_resolver_ns == 10 * 300_000


def test_k_equal_one_gives_no_signing_advantage():
    mtl, direct = _frames(k=1)
    c = evolution.update_cost(mtl, direct).iloc[0]
    assert 0.9 < c.ratio < 1.1


def test_coverage_is_the_share_of_answers_that_still_verify():
    mtl, _ = _frames(rounds=4, k=10, n=100, ages=(0, 1, 2))
    t = evolution.coverage_table(mtl).set_index("age")
    assert t.loc[0, "share"] == 1.0
    assert t.loc[1, "share"] == pytest.approx(0.9) and t.loc[2, "share"] == pytest.approx(0.8)
    by_round = evolution.coverage_by_round(mtl)
    assert set(by_round[by_round.age == 2]["round"]) == {2, 3, 4}  # age 2 exists only from round 2


def test_effective_bytes_add_a_full_signature_for_the_uncovered_share():
    mtl, _ = _frames(rounds=4, k=10, n=100, ages=(0, 1, 2))
    e = evolution.effective_bytes(mtl).set_index("age")
    full = 175.0 + e.loc[1, "ladder_bytes"]
    assert e.loc[1, "effective_bytes"] == pytest.approx(175.0 + 0.1 * full)
    assert e.loc[0, "effective_bytes"] == pytest.approx(175.0) and set(e.kind) == {"derived"}


def test_stale_share_and_growth():
    mtl, _ = _frames(rounds=3, k=10, n=100)
    s = evolution.stale_by_round(mtl)
    assert s.share.tolist() == pytest.approx([87 / 90] * 3) and 0 not in set(s["round"])
    g = evolution.growth(mtl)
    assert list(g["leaf_count"]) == [100, 110, 120, 130] and g.rung_count.iloc[0] == 3  # 100 = 64 + 32 + 4


@pytest.mark.parametrize("leaves,rungs", [(11, [(8, 0, 7), (2, 8, 9), (1, 10, 10)]), (8, [(8, 0, 7)]),
                                          (129, [(128, 0, 127), (1, 128, 128)])])
def test_rungs_are_the_binary_breakdown_of_the_leaf_count(leaves, rungs):
    assert evolution.rungs_of(leaves) == rungs


def test_settings_validate_the_block():
    base = {"seed": 1, "modes": ["slh-dsa", "slh-dsa-mtl"],
            "evolution": {"k": [1, 10], "rounds": [3, 3], "ages": [2, 0, 1, 1]}}
    assert evolution.settings(base)["ages"] == [0, 1, 2]
    assert evolution.settings({**base, "evolution": None}) is None
    assert evolution.settings({**base, "modes": ["slh-dsa"]}) is None
    for bad in ({"k": [1], "rounds": [3, 3], "ages": [0]}, {"k": [0], "rounds": [3], "ages": [0]},
                {"k": [1], "rounds": [3], "ages": [1, 2]}):
        with pytest.raises(SystemExit):
            evolution.settings({**base, "evolution": bad})


def test_checks_fail_on_any_mismatch_or_exit_code():
    mtl, direct = _frames()
    assert evolution.checks_passed(mtl, direct)
    assert not evolution.checks_passed(mtl.assign(leaf_index_mismatch=1), direct)
    assert not evolution.checks_passed(mtl, direct.assign(exit_code=1))
    assert not evolution.checks_passed(pd.DataFrame(), direct)
