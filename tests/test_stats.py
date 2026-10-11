"""bench/stats.py against hand-computed values and planted effects."""

from __future__ import annotations

import random
from pathlib import Path

import pytest

from deep_xpia.bench.schema import BenchCase
from deep_xpia.bench.stats import cluster_bootstrap_ci, depth_slope_fe, holm, mcnemar_exact, payload_template

ROOT = Path(__file__).resolve().parents[1]


def test_mcnemar_exact_hand_computed() -> None:
    # 1 vs 6 discordant pairs: p = 2 * (C(7,0) + C(7,1)) / 2^7 = 16/128 = 0.125
    a = [True] * 1 + [False] * 6 + [True] * 5 + [False] * 4
    b = [False] * 1 + [True] * 6 + [True] * 5 + [False] * 4
    r = mcnemar_exact(a, b)
    assert (r.only_a, r.only_b) == (1, 6) and r.p_value == pytest.approx(0.125)
    assert mcnemar_exact([True, False], [True, False]).p_value == 1.0


def test_holm_matches_textbook_example() -> None:
    adj = holm({"a": 0.01, "b": 0.04, "c": 0.03})
    assert adj == pytest.approx({"a": 0.03, "c": 0.06, "b": 0.06})


def test_cluster_bootstrap_contains_the_mean_and_is_deterministic() -> None:
    values = [1.0] * 30 + [0.0] * 30
    clusters = [i // 6 for i in range(60)]
    lo, hi = cluster_bootstrap_ci(values, clusters, B=2000)
    assert lo < 0.5 < hi
    assert cluster_bootstrap_ci(values, clusters, B=2000) == (lo, hi)


def test_depth_slope_recovers_a_planted_effect() -> None:
    rng = random.Random(0)
    y, depth, fe, cl = [], [], [], []
    for i in range(3000):
        d = rng.randint(1, 4)
        g = rng.choice("ABC")
        p = {"A": 0.2, "B": 0.5, "C": 0.6}[g] + 0.08 * (d - 1)
        y.append(float(rng.random() < p))
        depth.append(d)
        fe.append(g)
        cl.append(i % 40)
    r = depth_slope_fe(y, depth, fe, cl, B=500)
    assert r.ci95[0] < 0.08 < r.ci95[1]
    assert not r.equivalent_within(0.05)
    flat = depth_slope_fe([float(rng.random() < 0.5) for _ in depth], depth, fe, cl, B=500)
    assert flat.equivalent_within(0.05)


def test_every_v2_attack_case_maps_to_one_template() -> None:
    cases = [BenchCase.model_validate_json(ln) for ln in (ROOT / "deepxpiabench-v2.jsonl").read_text().splitlines() if ln.strip()]
    ids = {c.id: payload_template(c) for c in cases if c.injection is not None}
    assert len(ids) == 200 and all(ids.values())
    assert all(t.startswith("laundered-") for cid, t in ids.items() if cid.startswith("DXPIA-006"))
    assert len(set(ids.values())) <= 16
