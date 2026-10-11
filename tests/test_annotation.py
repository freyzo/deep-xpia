"""Labeling sample (scripts/annotation_sample.py) and agreement maths (scripts/annotation_agreement.py)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def sample():
    return _load("annotation_sample")


def test_kappa_hand_computed() -> None:
    agree = _load("annotation_agreement")
    # observed 0.75, expected 0.5 -> kappa 0.5
    assert agree.cohen_kappa(["x", "x", "y", "y"], ["x", "y", "y", "y"]) == pytest.approx(0.5)
    assert agree.cohen_kappa(["x", "y"], ["x", "y"]) == pytest.approx(1.0)
    pr = agree.per_label_precision_recall(["complied", "not_exposed"], ["complied", "complied"])
    assert pr["complied"] == (1, 0.5, 1.0) and pr["not_exposed"] == (1, None, 0.0)


def test_sample_is_deterministic_and_stratified(sample) -> None:
    a, b = sample.draw(), sample.draw()
    assert [(i["item_id"], i["case"].id, i["hop"], i["run_file"]) for i in a] == \
           [(i["item_id"], i["case"].id, i["hop"], i["run_file"]) for i in b]
    runs = {(i["run_file"], i["case"].id) for i in a}
    assert len(runs) == 150
    assert sum(not c.startswith("CLEAN") for _, c in runs) == 100
    assert len({(i["run_file"], i["case"].id) for i in a if i["per_hop_subset"]}) == 30


def test_committed_item_list_matches_the_draw(sample) -> None:
    import csv

    with (ROOT / "results/annotation/items_v2.csv").open(newline="") as f:
        committed = [(r["item_id"], r["case_id"], int(r["hop"])) for r in csv.DictReader(f)]
    assert committed == [(i["item_id"], i["case"].id, i["hop"]) for i in sample.draw()]


def test_hop_inputs_follow_v2_delivery(sample) -> None:
    from deep_xpia.bench.schema import BenchCase, InjectionPosition, RunResult

    cases = {c.id: c for c in (BenchCase.model_validate_json(ln) for ln in
                               (ROOT / "deepxpiabench-v2.jsonl").read_text().splitlines() if ln.strip())}
    runs = [RunResult.model_validate_json(ln) for ln in
            (ROOT / "results/raw/v2-live-2026-06/live_full_none.jsonl").read_text().splitlines() if ln.strip()]
    first = next(r for r in runs if cases[r.case_id].injection
                 and cases[r.case_id].injection.position == InjectionPosition.FIRST_HOP and len(r.agent_outputs) > 1)
    case = cases[first.case_id]
    assert sample.hop_input(case, first, 0) == f"{case.user_task}\n\n{case.injection.content}"
    assert sample.hop_input(case, first, 1) == first.agent_outputs[0]["output"]
    last = next(r for r in runs if cases[r.case_id].injection
                and cases[r.case_id].injection.position == InjectionPosition.LAST_HOP)
    lc = cases[last.case_id]
    assert all(lc.injection.content not in sample.hop_input(lc, last, h) for h in range(len(last.agent_outputs)))
