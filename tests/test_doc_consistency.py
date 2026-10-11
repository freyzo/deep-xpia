"""Docs, taxonomy and scenario code must agree (claims that may be cited)."""

from __future__ import annotations

from pathlib import Path

import yaml

from deep_xpia.scenarios.registry_injection.pipeline import RegistryInjectionPipeline
from deep_xpia.scenarios.session_smuggling.pipeline import SessionSmugglingPipeline

ROOT = Path(__file__).resolve().parents[1]
TAXONOMY = {a["id"]: a for a in yaml.safe_load((ROOT / "taxonomy/taxonomy.yaml").read_text())["attacks"]}


def test_deputy_counts_match_scenarios() -> None:
    for tid, pipeline in (("DXPIA-001", SessionSmugglingPipeline()), ("DXPIA-008", RegistryInjectionPipeline())):
        gt = pipeline.to_bench_ground_truth()
        assert TAXONOMY[tid]["confused_deputies"] == len(gt["confused_deputies"])
        assert TAXONOMY[tid]["innocent_deputies"] == 1


def test_reference_scenarios_exist_and_match_taxonomy() -> None:
    for tid, attack in TAXONOMY.items():
        ref = attack.get("reference_scenario")
        if ref:
            assert (ROOT / ref).is_dir(), f"{tid}: {ref} missing"
            assert tid in (ROOT / ref / "README.md").read_text(), f"{tid}: {ref} README is for another attack"


def test_scenario_depths_agree() -> None:
    import re

    from fastapi.testclient import TestClient

    from deep_xpia.server import create_app
    from deep_xpia.scenarios.intent_laundering.ground_truth import TOPOLOGY as IL
    from deep_xpia.scenarios.memory_poisoning.ground_truth import TOPOLOGY as MP
    from deep_xpia.scenarios.session_smuggling.ground_truth import TOPOLOGY as SS

    truth = {"session_smuggling": SS.hop_count, "memory_poisoning": MP.hop_count,
             "intent_laundering": IL.hop_count}
    listed = {s["id"]: s["depth"] for s in TestClient(create_app()).get("/api/scenarios").json()["scenarios"]}
    for sid, depth in truth.items():
        assert listed[sid] == depth
        readme = (ROOT / "src/deep_xpia/scenarios" / sid / "README.md").read_text()
        assert int(re.search(r"\*\*Depth:\*\* (\d+)", readme).group(1)) == depth
    assert "depth_definition" in yaml.safe_load((ROOT / "taxonomy/taxonomy.yaml").read_text())


def test_owasp_mapping_matches_taxonomy_everywhere() -> None:
    import re

    readme = (ROOT / "README.md").read_text()
    site = (ROOT / "dashboard/src/DeepXPIA.jsx").read_text()
    mapping = yaml.safe_load((ROOT / "taxonomy/owasp_mapping.yaml").read_text())
    for tid, attack in TAXONOMY.items():
        ids = attack["owasp_agentic"]
        assert set(attack["owasp_detail"]) == set(ids), tid
        row = re.search(rf"^\| {tid} \|.*\| ([^|]+) \|$", readme, re.M)
        assert row and [x.strip() for x in row.group(1).split(",")] == ids, tid
        js = re.search(rf'id: "{tid}",[^}}]*?owasp: "([^"]*)"', site)
        assert js and [x.strip() for x in js.group(1).split(",")] == ids, tid
        cov = mapping["coverage_matrix"][tid]
        assert list(cov) == ids and cov[ids[0]] == "P", tid
        for asi in ids:
            assert tid in mapping["owasp_agentic_top10"][asi]["dxpia_attacks"], (tid, asi)


def test_sentinelagent_properties_match_paper() -> None:
    """Property ids/names follow arXiv:2604.02767 numbering (taxonomy sentinelagent_reference)."""
    from deep_xpia.bench.generator import TAXONOMY_PROPERTY
    from deep_xpia.bench.schema import TaxonomyID
    from deep_xpia.scenarios.intent_laundering.ground_truth import make_bench_cases as il
    from deep_xpia.scenarios.memory_poisoning.ground_truth import make_bench_cases as mp
    from deep_xpia.scenarios.session_smuggling.ground_truth import make_bench_cases as ss

    ref = yaml.safe_load((ROOT / "taxonomy/taxonomy.yaml").read_text())["sentinelagent_reference"]["properties"]
    assert list(ref) == [f"P{i}" for i in range(1, 8)]
    for tid, attack in TAXONOMY.items():
        props = attack["delegation_properties_violated"]
        for p in props:
            assert ref[p["id"]] == p["name"], (tid, p)
        assert TAXONOMY_PROPERTY[TaxonomyID(tid)] == (props[0]["id"] if props else None), tid
    for make in (ss, mp, il):
        for case in make():
            assert case.taxonomy_id is not None
            assert case.ground_truth.delegation_property_violated == TAXONOMY_PROPERTY[case.taxonomy_id]


# Wording withdrawn or found inaccurate in the 2026-10 audit; must not come back.
BANNED_PHRASES = [
    "hypothesis (from arXiv:2503.12188)",  # the paper states no depth hypothesis
    "challenges arXiv:2503.12188",
    "finding confirmed",
]


def _claim_files() -> list[Path]:
    files = [ROOT / "README.md", *sorted((ROOT / "taxonomy").glob("*.yaml"))]
    files += [p for p in sorted((ROOT / "results").rglob("*.md")) if "archive" not in p.parts]
    files += sorted((ROOT / "src").rglob("*.py")) + sorted((ROOT / "dashboard/src").glob("*.jsx"))
    return files


def test_withdrawn_wording_absent() -> None:
    hits = [
        (str(p.relative_to(ROOT)), phrase)
        for p in _claim_files()
        for phrase in BANNED_PHRASES
        if phrase.lower() in p.read_text().lower()
    ]
    assert hits == []


def test_sources_trace_to_claims_ledger() -> None:
    """Every taxonomy source and site incident names a results/CLAIMS.yaml external id."""
    import re

    ledger = yaml.safe_load((ROOT / "results/CLAIMS.yaml").read_text())
    ids = {e["id"] for e in ledger["external"]}
    for tid, attack in TAXONOMY.items():
        for src in attack.get("sources", []):
            m = re.match(r"\[([^\]]+)\] ", src)
            assert m and m.group(1) in ids, (tid, src)
    site = (ROOT / "dashboard/src/DeepXPIA.jsx").read_text()
    block = site[site.index("const COPILOT = ["): site.index("];", site.index("const COPILOT = ["))]
    refs = re.findall(r'ref: "([^"]+)"', block)
    assert refs and all(r in ids for r in refs), refs
