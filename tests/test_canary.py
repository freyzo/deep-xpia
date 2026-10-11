"""Per-case canaries (workflow P1.3): instrumentation only, no wording change."""

from __future__ import annotations

import json

from deep_xpia.bench.generator import BenchGenerator
from deep_xpia.bench.outcomes import decode_payload
from deep_xpia.bench.injection_library import POISONED_MANIFESTS


def _gen(tmp_path, canaries: bool, name: str):
    return BenchGenerator(seed=7, canaries=canaries).generate(n_attack=200, n_clean=40, output_path=str(tmp_path / name))


def test_canaries_unique_and_present_where_delivered(tmp_path) -> None:
    cases = _gen(tmp_path, True, "a.jsonl")
    attack = [c for c in cases if c.ground_truth.is_attack]
    tagged = [c for c in attack if c.metadata.get("canary")]
    assert len(tagged) >= 50
    assert len({c.metadata["canary"] for c in tagged}) == len(tagged)
    for c in tagged:
        delivered = json.dumps(c.tool_metadata) if c.tool_metadata else decode_payload(c)
        assert c.metadata["canary"] in delivered
    assert all("canary" not in c.metadata for c in cases if not c.ground_truth.is_attack)


def test_canaries_change_only_the_identifier(tmp_path) -> None:
    with_c = _gen(tmp_path, True, "a.jsonl")
    without = _gen(tmp_path, False, "b.jsonl")
    assert [c.id for c in with_c] == [c.id for c in without]
    for a, b in zip(with_c, without):
        canary = a.metadata.get("canary")
        if a.injection is None:
            continue
        strip = (lambda s: s.replace(f"-{canary}", "").replace(f"{canary}.", "")) if canary else (lambda s: s)
        # compare decoded payloads: base64 / homoglyph encodings carry the canary inside
        assert strip(decode_payload(a)) == decode_payload(b)
        assert a.injection.technique == b.injection.technique and a.injection.position == b.injection.position
        if a.tool_metadata:
            assert json.loads(strip(json.dumps(a.tool_metadata))) == b.tool_metadata


def test_manifest_library_is_not_mutated(tmp_path) -> None:
    before = json.dumps(POISONED_MANIFESTS, sort_keys=True)
    _gen(tmp_path, True, "a.jsonl")
    assert json.dumps(POISONED_MANIFESTS, sort_keys=True) == before
