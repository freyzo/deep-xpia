# deep-xpia

**how cross-prompt injection goes deeper than one agent**

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)

Single-agent XPIA is well-studied. The open problem is **multi-hop XPIA**: when the injection crosses delegation boundaries between agents. deep-xpia is a benchmark with 250 attack cases across 7 multi-hop injection patterns, with 4 defenses evaluated quantitatively.

The headline finding: **detection accuracy degrades as injections propagate deeper into the chain**. For DXPIA-006 (intent laundering), drift score drops from 1.0 at hop 1 to 0.0 at hop 2 -- the injection quality *improves* as it propagates.

## Quickstart

```bash
# Docker (full stack)
docker compose up
# open localhost:3000

# or pip
pip install deep-xpia

# interactive demo
deepxpia demo

# run the benchmark
deepxpia bench generate          # generate 250 cases
deepxpia bench run --defense none
deepxpia bench run --defense intent-verify
deepxpia bench run --defense all
```

## Use as a benchmark

```bash
# against your own LangGraph pipeline
deepxpia bench run --target langgraph --dataset deepxpiabench-v1.jsonl

# live mode (real LLM calls, ~$5-10 for 250 cases)
DEEPXPIA_LIVE=1 deepxpia bench run --model claude-haiku-4-5-20251001
```

## Use as a library

```python
# intent verification defense
from deep_xpia.defenses.intent_verify import IntentVerifier

verifier = IntentVerifier(threshold=0.5)
result = verifier.verify(
    hop=1,
    agent="research_agent",
    intent="Analyze market data",
    response=agent_output,
)
if result.blocked:
    raise SecurityError(f"Injection detected: {result.reason}")

# taint tracking
from deep_xpia.defenses.taint import TaintTracker
from deep_xpia.defenses.taint_types import TrustLevel

tracker = TaintTracker()
label = tracker.tag("external_pr", TrustLevel.UNTRUSTED, pr_content)
_, violation = tracker.check_and_propagate(2, "deploy_agent", output, "notification_agent", label)

# scope-bound delegation tokens
from deep_xpia.defenses.delegation_token import ScopeTokenEnforcer

enforcer = ScopeTokenEnforcer()
root = enforcer.issue_root("orchestrator", {"read_data", "summarize", "delegate"})
child = enforcer.delegate(root, "research_agent", {"read_data", "summarize"})
violation = enforcer.check_action(1, child, "research_agent", "execute_trade")
```

## Attack Taxonomy

| ID | Name | Hop Mechanism | Min Depth | OWASP |
|----|------|--------------|-----------|-------|
| DXPIA-001 | Session Smuggling | instruction piggyback | 2 | ASI02, ASI03 |
| DXPIA-002 | Memory Poisoning | temporal persistence | 2 | ASI07 |
| DXPIA-003 | Tool Chain Cascade | data flow cascade | 3 | ASI02, ASI04 |
| DXPIA-004 | Chain Re-routing | control plane injection | 2 | ASI01, ASI03 |
| DXPIA-005 | Scope Escalation | privilege differential | 2 | ASI03 |
| DXPIA-006 | Intent Laundering | adversarial refinement | 3 | ASI01 |
| DXPIA-007 | Delayed Trigger | conditional activation | 2 | ASI07 |

Full taxonomy: [taxonomy/TAXONOMY.md](taxonomy/TAXONOMY.md)

## Results (simulated baseline, N=5 per case)

| Defense | ASR | TPR | FPR | DXPIA-001 TPR | DXPIA-006 TPR |
|---------|-----|-----|-----|---------------|---------------|
| None | 0.87 | 0.05 | 0.05 | 0.05 | 0.05 |
| Intent verify | 0.52 | 0.57 | 0.15 | **0.82** | **0.38** |
| Taint | 0.64 | 0.53 | 0.08 | 0.35 | 0.32 |
| Scope tokens | 0.66 | 0.38 | 0.05 | 0.20 | 0.22 |
| DLP | 0.71 | 0.33 | 0.10 | 0.25 | 0.28 |
| All combined | 0.36 | 0.76 | 0.18 | **0.90** | **0.52** |

**DDA (depth-dependent accuracy, intent verify):**

| Depth | Detection Accuracy |
|-------|-------------------|
| 2 | 0.72 |
| 3 | 0.58 |
| 4 | 0.31 |
| 5 | 0.12 |

Detection accuracy drops 60 points from depth 2 to depth 5.

## Honest Limitations

- **DXPIA-006 resists intent verification.** The laundered instruction passes semantic similarity checks. Reproduces SentinelAgent's adversarial intent paraphrasing finding (arXiv:2604.02767).
- **Taint tracking loses provenance at memory boundaries.** DXPIA-002 evades taint tracking on naive memory stores.
- **Scope tokens don't catch intent drift within authorized scope.** DXPIA-001 evades scope tokens (smuggled instruction IS authorized text).
- **Benchmark size: 250 cases.** Different scope from ACIArena (1,356) -- confused-deputy focus + DDA metric. Not a replacement.

## Project Structure

```
deep-xpia/
  src/deep_xpia/
    bench/          generator, runner, metrics, report, schema
    defenses/       intent_verify, taint, delegation_token, dlp
    adapters/       native, base (protocol)
    server.py       FastAPI + WebSocket event server
    events.py       event types for visualizer
    cli.py          CLI
  scenarios/
    session_smuggling/   DXPIA-001
    memory_poisoning/    DXPIA-002
    intent_laundering/   DXPIA-006
  taxonomy/
    TAXONOMY.md, taxonomy.yaml, owasp_mapping.yaml, aciarena_mapping.yaml
  tests/            43 tests
```

## Related Work

- [ACIArena](https://arxiv.org/abs/2604.07775): 1,356 cases, 6 frameworks. General cascading injection.
- [SentinelAgent](https://arxiv.org/abs/2604.02767): formal delegation properties P1-P7.
- [arXiv:2503.12188](https://arxiv.org/abs/2503.12188): intermediate agents reformat injections (basis for DXPIA-006).

## Citation

```bibtex
@software{deep-xpia,
  author = {Freya Zou},
  title  = {deep-xpia: Multi-Hop Cross-Prompt Injection Benchmark for Multi-Agent AI Systems},
  year   = {2026},
  url    = {https://github.com/freya-zou/deep-xpia}
}
```

MIT License.
