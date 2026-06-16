# deep-xpia

**The trust boundary predicts compromise, not delegation depth.**

deep-xpia benchmarks multi-hop cross-prompt injection (XPIA) across agent delegation chains. One injection, three agents, zero alerts. 300 cases, 8 attack patterns, 5 defenses, with a live harness that measures defenses against real model output.

This wiki is the reference companion to the [README](https://github.com/freyzo/deep-xpia). Start here for the concepts; go to the code to run the benchmark.

## the finding (live-measured)

Anthropic API, Claude Haiku, 300 cases, June 2026:

- Undefended, **69% of multi-hop injections succeed**. No single defense closes the gap (intent verification alone: 23% TPR at 1% FPR). All five stacked cut attack success to 12%, at a 31% false-positive cost.
- **The blind spot is the trust boundary, not depth.** Registry injection (DXPIA-008) enters at tool-discovery time and evades all five defenses stacked. Hop count does not predict detection; position relative to the trust boundary does.
- **The depth-decay hypothesis did not replicate.** An earlier simulation modeled detection falling with depth; live measurement showed it flat and confounded with attack type. The simulated curve was a property of the model, not the world. See [Results](Results) and [Metrics](Metrics).

## why it matters

Single-agent XPIA tools (mcp-scan, promptfoo) measure how vulnerable one model is to one prompt. deep-xpia measures what happens when injections cross delegation and tool-trust boundaries, and reports what the measurement says even when it contradicts the original hypothesis.

## where to go next

- [Attack Taxonomy](Taxonomy) - the 8 DXPIA patterns
- [Defenses](Defenses) - the 5 defense primitives
- [Metrics](Metrics) - DDA and CAS, and why DDA falsified the depth hypothesis
- [Results](Results) - live measured numbers and the simulated prior, clearly separated
- [Contributing](Contributing) - add an attack, a defense, or an adapter

## quickstart

```bash
docker compose up        # full stack + visualizer, then localhost:3000
# or
pip install deep-xpia
deepxpia demo

DEEPXPIA_LIVE=1 deepxpia bench run --defense all --n-runs 1 --output live_all.jsonl
```
