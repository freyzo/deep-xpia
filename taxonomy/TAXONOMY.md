# deep-xpia Attack Taxonomy v1.0.0

**XPIA** = cross-prompt injection attack (indirect prompt injection).  
**deep** = the injection propagates through multi-agent delegation chains.

The taxonomy is organized by **hop mechanism**: *how* the injection crosses agent boundaries, not just *that* it does.

---

## DXPIA-001: Session Smuggling

**Hop mechanism:** instruction piggyback  
**Depth:** 2-3 hops  
**OWASP Agentic:** ASI02, ASI03  
**SentinelAgent property violated:** P2 (intent preservation)

The delegatee returns clean output plus a hidden action instruction appended at the end. The delegator trusts the output as-is and forwards the embedded action to a third agent. The injection rides inside a legitimate response — no abnormal channel required.

**Three confused deputies:**
1. *Research agent*: has data access, produces action instruction (confused)
2. *Financial assistant*: trusts research output, forwards trade (confused)
3. *Trade executor*: receives authorized-looking request (innocent)

**Reference:** CSA session smuggling PoC (March 2026)  
**Reference scenario:** `scenarios/session_smuggling/`

---

## DXPIA-002: Cross-Agent Memory Poisoning

**Hop mechanism:** temporal persistence  
**Depth:** 2+ hops, across sessions  
**OWASP Agentic:** ASI07  
**SentinelAgent property violated:** P6 (scope-action conformance)

Agent A writes attacker-controlled data to shared memory. Agent B reads it in a later session and acts on poisoned data. The injection persists across session boundaries, making attribution and detection harder.

**Key dimension:** "deep" in the *time* dimension, not just topology. The injection survives session boundaries.

**Reference:** Rehberger Gemini memory attack (2025)  
**Reference scenario:** `scenarios/memory_poisoning/`

---

## DXPIA-003: Tool Chain Cascade

**Hop mechanism:** data flow cascade  
**Depth:** 3+ hops  
**OWASP Agentic:** ASI02, ASI04  
**SentinelAgent property violated:** P1 (authority narrowing)

Injection enters at hop 1, executes at hop 2, exfiltrates at hop 3. No single agent acts outside its permissions in isolation. The vulnerability is the chain itself — each hop adds a capability the injection exploits at the next.

**Reference:** Invariant cross-server MCP exfil (April 2025)

---

## DXPIA-004: Delegation Chain Re-routing

**Hop mechanism:** control plane injection  
**Depth:** 2 hops  
**OWASP Agentic:** ASI01, ASI03  
**SentinelAgent property violated:** P4 (cascade containment)

The compromised agent modifies the delegation chain *topology* itself — instructing the orchestrator to add an attacker-controlled agent or skip a security-checking agent. The injection escapes the data plane into the orchestration layer.

**Reference:** arXiv:2503.12188 MAS hijacking

---

## DXPIA-005: Scope Escalation via Delegation

**Hop mechanism:** privilege differential  
**Depth:** 2 hops  
**OWASP Agentic:** ASI03  
**SentinelAgent property violated:** P1 (authority narrowing)

Agent A has permissions `{read}`. It delegates to agent B with permissions `{read, write}`. Agent A includes an instruction causing B to exercise its write permission on A's behalf. A has effectively escalated beyond its own scope through delegation.

**Reference:** CSA cross-agent privilege escalation (Sept 2025)

---

## DXPIA-006: Intent Laundering

**Hop mechanism:** adversarial refinement  
**Depth:** 3+ hops  
**OWASP Agentic:** ASI01  
**SentinelAgent property violated:** P2 (intent preservation)

An intermediate agent *reformats* the malicious instruction — stripping obvious injection markers, rephrasing as natural output. Downstream agents receive clean-looking input. **The attack quality improves as it propagates**, inverting the usual assumption that cascading degrades injection effectiveness.

**The headline finding:** Detection at hop 2 is harder than at hop 1. This is the arXiv:2503.12188 result: "intermediate trusted agents actively reformat malicious instructions to strip detection markers." The DDA metric quantifies this degradation.

**Honest limitation:** Intent verification (P2) catches DXPIA-001 well but struggles with DXPIA-006 because the laundered instruction passes semantic similarity checks. This reproduces SentinelAgent's adversarial intent paraphrasing finding.

**Reference scenario:** `scenarios/intent_laundering/`

---

## DXPIA-007: Delayed Delegation Trigger

**Hop mechanism:** conditional activation  
**Depth:** 2+ hops, time-delayed  
**OWASP Agentic:** ASI07  
**SentinelAgent property violated:** P3 (forensic reconstructibility)

Injection enters agent A but remains dormant until a trigger condition is met in a future delegation — agent B says "confirmed", a time elapses, or a context condition is satisfied. The dormant form is hard to detect; attribution to the original source becomes difficult.

**Reference:** Rehberger delayed trigger in Gemini (2025)

---

## Summary Table

| ID | Name | Hop Mechanism | Min Depth | OWASP | Property |
|----|------|--------------|-----------|-------|----------|
| DXPIA-001 | Session Smuggling | instruction piggyback | 2 | ASI02, ASI03 | P2 |
| DXPIA-002 | Memory Poisoning | temporal persistence | 2 | ASI07 | P6 |
| DXPIA-003 | Tool Chain Cascade | data flow cascade | 3 | ASI02, ASI04 | P1 |
| DXPIA-004 | Chain Re-routing | control plane injection | 2 | ASI01, ASI03 | P4 |
| DXPIA-005 | Scope Escalation | privilege differential | 2 | ASI03 | P1 |
| DXPIA-006 | Intent Laundering | adversarial refinement | 3 | ASI01 | P2 |
| DXPIA-007 | Delayed Trigger | conditional activation | 2 | ASI07 | P3 |

---

## Mappings

- **OWASP:** `taxonomy/owasp_mapping.yaml`
- **ACIArena:** `taxonomy/aciarena_mapping.yaml`
- **Machine-readable:** `taxonomy/taxonomy.yaml`
