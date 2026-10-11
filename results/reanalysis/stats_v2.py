"""Statistics on the frozen v2 live runs: paired tests, clustered CIs, depth slope.

Paired McNemar tests compare defenses on the same cases (Holm-adjusted);
clustered intervals treat cases built from one payload template as a
cluster; the depth effect is a linear-probability slope with taxonomy fixed
effects, its CI from a template-cluster bootstrap, read as an equivalence
test (TOST). Success rates use the provisional outcome scorer.

Run from the repo root:
    python results/reanalysis/stats_v2.py > results/reanalysis/v2_stats.md
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from deep_xpia.bench.metrics import wilson_ci
from deep_xpia.bench.outcomes import injected_hops_v2, score_run
from deep_xpia.bench.per_hop import detector_flags
from deep_xpia.bench.schema import BenchCase, RunResult
from deep_xpia.bench.stats import cluster_bootstrap_ci, depth_slope_fe, holm, mcnemar_exact, payload_template

DATASET = Path("deepxpiabench-v2.jsonl")
RAW = Path("results/raw/v2-live-2026-06")
FILES = {"none": "live_full_none.jsonl", "intent": "live_full_intent.jsonl", "all": "live_full_all.jsonl"}


def _lines(p: Path) -> list[str]:
    return [ln for ln in p.read_text().splitlines() if ln.strip()]


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()[:16]


def _ci(c: tuple[float, float]) -> str:
    return f"[{c[0]:.2f}, {c[1]:.2f}]"


def main() -> None:
    cases = {c.id: c for c in (BenchCase.model_validate_json(ln) for ln in _lines(DATASET))}
    runs = {d: {r.case_id: r for r in (RunResult.model_validate_json(ln) for ln in _lines(RAW / f))}
            for d, f in FILES.items()}
    delivered = sorted(cid for cid, c in cases.items() if c.ground_truth.is_attack and injected_hops_v2(c))
    clean = sorted(cid for cid, c in cases.items() if not c.ground_truth.is_attack)
    success = {d: {cid: score_run(cases[cid], runs[d][cid], injected_hops_v2(cases[cid])).success for cid in delivered}
               for d in FILES}
    offline = {cid: [any(f[k] for f in detector_flags(runs["none"][cid], cases[cid].user_task)) for k in ("intent", "either")]
               for cid in delivered}

    tests = {
        "detection: intent vs all (delivered attacks)": mcnemar_exact(
            [runs["intent"][c].detected for c in delivered], [runs["all"][c].detected for c in delivered]),
        "false positive: intent vs all (clean)": mcnemar_exact(
            [runs["intent"][c].detected for c in clean], [runs["all"][c].detected for c in clean]),
        "offline on identical outputs: intent vs either (delivered attacks)": mcnemar_exact(
            [offline[c][0] for c in delivered], [offline[c][1] for c in delivered]),
        "re-scored success: none vs intent": mcnemar_exact(
            [success["none"][c] for c in delivered], [success["intent"][c] for c in delivered]),
        "re-scored success: none vs all": mcnemar_exact(
            [success["none"][c] for c in delivered], [success["all"][c] for c in delivered]),
        "re-scored success: intent vs all": mcnemar_exact(
            [success["intent"][c] for c in delivered], [success["all"][c] for c in delivered]),
    }
    adj = holm({k: t.p_value for k, t in tests.items()})
    out = [
        "# v2 statistics: paired tests, clustered CIs, depth slope",
        "",
        "> Success rates use the PROVISIONAL outcome scorer (not yet validated against human labels).",
        "",
        "Inputs (sha256 prefix): " + ", ".join(
            [f"`{DATASET}` {_sha(DATASET)}"] + [f"`{f}` {_sha(RAW / f)}" for f in FILES.values()]),
        "Command: `python results/reanalysis/stats_v2.py`",
        f"Delivered attack cases: {len(delivered)}; clean cases: {len(clean)}; n=1 run per case.",
        "",
        "## Paired comparisons (exact McNemar, Holm-adjusted across this table)",
        "",
        "| Comparison | only first | only second | p | Holm p |",
        "|---|---|---|---|---|",
        *[f"| {k} | {t.only_a} | {t.only_b} | {t.p_value:.3g} | {adj[k]:.3g} |" for k, t in tests.items()],
    ]

    tax = sorted({cases[c].taxonomy_id.value for c in delivered if cases[c].taxonomy_id})
    per_tax = {t: mcnemar_exact([runs["intent"][c].detected for c in delivered if cases[c].taxonomy_id.value == t],
                                [runs["all"][c].detected for c in delivered if cases[c].taxonomy_id.value == t])
               for t in tax}
    adj_tax = holm({t: r.p_value for t, r in per_tax.items()})
    out += [
        "",
        "## Detection intent vs all by taxonomy (exploratory; Holm across the 8 tests)",
        "",
        "| Taxonomy | only intent | only all | p | Holm p |",
        "|---|---|---|---|---|",
        *[f"| {t} | {r.only_a} | {r.only_b} | {r.p_value:.3g} | {adj_tax[t]:.3g} |" for t, r in per_tax.items()],
    ]

    templates = [payload_template(cases[c]) for c in delivered]
    out += [
        "",
        f"## Detection rate: Wilson vs template-clustered bootstrap ({len(set(templates))} templates)",
        "",
        "| Defense | rate | Wilson 95% | clustered bootstrap 95% |",
        "|---|---|---|---|",
    ]
    for d in ("intent", "all"):
        ys = [float(runs[d][c].detected) for c in delivered]
        k = int(sum(ys))
        out.append(f"| {d} | {k}/{len(ys)} = {k / len(ys):.2f} | {_ci(wilson_ci(k, len(ys)))} "
                   f"| {_ci(cluster_bootstrap_ci(ys, templates))} |")

    out += [
        "",
        "## Depth effect on detection (equivalence test)",
        "",
        "Linear-probability slope of `detected` on depth, taxonomy fixed effects, template-cluster bootstrap",
        "(2,000 draws). Slope = change in detection probability per extra hop. TOST at 5%: equivalence within",
        "+-delta holds iff the 90% CI lies inside it; the last column is the smallest margin these data establish.",
        "",
        "| Defense | depth | slope | 90% CI | 95% CI | n (clusters) | smallest margin shown |",
        "|---|---|---|---|---|---|---|",
    ]
    for d in ("intent", "all"):
        for label, depth_of in (("executed calls", lambda c: len(c.topology.agents) - 1),
                                ("hops after injection", lambda c: len(c.topology.agents) - 1 - min(injected_hops_v2(c)))):
            r = depth_slope_fe([float(runs[d][c].detected) for c in delivered],
                               [float(depth_of(cases[c])) for c in delivered],
                               [cases[c].taxonomy_id.value for c in delivered], templates)
            out.append(f"| {d} | {label} | {r.slope:+.3f} | {_ci(r.ci90)} | {_ci(r.ci95)} | {r.n} ({r.clusters}) "
                       f"| +-{r.smallest_delta_shown:.2f} |")
    out += [
        "",
        "## Reading",
        "",
        "- Intent verification: the slope's 90% CI includes declines of up to 14 points per hop, and no margin",
        "  was fixed in advance, so 'detection does not decay with depth' is not established by v2.",
        "- Intent + taint: run-level detection rises with depth even within taxonomy, but a run gets one more",
        "  chance to be flagged at every hop and the taint flag fires on about half of payload-free hops",
        "  (v2_per_hop.md). A rising curve is expected without any depth effect on the detectors; per-hop",
        "  rates (v2_per_hop.md) are the measure to use.",
        "- The two configurations differ strongly in how often they fire, on attacks and on clean cases alike;",
        "  with re-scored success near zero for every defense, v2 cannot show that either reduces attack success.",
    ]
    print("\n".join(out))


if __name__ == "__main__":
    main()
