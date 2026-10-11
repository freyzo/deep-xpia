"""Sensitivity check for the depth slope: GEE logistic model (needs the [analysis] extra).

detected ~ depth + C(taxonomy), binomial family, logit link, exchangeable
working correlation within payload template, robust (sandwich) standard
errors. Complements the linear-probability slope in v2_stats.md.

Run from the repo root (pip install -e '.[analysis]'):
    python results/reanalysis/depth_gee_v2.py > results/reanalysis/v2_depth_gee.md
"""

from __future__ import annotations

import math
import warnings
from pathlib import Path

import pandas as pd
import statsmodels.api as sm
import statsmodels.formula.api as smf

from deep_xpia.bench.outcomes import injected_hops_v2
from deep_xpia.bench.schema import BenchCase, RunResult
from deep_xpia.bench.stats import payload_template

DATASET = Path("deepxpiabench-v2.jsonl")
RAW = Path("results/raw/v2-live-2026-06")
FILES = {"intent": "live_full_intent.jsonl", "all": "live_full_all.jsonl"}


def _lines(p: Path) -> list[str]:
    return [ln for ln in p.read_text().splitlines() if ln.strip()]


def main() -> None:
    cases = {c.id: c for c in (BenchCase.model_validate_json(ln) for ln in _lines(DATASET))}
    delivered = sorted(cid for cid, c in cases.items() if c.ground_truth.is_attack and injected_hops_v2(c))
    out = [
        "# v2 depth effect: GEE logistic sensitivity model",
        "",
        "Model: detected ~ depth + C(taxonomy); binomial/logit; exchangeable correlation within payload",
        "template (16 clusters); robust SEs. Odds ratio per extra hop with 95% CI; AME = average marginal",
        "effect on detection probability per hop (point estimate).",
        "Command: `python results/reanalysis/depth_gee_v2.py` (statsmodels; `pip install -e '.[analysis]'`)",
        "",
        "| Defense | depth | odds ratio per hop [95% CI] | p | AME per hop |",
        "|---|---|---|---|---|",
    ]
    for d, fname in FILES.items():
        runs = {r.case_id: r for r in (RunResult.model_validate_json(ln) for ln in _lines(RAW / fname))}
        for label, depth_of in (("executed calls", lambda c: len(c.topology.agents) - 1),
                                ("hops after injection", lambda c: len(c.topology.agents) - 1 - min(injected_hops_v2(c)))):
            df = pd.DataFrame({
                "detected": [int(runs[c].detected) for c in delivered],
                "depth": [depth_of(cases[c]) for c in delivered],
                "taxonomy": [cases[c].taxonomy_id.value for c in delivered],
                "template": [payload_template(cases[c]) for c in delivered],
            })
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                fit = smf.gee("detected ~ depth + C(taxonomy)", "template", df,
                              family=sm.families.Binomial(), cov_struct=sm.cov_struct.Exchangeable()).fit()
            b, se, p = fit.params["depth"], fit.bse["depth"], fit.pvalues["depth"]
            mu = fit.fittedvalues
            ame = b * float((mu * (1 - mu)).mean())
            out.append(f"| {d} | {label} | {math.exp(b):.2f} [{math.exp(b - 1.96 * se):.2f}, {math.exp(b + 1.96 * se):.2f}] "
                       f"| {p:.3g} | {ame:+.3f} |")
    out += [
        "",
        "Read with v2_stats.md: the logistic model agrees on direction. Some taxonomies are detected in all or",
        "none of their cases under one defense, so their fixed effects sit near the boundary; treat the odds",
        "ratios as a sensitivity check, not the primary estimate.",
    ]
    print("\n".join(out))


if __name__ == "__main__":
    main()
