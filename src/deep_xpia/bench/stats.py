"""Inference for benchmark comparisons (stdlib only).

Follows Miller, "Adding Error Bars to Evals" (arXiv:2411.00640): compare
defenses on the same cases (paired tests), treat cases built from one payload
template as a cluster, and test "no effect" claims with an equivalence test
instead of a non-significant difference.

  mcnemar_exact          paired binary outcomes, exact two-sided test
  holm                   Holm-Bonferroni adjusted p-values
  cluster_bootstrap_ci   CI of a pooled mean, resampling clusters then cases
  depth_slope_fe         linear-probability slope of an outcome on depth with
                         fixed effects (e.g. taxonomy), in probability points
                         per hop; clustered bootstrap CI; TOST against +-delta
  payload_template       which injection_library template a v2 payload came from
"""

from __future__ import annotations

import random
import re
from collections import defaultdict
from collections.abc import Hashable, Sequence
from dataclasses import dataclass
from math import comb

from deep_xpia.bench import injection_library as lib
from deep_xpia.bench.outcomes import decode_payload
from deep_xpia.bench.schema import BenchCase


@dataclass(frozen=True)
class McNemar:
    only_a: int  # cases where a is true and b is false
    only_b: int
    p_value: float


def mcnemar_exact(a: Sequence[bool], b: Sequence[bool]) -> McNemar:
    """Exact (binomial) two-sided McNemar test on paired binary outcomes."""
    if len(a) != len(b):
        raise ValueError("paired outcomes must have equal length")
    only_a = sum(x and not y for x, y in zip(a, b))
    only_b = sum(y and not x for x, y in zip(a, b))
    n = only_a + only_b
    if n == 0:
        return McNemar(0, 0, 1.0)
    tail = sum(comb(n, k) for k in range(min(only_a, only_b) + 1)) / 2**n
    return McNemar(only_a, only_b, min(1.0, 2 * tail))


def holm(p_values: dict[str, float]) -> dict[str, float]:
    """Holm-Bonferroni step-down adjustment (monotone, capped at 1)."""
    order = sorted(p_values, key=lambda k: p_values[k])
    m = len(order)
    adjusted: dict[str, float] = {}
    running = 0.0
    for i, key in enumerate(order):
        running = max(running, min(1.0, (m - i) * p_values[key]))
        adjusted[key] = running
    return adjusted


def cluster_bootstrap_ci(
    values: Sequence[float],
    clusters: Sequence[Hashable],
    B: int = 10000,
    seed: int = 42,
    level: float = 0.95,
) -> tuple[float, float]:
    """Percentile CI of the pooled mean, resampling clusters, then cases within each."""
    groups: dict[Hashable, list[float]] = defaultdict(list)
    for v, c in zip(values, clusters):
        groups[c].append(v)
    keys = sorted(groups, key=str)
    rng = random.Random(seed)
    stats = []
    for _ in range(B):
        total = count = 0.0
        for k in rng.choices(keys, k=len(keys)):
            g = groups[k]
            draw = rng.choices(g, k=len(g))
            total += sum(draw)
            count += len(draw)
        stats.append(total / count)
    stats.sort()
    lo = stats[int((1 - level) / 2 * B)]
    hi = stats[min(B - 1, int((1 + level) / 2 * B))]
    return lo, hi


def _fe_slope(y: Sequence[float], x: Sequence[float], fe: Sequence[Hashable]) -> float:
    """OLS slope of y on x after removing fixed-effect group means (Frisch-Waugh)."""
    gy: dict[Hashable, list[float]] = defaultdict(list)
    gx: dict[Hashable, list[float]] = defaultdict(list)
    for yi, xi, g in zip(y, x, fe):
        gy[g].append(yi)
        gx[g].append(xi)
    my = {g: sum(v) / len(v) for g, v in gy.items()}
    mx = {g: sum(v) / len(v) for g, v in gx.items()}
    num = sum((xi - mx[g]) * (yi - my[g]) for yi, xi, g in zip(y, x, fe))
    den = sum((xi - mx[g]) ** 2 for xi, g in zip(x, fe))
    if den == 0:
        raise ValueError("no within-group variation in x")
    return num / den


@dataclass(frozen=True)
class SlopeResult:
    slope: float  # change in P(outcome) per unit depth
    ci90: tuple[float, float]  # for TOST at alpha = 0.05
    ci95: tuple[float, float]
    n: int
    clusters: int

    def equivalent_within(self, delta: float) -> bool:
        """TOST: both one-sided tests reject at 0.05 iff the 90% CI lies inside (-delta, +delta)."""
        return -delta < self.ci90[0] and self.ci90[1] < delta

    @property
    def smallest_delta_shown(self) -> float:
        """Smallest equivalence margin these data could establish."""
        return max(abs(self.ci90[0]), abs(self.ci90[1]))


def depth_slope_fe(
    y: Sequence[float],
    depth: Sequence[float],
    fe: Sequence[Hashable],
    clusters: Sequence[Hashable],
    B: int = 2000,
    seed: int = 42,
) -> SlopeResult:
    """Linear-probability slope on depth with fixed effects; CIs by cluster bootstrap."""
    slope = _fe_slope(y, depth, fe)
    rows = list(zip(y, depth, fe, clusters))
    groups: dict[Hashable, list[tuple[float, float, Hashable, Hashable]]] = defaultdict(list)
    for r in rows:
        groups[r[3]].append(r)
    keys = sorted(groups, key=str)
    rng = random.Random(seed)
    draws = []
    for _ in range(B):
        sample = [r for k in rng.choices(keys, k=len(keys)) for r in groups[k]]
        try:
            draws.append(_fe_slope([r[0] for r in sample], [r[1] for r in sample], [r[2] for r in sample]))
        except ValueError:
            continue
    draws.sort()

    def pct(q: float) -> float:
        return draws[min(len(draws) - 1, int(q * len(draws)))]

    return SlopeResult(slope, (pct(0.05), pct(0.95)), (pct(0.025), pct(0.975)), len(rows), len(keys))


def _template_regex(template: str) -> re.Pattern[str]:
    escaped = re.escape(template)
    for name in ("target", "action", "data", "trigger"):
        escaped = escaped.replace(re.escape("{" + name + "}"), "(.+?)")
    return re.compile(escaped, re.S)


_TEMPLATES: list[tuple[str, re.Pattern[str]]] = [
    *[(f"exfil-{i}", _template_regex(t)) for i, t in enumerate(lib.EXFIL_PAYLOADS)],
    *[(f"action-{i}", _template_regex(t)) for i, t in enumerate(lib.UNAUTHORIZED_ACTION_PAYLOADS)],
    *[(f"suppress-{i}", _template_regex(t)) for i, t in enumerate(lib.INFO_SUPPRESSION_PAYLOADS)],
    *[(f"laundered-{i}", _template_regex(t)) for i, t in enumerate(lib.LAUNDERED_EXFIL)],
]


def payload_template(case: BenchCase) -> str:
    """Id of the injection_library template a payload was built from ('' for clean cases)."""
    if case.injection is None:
        return ""
    raw = decode_payload(case)
    hits = [name for name, rx in _TEMPLATES if rx.fullmatch(raw)]
    if len(hits) != 1:
        raise ValueError(f"{case.id}: payload matches {len(hits)} templates")
    return hits[0]

