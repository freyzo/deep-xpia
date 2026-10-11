"""Generate markdown reports from benchmark results."""

from __future__ import annotations

from pathlib import Path

from deep_xpia.bench.metrics import AggregateMetrics, format_results_table
from deep_xpia.bench.schema import TaxonomyID


def _note(note: str) -> str:
    return f"> {note}\n\n" if note else ""


def write_results_report(
    all_metrics: dict[str, AggregateMetrics],
    output_path: str,
    note: str = "",
) -> None:
    """Write the core results table for each defense label."""
    body = _note(note) + "\n\n".join(
        format_results_table(m, label) for label, m in all_metrics.items()
    )
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(body)


def write_coverage_matrix(
    all_metrics: dict[str, AggregateMetrics],
    output_path: str,
    note: str = "",
) -> None:
    """Write defense x taxonomy coverage matrix."""
    taxonomy_ids = [t.value for t in TaxonomyID]

    header = "| Defense | " + " | ".join(taxonomy_ids) + " |"
    sep = "|---------|" + "|".join(["--------"] * len(taxonomy_ids)) + "|"
    rows = [header, sep]

    for defense, m in all_metrics.items():
        cells = []
        for tid in taxonomy_ids:
            tpr = m.per_taxonomy.get(tid, {}).get("tpr", 0.0)
            cells.append(f"{tpr:.2f}")
        rows.append(f"| {defense} | " + " | ".join(cells) + " |")

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        "# Defense x Taxonomy Coverage Matrix\n\n"
        + _note(note)
        + "Values = TPR (detection rate)\n\n"
        + "\n".join(rows)
        + "\n"
    )


def write_depth_analysis(
    all_metrics: dict[str, AggregateMetrics],
    output_path: str,
    note: str = "",
) -> None:
    """Write DDA (depth-dependent accuracy) analysis."""
    lines = [
        "# Depth-Dependent Accuracy (DDA) Analysis",
        "",
        *([f"> {note}", ""] if note else []),
        "DDA measures how detection accuracy changes as injection depth increases.",
        "Our hypothesis: detection degrades with depth, especially for DXPIA-006",
        "(intent laundering). It is motivated by the laundering mechanism in",
        "arXiv:2503.12188 (Sec. 4), which does not itself test depth.",
        "",
        "| Depth | " + " | ".join(all_metrics.keys()) + " |",
        "|-------|" + "|".join(["-------"] * len(all_metrics)) + "|",
    ]

    all_depths = sorted(set(d for m in all_metrics.values() for d in m.dda))
    for depth in all_depths:
        cells = [f"{m.dda.get(depth, 0.0):.3f}" for m in all_metrics.values()]
        lines.append(f"| {depth} | " + " | ".join(cells) + " |")

    lines += [
        "",
        "## Interpretation",
        "",
        "If detection accuracy decreases monotonically with depth: supports the",
        "depth-decay hypothesis.",
        "",
        "If no significant trend: report it. The hypothesis is ours, so a null",
        "result does not contradict arXiv:2503.12188.",
        "Report honestly either way. Note: the live (DEEPXPIA_LIVE=1) run did not",
        "show depth decay; depth is confounded with attack type. See README.",
    ]

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines))
