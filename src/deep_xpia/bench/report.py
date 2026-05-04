"""Generate markdown reports from benchmark results."""

from __future__ import annotations

from pathlib import Path

from deep_xpia.bench.metrics import AggregateMetrics, format_results_table


def write_results_report(
    metrics: AggregateMetrics,
    defense_label: str,
    output_path: str = "results/deepxpiabench-v1-results.md",
) -> None:
    body = format_results_table(metrics, defense_label)
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(body)


def write_coverage_matrix(
    all_metrics: dict[str, AggregateMetrics],
    output_path: str = "results/coverage_matrix.md",
) -> None:
    """Write defense x taxonomy coverage matrix."""
    taxonomy_ids = ["DXPIA-001", "DXPIA-002", "DXPIA-003", "DXPIA-004", "DXPIA-005", "DXPIA-006", "DXPIA-007"]
    defenses = list(all_metrics.keys())

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
        "# Defense x Taxonomy Coverage Matrix\n\nValues = TPR (detection rate)\n\n"
        + "\n".join(rows)
    )


def write_depth_analysis(
    all_metrics: dict[str, AggregateMetrics],
    output_path: str = "results/depth_analysis.md",
) -> None:
    """Write DDA (depth-dependent accuracy) analysis."""
    lines = [
        "# Depth-Dependent Accuracy (DDA) Analysis",
        "",
        "DDA measures how detection accuracy changes as injection depth increases.",
        "The hypothesis (from arXiv:2503.12188): detection degrades with depth,",
        "especially for DXPIA-006 (intent laundering).",
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
        "If detection accuracy decreases monotonically with depth: confirms the",
        "deep-xpia hypothesis. This is the headline finding.",
        "",
        "If no significant trend: also a finding -- challenges arXiv:2503.12188.",
        "Report honestly either way.",
    ]

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines))
