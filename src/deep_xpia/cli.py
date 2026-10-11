"""deep-xpia CLI."""

from __future__ import annotations

import typer
from rich.console import Console

app = typer.Typer(
    name="deepxpia",
    help="deep-xpia: multi-hop cross-prompt injection benchmark",
    add_completion=False,
)
console = Console()

bench_app = typer.Typer(help="Benchmark commands")
app.add_typer(bench_app, name="bench")


@bench_app.command("run")
def bench_run(
    dataset: str = typer.Option(
        "deepxpiabench-v2.jsonl", help="Dataset file (v2 = the 300-case set behind the README results)"
    ),
    target: str = typer.Option("native", help="Target adapter (only 'native' ships today)"),
    defense: str = typer.Option("none", help="Defense: none|intent-verify|taint|scope|dlp|context-budget|all"),
    model: str = typer.Option("claude-haiku-4-5-20251001", help="Agent model"),
    output: str = typer.Option("results.jsonl", help="Output file"),
    n_runs: int = typer.Option(5, help="Runs per case for CI"),
    limit: int = typer.Option(0, help="Limit cases (0 = all)"),
    temperature: float = typer.Option(None, help="Live sampling temperature (default: API default)"),
    judge: str = typer.Option("v2", help="Live success judge: v2 (outcome scorer) | legacy (v2 keyword rule, reproduction only)"),
    message_format: str = typer.Option(
        "delegation", help="Hand-off to hops >= 1: delegation (task + upstream output) | bare (v2: upstream output only)"
    ),
    provider: str = typer.Option("anthropic", help="Live model provider: anthropic | openai (OpenAI-compatible API)"),
    base_url: str = typer.Option(None, help="Base URL for an OpenAI-compatible server (e.g. a local vLLM)"),
) -> None:
    """Run DeepXPIABench against a target MAS."""
    from deep_xpia.bench.runner import BenchRunner

    runner = BenchRunner(
        dataset_path=dataset,
        target=target,
        defense=defense,
        model=model,
        output_path=output,
        n_runs=n_runs,
        limit=limit or None,
        temperature=temperature,
        judge=judge,
        message_format=message_format,
        provider=provider,
        base_url=base_url,
    )
    runner.run()


@bench_app.command("generate")
def bench_generate(
    output: str = typer.Option("deepxpiabench-v3.jsonl", help="Output file"),
    n_attack: int = typer.Option(200, help="Number of attack cases"),
    n_clean: int = typer.Option(100, help="Number of clean cases"),
    seed: int = typer.Option(42, help="Random seed"),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing output file"),
    linear_only: bool = typer.Option(
        True, "--linear-only/--all-topologies",
        help="Linear chains only (the live runner does not execute fan-out/hierarchical/loop edges)",
    ),
) -> None:
    """Generate the DeepXPIABench dataset."""
    from pathlib import Path

    from deep_xpia.bench.generator import BenchGenerator

    # the shipped datasets are the inputs to published results; never clobber silently
    if Path(output).exists() and not force:
        console.print(f"[red]{output} already exists; pass --force to overwrite[/red]")
        raise typer.Exit(code=1)

    gen = BenchGenerator(seed=seed, linear_only=linear_only)
    gen.generate(n_attack=n_attack, n_clean=n_clean, output_path=output)
    console.print(f"[green]Generated {n_attack + n_clean} cases -> {output}[/green]")


@bench_app.command("report")
def bench_report(
    runs: list[str] = typer.Argument(..., help="LABEL=results.jsonl pairs, one per defense"),
    dataset: str = typer.Option("deepxpiabench-v2.jsonl", help="Dataset the runs used"),
    out_dir: str = typer.Option("report", help="Output directory (not results/, which is curated)"),
    note: str = typer.Option("", help="Provenance note placed at the top of each report"),
    depth_source: str = typer.Option(
        "topology", help="DDA depth: topology (edges built) | executed (live calls) | label (case.depth)"
    ),
) -> None:
    """Write results, coverage-matrix and DDA reports from `bench run` outputs."""
    from pathlib import Path

    from deep_xpia.bench.metrics import compute_metrics
    from deep_xpia.bench.report import (
        write_coverage_matrix,
        write_depth_analysis,
        write_results_report,
    )
    from deep_xpia.bench.schema import BenchCase, RunResult

    def _jsonl(path: str) -> list[str]:
        return [ln for ln in Path(path).read_text().splitlines() if ln.strip()]

    cases = [BenchCase.model_validate_json(ln) for ln in _jsonl(dataset)]
    all_metrics = {}
    for pair in runs:
        label, sep, path = pair.partition("=")
        if not sep or not label or not path:
            raise typer.BadParameter(f"expected LABEL=path, got {pair!r}")
        results = [RunResult.model_validate_json(ln) for ln in _jsonl(path)]
        n_runs = max((r.run_index for r in results), default=0) + 1
        all_metrics[label] = compute_metrics(cases, results, n_runs, depth_source=depth_source)

    out = Path(out_dir)
    write_results_report(all_metrics, str(out / "results.md"), note)
    write_coverage_matrix(all_metrics, str(out / "coverage_matrix.md"), note)
    write_depth_analysis(all_metrics, str(out / "depth_analysis.md"), note)
    console.print(f"[green]Wrote 3 reports for {', '.join(all_metrics)} -> {out}/[/green]")


@app.command()
def demo() -> None:
    """Serve the scenario demo API (events over WebSocket) and the static site on :8000."""
    import uvicorn
    from deep_xpia.server import create_app

    uvicorn.run(create_app(), host="0.0.0.0", port=8000)
