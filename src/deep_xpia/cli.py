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
    dataset: str = typer.Option("deepxpiabench-v2.jsonl", help="Dataset file"),
    target: str = typer.Option("native", help="Target adapter: native|langgraph|crewai|autogen"),
    defense: str = typer.Option("none", help="Defense: none|intent-verify|taint|scope|dlp|context-budget|all"),
    model: str = typer.Option("claude-haiku-4-5-20251001", help="Agent model"),
    output: str = typer.Option("results.jsonl", help="Output file"),
    n_runs: int = typer.Option(5, help="Runs per case for CI"),
    limit: int = typer.Option(0, help="Limit cases (0 = all)"),
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
    )
    runner.run()


@bench_app.command("generate")
def bench_generate(
    output: str = typer.Option("deepxpiabench-v2.jsonl", help="Output file"),
    n_attack: int = typer.Option(200, help="Number of attack cases"),
    n_clean: int = typer.Option(100, help="Number of clean cases"),
    seed: int = typer.Option(42, help="Random seed"),
) -> None:
    """Generate the DeepXPIABench dataset."""
    from deep_xpia.bench.generator import BenchGenerator

    gen = BenchGenerator(seed=seed)
    gen.generate(n_attack=n_attack, n_clean=n_clean, output_path=output)
    console.print(f"[green]Generated {n_attack + n_clean} cases -> {output}[/green]")


@app.command()
def demo() -> None:
    """Launch the interactive chain visualizer."""
    import uvicorn
    from deep_xpia.server import create_app

    uvicorn.run(create_app(), host="0.0.0.0", port=8000)
