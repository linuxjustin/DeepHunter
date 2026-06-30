"""DeepHunter CLI — main entry point.

Uses Click for command parsing and Rich for formatted output.
"""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from deephunter.core.config import DeepHunterConfig
from deephunter.ingestion.pipeline import IngestionPipeline
from deephunter.knowledge.store import KnowledgeStore
from deephunter.rag.embeddings import EmbeddingProviderFactory
from deephunter.rag.retriever import Retriever
from deephunter.reasoning.hypothesis import HypothesisGenerator
from deephunter.utils.logging import setup_logging

console = Console()


@click.group()
@click.option(
    "--config",
    "-c",
    default="config.yaml",
    help="Path to configuration file",
    show_default=True,
)
@click.option(
    "--log-level",
    default=None,
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
    help="Override configured log level",
)
@click.pass_context
def cli(ctx: click.Context, config: str, log_level: str | None) -> None:
    """DeepHunter — AI-assisted bug bounty research platform."""
    ctx.ensure_object(dict)

    cfg_path = Path(config)
    if cfg_path.exists():
        cfg = DeepHunterConfig.load(str(cfg_path))
    else:
        cfg = DeepHunterConfig.default()
        if cfg_path.suffix in {".yaml", ".yml"}:
            cfg.save(str(cfg_path))
            console.print(f"[yellow]Created default config at {cfg_path}[/yellow]")

    if log_level:
        cfg.log_level = log_level

    setup_logging(level=cfg.log_level, log_file=cfg.log_file)
    ctx.obj["config"] = cfg
    ctx.obj["store"] = KnowledgeStore()


@cli.command()
@click.argument("paths", nargs=-1, type=click.Path(exists=True))
@click.option("--recursive/--no-recursive", default=None, help="Scan directories recursively")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format for results",
)
@click.pass_context
def ingest(
    ctx: click.Context,
    paths: tuple[str, ...],
    recursive: bool | None,
    fmt: str,
) -> None:
    """Ingest knowledge documents into the store.

    Scans the given paths (file or directory) for supported documents,
    parses them, and stores them as SKOs.
    """
    config: DeepHunterConfig = ctx.obj["config"]
    store: KnowledgeStore = ctx.obj["store"]

    pipeline = IngestionPipeline(config, store)
    input_paths = list(paths) if paths else None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Ingesting documents...", total=None)

        report = pipeline.run(paths=input_paths, recursive=recursive)

        progress.update(task, total=report.total, completed=report.total)

    if fmt == "json":
        import json

        console.print(json.dumps({
            "total": report.total,
            "parsed": report.stored,
            "skipped": report.skipped,
            "duplicates": report.duplicates,
            "failed": report.failed,
            "elapsed_seconds": report.elapsed_seconds,
            "errors": [
                {"path": str(e.path), "error": e.error}
                for e in report.errors
            ],
        }, indent=2))
        return

    console.print()
    table = Table(title="Ingestion Results", title_style="bold green")
    table.add_column("Metric", style="cyan")
    table.add_column("Count", style="green")

    table.add_row("Total files found", str(report.total))
    table.add_row("Successfully parsed", str(report.stored))
    table.add_row("Skipped (no parser / error)", str(report.skipped))
    table.add_row("Duplicates skipped", str(report.duplicates))
    table.add_row("Failed", str(report.failed))
    table.add_row("Validation failures", str(report.validation.failed))
    table.add_row("Elapsed time", f"{report.elapsed_seconds:.2f}s")

    console.print(table)

    if report.errors:
        error_table = Table(title="Errors", title_style="bold red")
        error_table.add_column("File", style="red")
        error_table.add_column("Error", style="red")
        for err in report.errors:
            error_table.add_row(str(err.path), err.error or "")
        console.print(error_table)


@cli.command()
@click.option("--tag", "-t", multiple=True, help="Filter by tag")
@click.option("--bug-class", "-b", help="Filter by bug class")
@click.option("--source-type", "-s", help="Filter by source type")
@click.pass_context
def list_skos(
    ctx: click.Context,
    tag: tuple[str, ...],
    bug_class: str | None,
    source_type: str | None,
) -> None:
    """List stored Security Knowledge Objects."""
    store: KnowledgeStore = ctx.obj["store"]

    if tag:
        skos = []
        for t in tag:
            skos.extend(store.search_by_tag(t))
    elif bug_class:
        skos = store.search_by_bug_class(bug_class)
    elif source_type:
        skos = store.search_source_type(source_type)
    else:
        skos = store.list_all()

    if not skos:
        console.print("[yellow]No SKOs found.[/yellow]")
        return

    table = Table(title=f"SKOs ({len(skos)} total)")
    table.add_column("ID", style="dim")
    table.add_column("Title")
    table.add_column("Source Type")
    table.add_column("Bug Classes")
    table.add_column("Tags")

    for sko in skos:
        bc_str = ", ".join(b.value for b in sko.bug_classes[:3])
        tags_str = ", ".join(sko.tags[:5])
        table.add_row(
            sko.id[:8],
            sko.title[:50],
            sko.source_type.value,
            bc_str,
            tags_str,
        )

    console.print(table)


@cli.command()
@click.argument("sko_id")
@click.pass_context
def get_sko(ctx: click.Context, sko_id: str) -> None:
    """Display details of a specific SKO by ID."""
    store: KnowledgeStore = ctx.obj["store"]
    sko = store.get(sko_id)

    if sko is None:
        matches = [s for s in store.list_all() if s.id.startswith(sko_id)]
        if not matches:
            console.print(f"[red]SKO not found: {sko_id}[/red]")
            return
        sko = matches[0]

    console.print(f"[bold]Title:[/bold] {sko.title}")
    console.print(f"[bold]Source:[/bold] {sko.source}")
    console.print(f"[bold]Type:[/bold] {sko.source_type.value} / {sko.document_type.value}")
    console.print(f"[bold]Confidence:[/bold] {sko.confidence.value}")
    console.print(f"[bold]Bug Classes:[/bold] {', '.join(b.value for b in sko.bug_classes)}")
    console.print(f"[bold]Technologies:[/bold] {', '.join(t.value for t in sko.technology)}")

    if sko.summary:
        console.print(f"\n[bold]Summary:[/bold]\n{sko.summary}")

    if sko.high_level_testing_ideas:
        console.print("\n[bold]Testing Ideas:[/bold]")
        for idea in sko.high_level_testing_ideas:
            console.print(f"  - {idea.description}")

    if sko.references:
        console.print("\n[bold]References:[/bold]")
        for ref in sko.references:
            console.print(f"  - {ref.title}")


@cli.command()
@click.argument("query")
@click.option("--top-k", default=5, help="Number of results")
@click.option("--threshold", default=0.3, type=float, help="Similarity threshold")
@click.pass_context
def search(ctx: click.Context, query: str, top_k: int, threshold: float) -> None:
    """Search knowledge using RAG-based retrieval."""
    config: DeepHunterConfig = ctx.obj["config"]
    store: KnowledgeStore = ctx.obj["store"]

    config.rag.top_k = top_k
    config.rag.similarity_threshold = threshold

    embedding_provider = EmbeddingProviderFactory.create(config.rag)
    retriever = Retriever(config.rag, store, embedding_provider)

    indexed = retriever.index()
    if indexed == 0:
        console.print("[yellow]No SKOs indexed. Ingest documents first with 'deephunter ingest'.[/yellow]")
        return

    results = retriever.query(query)

    table = Table(title=f"Search Results for: {query}")
    table.add_column("Score", style="green")
    table.add_column("Title")
    table.add_column("Bug Classes")
    table.add_column("Source")

    for sko, score in results:
        bc_str = ", ".join(b.value for b in sko.bug_classes[:2])
        table.add_row(
            f"{score:.4f}",
            sko.title[:50],
            bc_str,
            sko.source[:40],
        )

    console.print(table)


@cli.command()
@click.argument("context")
@click.pass_context
def hypothesize(ctx: click.Context, context: str) -> None:
    """Generate research hypotheses for a target context."""
    config: DeepHunterConfig = ctx.obj["config"]
    store: KnowledgeStore = ctx.obj["store"]

    if store.count() == 0:
        console.print("[yellow]No knowledge ingested yet. Use 'deephunter ingest' first.[/yellow]")
        return

    embedding_provider = EmbeddingProviderFactory.create(config.rag)
    retriever = Retriever(config.rag, store, embedding_provider)

    retriever.index()

    gen = HypothesisGenerator(store, retriever, config.reasoning)
    hypotheses = gen.generate(context)

    if not hypotheses:
        console.print("[yellow]No hypotheses generated from current knowledge.[/yellow]")
        return

    table = Table(title=f"Hypotheses for: {context}")
    table.add_column("Priority", style="bold")
    table.add_column("Title")
    table.add_column("Bug Class")
    table.add_column("Confidence")

    for hyp in hypotheses:
        bc_str = ", ".join(b.value for b in hyp.bug_classes[:2])
        table.add_row(
            hyp.priority.value.upper(),
            hyp.title[:50],
            bc_str,
            hyp.confidence.value,
        )

    console.print(table)

    for hyp in hypotheses:
        console.print(f"\n[bold]{hyp.priority.value.upper()}:[/bold] {hyp.title}")
        console.print(f"  [dim]Description:[/dim] {hyp.description}")
        console.print(f"  [dim]Rationale:[/dim] {hyp.rationale}")
        if hyp.testing_ideas:
            console.print(f"  [dim]Test:[/dim] {hyp.testing_ideas[0]}")


@cli.command()
@click.pass_context
def stats(ctx: click.Context) -> None:
    """Show statistics about the knowledge store."""
    store: KnowledgeStore = ctx.obj["store"]
    skos = store.list_all()

    console.print(f"[bold]Total SKOs:[/bold] {len(skos)}")

    source_counts: dict[str, int] = {}
    bc_counts: dict[str, int] = {}

    for sko in skos:
        source_counts[sko.source_type.value] = source_counts.get(sko.source_type.value, 0) + 1
        for bc in sko.bug_classes:
            bc_counts[bc.value] = bc_counts.get(bc.value, 0) + 1

    if source_counts:
        table = Table(title="By Source Type")
        table.add_column("Source", style="cyan")
        table.add_column("Count", style="green")
        for source, count in sorted(source_counts.items(), key=lambda x: -x[1]):
            table.add_row(source, str(count))
        console.print(table)

    if bc_counts:
        table = Table(title="By Bug Class")
        table.add_column("Bug Class", style="cyan")
        table.add_column("Count", style="green")
        for bc, count in sorted(bc_counts.items(), key=lambda x: -x[1]):
            table.add_row(bc, str(count))
        console.print(table)


@cli.command()
@click.argument("output", default="config.yaml")
def init(output: str) -> None:
    """Create a default configuration file."""
    cfg = DeepHunterConfig.default()
    cfg.save(output)
    console.print(f"[green]Default configuration written to {output}[/green]")
    console.print("Edit this file to customize DeepHunter behavior.")


@cli.command()
@click.argument("target")
@click.pass_context
def plan(ctx: click.Context, target: str) -> None:
    """Generate an investigation plan for a target.

    Creates a phased, prioritized investigation plan based on
    the target description and available knowledge.
    """
    console.print("[yellow]Planning engine active. Generating investigation plan...[/yellow]")
    console.print(f"[bold]Target:[/bold] {target}")

    from deephunter.reasoning.session import InvestigationSession
    from deephunter.planning import Planner, PlanningPhase

    session = InvestigationSession.new(target)
    planner = Planner()
    result = planner.plan_from_session(session)

    plan = result.plan
    if not plan.steps:
        console.print("[yellow]No investigation steps generated. Add more context.[/yellow]")
        return

    table = Table(title=f"Investigation Plan — {target}")
    table.add_column("Phase", style="cyan")
    table.add_column("Step", style="white")
    table.add_column("Priority", style="green")
    table.add_column("Est. Hours", style="yellow")
    table.add_column("Risk", style="red")

    for step in plan.steps:
        table.add_row(
            step.phase.value,
            step.title[:60],
            f"{step.priority_score:.2f}",
            str(step.estimated_cost_hours),
            str(step.risk.overall),
        )

    console.print(table)
    console.print(f"[bold]Total estimated hours:[/bold] {plan.total_estimated_hours:.1f}")
    console.print(f"[bold]Phases covered:[/bold] {len(plan.phases_covered)}/{len(list(PlanningPhase))}")
    console.print(f"[bold]Risk score:[/bold] {plan.risk.overall:.1f}/10.0")


@cli.command()
@click.pass_context
def roadmap(ctx: click.Context) -> None:
    """Show the investigation roadmap from latest plan."""
    console.print("[yellow]Roadmap command: Load the latest investigation plan and display ordered steps.[/yellow]")
    console.print("Use 'deephunter plan <target>' first to generate a plan.")


@cli.command()
@click.argument("target")
@click.option("--enable-subdomain", default=True, help="Enable subdomain enumeration")
@click.option("--enable-dns", default=True, help="Enable DNS resolution")
@click.option("--enable-ports", default=True, help="Enable port scanning")
@click.option("--enable-http-probe", default=True, help="Enable HTTP probing")
@click.pass_context
def recon(ctx: click.Context, target: str, **flags: bool) -> None:
    """Run initial reconnaissance against a target."""
    from deephunter.agents.workflows.initial_recon import InitialReconWorkflow
    workflow = InitialReconWorkflow()
    with console.status("[bold green]Running reconnaissance...") as status:
        result = workflow.execute({"target": target, **{f"enable_{k.replace('-', '_')}": v for k, v in flags.items()}})
    if result.success:
        console.print(f"[green]Recon completed in {result.execution_time_ms:.0f}ms[/green]")
    else:
        console.print(f"[red]Recon failed: {result.error}[/red]")


@cli.command()
@click.argument("target")
@click.option("--enable-gau", default=True, help="Enable gau URL discovery")
@click.option("--enable-wayback", default=True, help="Enable Wayback URL discovery")
@click.option("--enable-crawl", default=False, help="Enable crawling with Katana")
@click.option("--enable-fuzz", default=False, help="Enable fuzzing with ffuf")
@click.pass_context
def scan(ctx: click.Context, target: str, **flags: bool) -> None:
    """Run attack surface expansion against a target."""
    from deephunter.agents.workflows.attack_surface import AttackSurfaceWorkflow
    workflow = AttackSurfaceWorkflow()
    with console.status("[bold green]Scanning attack surface...") as status:
        result = workflow.execute({"target": target, **{f"enable_{k.replace('-', '_')}": v for k, v in flags.items()}})
    if result.success:
        console.print(f"[green]Scan completed in {result.execution_time_ms:.0f}ms[/green]")
    else:
        console.print(f"[red]Scan failed: {result.error}[/red]")


@cli.command()
@click.option("--benchmark", "-b", multiple=True, help="Specific benchmark(s) to run (default: all)")
@click.option("--format", "fmt", default="table", type=click.Choice(["table", "json"]), help="Output format")
@click.pass_context
def benchmark(ctx: click.Context, benchmark: tuple[str, ...], fmt: str) -> None:
    """Run evaluation benchmarks against subsystems."""
    from deephunter.evaluation.datasets.app_benchmarks import get_app_benchmarks, get_app_benchmark
    if benchmark:
        entries = [get_app_benchmark(b) for b in benchmark if get_app_benchmark(b)]
    else:
        entries = get_app_benchmarks()
    if not entries:
        console.print("[yellow]No benchmarks found.[/yellow]")
        return
    table = Table(title=f"App Benchmarks ({len(entries)} loaded)")
    table.add_column("Name", style="cyan")
    table.add_column("Difficulty", style="yellow")
    table.add_column("Bug Classes", style="green")
    table.add_column("Steps", style="white")
    table.add_column("Hypotheses", style="white")
    table.add_column("CWEs", style="dim")
    for e in entries:
        table.add_row(
            e.name, e.difficulty, str(len(e.input.bug_classes)),
            str(len(e.expected.planner_steps)), str(len(e.expected.reasoning.hypotheses)),
            ", ".join(e.cwe_ids[:3]),
        )
    console.print(table)


@cli.command()
@click.argument("target")
@click.option("--author", default="DeepHunter", help="Report author name")
@click.option("--format", "fmt", default="markdown", type=click.Choice(["markdown", "json", "html"]), help="Report format")
@click.pass_context
def report(ctx: click.Context, target: str, author: str, fmt: str) -> None:
    """Generate a bug bounty report for a target."""
    from deephunter.agents.workflows.report_gen import ReportGenerationWorkflow
    sample_findings = [
        {"title": "Discovery Report", "severity": "info", "endpoint": target,
         "description": f"Automated reconnaissance and scanning report for {target}",
         "evidence": "Generated by DeepHunter CLI", "remediation": "Review findings and patch vulnerabilities"},
    ]
    workflow = ReportGenerationWorkflow()
    with console.status("[bold green]Generating report...") as status:
        result = workflow.execute({
            "target": target, "author": author, "format": fmt,
            "findings": sample_findings,
            "summary": {"total": 1, "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 1}},
        })
    if result.success:
        output = result.data["report"]
        ext = {"markdown": "md", "json": "json", "html": "html"}[fmt]
        path = f"report_{target.replace('://', '_').replace('/', '_')}.{ext}"
        Path(path).write_text(output)
        console.print(f"[green]Report written to {path}[/green]")
    else:
        console.print(f"[red]Report generation failed: {result.error}[/red]")


if __name__ == "__main__":
    cli()
