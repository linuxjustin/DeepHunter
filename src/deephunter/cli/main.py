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


@cli.command("roadmap")
@click.argument("target")
@click.option("--path-name", default="", help="Filter to a specific investigation path name")
@click.option("--min-priority", default=0.0, type=float, help="Minimum priority score (0.0-1.0)")
@click.option("--phase", default="", help="Filter to a specific planning phase")
@click.pass_context
def roadmap(ctx: click.Context, target: str, path_name: str, min_priority: float, phase: str) -> None:
    """Generate and display a detailed investigation roadmap for a target.

    Shows the full investigation plan grouped by phase, with alternative
    investigation paths, manual test guidance, and bug class coverage.

    Use 'deephunter roadmap <target>' to generate a comprehensive roadmap.
    Use 'deephunter plan <target>' for a compact table view.
    """
    from deephunter.reasoning.session import InvestigationSession
    from deephunter.planning import Planner, PlanningPhase

    console.print(f"[bold cyan]Generating investigation roadmap for:[/bold cyan] {target}")

    session = InvestigationSession.new(target)
    planner = Planner()
    result = planner.plan_from_session(session)
    plan = result.plan

    if not plan.steps:
        console.print("[yellow]No investigation steps generated. Add more context.[/yellow]")
        return

    phases_order = list(PlanningPhase)

    if path_name:
        matching = [p for p in plan.alternative_paths if path_name.lower() in p.name.lower()]
        if matching:
            path = matching[0]
            steps = path.steps_in_path(plan.steps)
            console.print(f"\n[bold cyan]📍 Path:[/bold cyan] {path.name}")
            console.print(f"[dim]{path.description}[/dim]")
            console.print(f"[green]Priority:[/green] {path.priority:.2f}  [yellow]Steps:[/yellow] {len(path.step_ids)}")
        else:
            console.print(f"[yellow]No path matching '{path_name}' found. Showing full plan.[/yellow]")
            steps = plan.steps
    else:
        steps = plan.steps

    if min_priority > 0:
        steps = [s for s in steps if s.priority_score >= min_priority]
        console.print(f"[dim]Filtered to steps with priority >= {min_priority}[/dim]")

    if phase:
        try:
            phase_enum = PlanningPhase(phase.lower())
            steps = [s for s in steps if s.phase == phase_enum]
            console.print(f"[dim]Filtered to phase: {phase}[/dim]")
        except ValueError:
            console.print(f"[red]Unknown phase: {phase}[/red]")

    console.print(f"\n[bold]Investigation Roadmap — {target}[/bold]")
    console.print(f"[dim]Total steps: {len(steps)}  |  Est. hours: {sum(s.estimated_cost_hours for s in steps):.1f}  |  Risk: {plan.risk.overall:.1f}/10[/dim]")

    grouped: dict[PlanningPhase, list] = {}
    for step in steps:
        grouped.setdefault(step.phase, []).append(step)

    for phase_enum in phases_order:
        if phase_enum not in grouped:
            continue
        phase_steps = grouped[phase_enum]
        console.print(f"\n[bold cyan]━━ {phase_enum.value.upper()} ({len(phase_steps)} steps)[/bold cyan]")

        for s in phase_steps:
            risk_color = "red" if s.risk.overall >= 7 else "yellow" if s.risk.overall >= 4 else "green"
            icon = "🔴" if s.priority_score >= 0.8 else "🟡" if s.priority_score >= 0.6 else "🟢"

            console.print(f"  {icon} [{s.priority_score:.2f}] {s.title[:70]}")
            if s.description and s.description != s.title:
                for line in s.description[:120].split("\n"):
                    console.print(f"     [dim]{line.strip()}[/dim]")

            if s.recommended_tests:
                console.print(f"     [magenta]🧪 Manual test:[/magenta] {s.recommended_tests[0].description[:80]}")
                if s.recommended_tests[0].procedure:
                    proc_lines = s.recommended_tests[0].procedure.split("\n")[:2]
                    for pl in proc_lines:
                        console.print(f"       [dim]→ {pl.strip()}[/dim]")

            if s.bug_classes:
                console.print(f"     [red]Bug classes:[/red] {', '.join(s.bug_classes)}")
            console.print(f"     Risk: [{risk_color}]{s.risk.overall:.1f}[/{risk_color}]  Est: {s.estimated_cost_hours}h  Complex: {s.complexity:.1f}")

    if plan.alternative_paths:
        console.print(f"\n[bold cyan]━━ ALTERNATIVE PATHS ({len(plan.alternative_paths)})[/bold cyan]")
        for ap in plan.alternative_paths:
            console.print(f"  [bold]{ap.name}[/bold]  (priority: {ap.priority:.2f})")
            if ap.description:
                console.print(f"    {ap.description[:100]}")
            console.print(f"    Phases: {', '.join(p.value for p in ap.phases[:4])}  |  Steps: {len(ap.step_ids)}  |  Recommended by: {', '.join(ap.recommended_by)}")

    console.print(f"\n[dim]Plan ID: {plan.id}  |  Phases covered: {len(plan.phases_covered)}/{len(phases_order)}[/dim]")


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


# ── Investigation Workflow CLI ─────────────────────────────────────────────


@cli.group()
def investigate() -> None:
    """End-to-end investigation workflow orchestration.

    Creates, manages, and runs full investigation sessions that
    coordinate all DeepHunter subsystems.
    """


@investigate.command()
@click.argument("target")
@click.option("--name", "-n", help="Investigation name")
@click.option("--tech", "-t", multiple=True, help="Identified technologies")
@click.option("--workflow", "-w", default="web_app_review", help="Workflow name to execute")
@click.option("--auto-approve", is_flag=True, help="Auto-approve all approval steps")
@click.option("--output", "-o", default="investigation_report.md", help="Report output path")
def run(target: str, name: str | None, tech: tuple[str, ...], workflow: str, auto_approve: bool, output: str) -> None:
    """Run a complete investigation workflow against a target."""
    from deephunter.investigation.orchestrator import InvestigationOrchestrator
    orch = InvestigationOrchestrator()

    tech_list = list(tech) if tech else []
    state = orch.create_session(target, name=name or "", technologies=tech_list)
    console.print(f"[green]Created investigation session: {state.session_id}[/green]")

    try:
        wf = orch.load_workflow_by_name(workflow)
        console.print(f"[bold]Running workflow:[/bold] {wf.name}")
    except FileNotFoundError:
        console.print(f"[yellow]Workflow '{workflow}' not found, using default workflow.[/yellow]")
        from deephunter.investigation.models import WorkflowStepDefinition, WorkflowDefinition, WorkflowStepType
        wf = WorkflowDefinition(
            name="default",
            steps=[
                WorkflowStepDefinition(id="scope", step_type=WorkflowStepType.BUILTIN, action="load_scope"),
                WorkflowStepDefinition(id="plan", step_type=WorkflowStepType.BUILTIN, action="generate_plan", depends_on=["scope"]),
                WorkflowStepDefinition(id="report", step_type=WorkflowStepType.BUILTIN, action="draft_report", depends_on=["plan"]),
            ],
        )

    with console.status("[bold green]Executing investigation workflow...") as status:
        result = orch.execute_workflow(state, wf, auto_approve=auto_approve)

    if result.success:
        console.print(f"[green]Workflow completed in {result.total_execution_time_ms:.0f}ms[/green]")
    else:
        failed = [r for r in result.step_results if not r.success]
        for f in failed:
            console.print(f"[red]Step '{f.step_id}' failed: {f.error}[/red]")
        console.print("[yellow]Workflow paused. Resume with checkpoint.[/yellow]")

    report_path = orch.export_report(state, output)
    console.print(f"[green]Report written to {report_path}[/green]")


@investigate.command()
@click.argument("path")
def resume(path: str) -> None:
    """Resume a previously checkpointed investigation."""
    from deephunter.investigation.orchestrator import InvestigationOrchestrator
    orch = InvestigationOrchestrator()
    state, workflow = orch.resume(path)
    console.print(f"[green]Resumed investigation: {state.name or state.target} (status: {state.status.value})[/green]")
    console.print(f"[green]Checkpoint: {len(state.completed_steps)} steps completed[/green]")


@investigate.command()
@click.argument("target")
@click.option("--output", "-o", default="session.json", help="Session output path")
def init(target: str, output: str) -> None:
    """Create a new investigation session."""
    from deephunter.investigation.orchestrator import InvestigationOrchestrator
    orch = InvestigationOrchestrator()
    state = orch.create_session(target)
    orch.save_session(state, output)
    console.print(f"[green]Created session {state.session_id} for {target}[/green]")
    console.print(f"[green]Saved to {output}[/green]")


@investigate.command()
@click.argument("session_path", type=click.Path(exists=True))
def status(session_path: str) -> None:
    """Show the status of a saved investigation session."""
    from deephunter.investigation.orchestrator import InvestigationOrchestrator
    from deephunter.planning.models import TaskStatus
    from deephunter.investigation.models import InvestigationStatus

    orch = InvestigationOrchestrator()
    state, _ = orch.resume(session_path)

    console.print(f"[bold]Investigation:[/bold] {state.name or state.target}")
    console.print(f"[bold]Target:[/bold] {state.target}")
    console.print(f"[bold]Status:[/bold] [{_status_color(state.status)}]{state.status.value}[/]")
    console.print(f"[bold]Session:[/bold] {state.session_id}")

    if state.completed_steps:
        console.print(f"\n[bold green]Completed steps ({len(state.completed_steps)}):[/bold green]")
        for step_id in state.completed_steps:
            console.print(f"  ✅ {step_id}")

    pending_steps = [s for s in (state.workflow.steps if state.workflow else []) if s.id not in state.completed_steps]
    if pending_steps:
        console.print(f"\n[bold yellow]Pending steps ({len(pending_steps)}):[/bold yellow]")
        for step in pending_steps:
            console.print(f"  ⏳ {step.id}")

    if state.tasks:
        task_table = Table(title="Investigation Tasks")
        task_table.add_column("Title")
        task_table.add_column("Priority", style="cyan")
        task_table.add_column("Status", style="magenta")
        for t in state.tasks:
            status_color = _task_status_color(t.status)
            task_table.add_row(t.title, t.priority.name, f"[{status_color}]{t.status.value}[/]")
        console.print(f"\n[bold]Tasks ({len(state.tasks)}):[/bold]")
        console.print(task_table)

    if state.scope.technologies:
        console.print(f"\n[bold]Technologies:[/bold] {', '.join(state.scope.technologies)}")


def _status_color(status: InvestigationStatus) -> str:
    if status == InvestigationStatus.COMPLETED:
        return "green"
    if status == InvestigationStatus.FAILED:
        return "red"
    if status == InvestigationStatus.IN_PROGRESS:
        return "yellow"
    return "cyan"


def _task_status_color(status: TaskStatus) -> str:
    if status == TaskStatus.COMPLETED:
        return "green"
    if status == TaskStatus.FAILED:
        return "red"
    if status == TaskStatus.IN_PROGRESS:
        return "yellow"
    return "cyan"


@investigate.command()
def list_workflows() -> None:
    """List available YAML workflow definitions."""
    from deephunter.investigation.orchestrator import InvestigationOrchestrator
    orch = InvestigationOrchestrator()
    workflows = orch.list_workflows()
    if not workflows:
        console.print("[yellow]No workflows found.[/yellow]")
        return
    table = Table(title="Available Workflows")
    table.add_column("Name", style="cyan")
    table.add_column("Description")
    table.add_column("Path", style="dim")
    for w in workflows:
        table.add_row(w["name"], w["description"][:60], w["path"])
    console.print(table)


if __name__ == "__main__":
    cli()
