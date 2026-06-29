"""DeepHunter CLI — main entry point.

Uses Click for command parsing and Rich for formatted output.
"""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console
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
@click.argument("directories", nargs=-1, type=click.Path(exists=True))
@click.pass_context
def ingest(ctx: click.Context, directories: tuple[str, ...]) -> None:
    """Ingest knowledge documents into the store.

    Scans the given directories (or the configured data directory)
    for supported document files, parses them, and stores them as SKOs.
    """
    config: DeepHunterConfig = ctx.obj["config"]
    store: KnowledgeStore = ctx.obj["store"]

    pipeline = IngestionPipeline(config, store)
    dirs = list(directories) if directories else None
    results = pipeline.run(directories=dirs)

    table = Table(title="Ingestion Results")
    table.add_column("Metric", style="cyan")
    table.add_column("Count", style="green")

    table.add_row("Total files found", str(results["total"]))
    table.add_row("Successfully parsed", str(results["parsed"]))
    table.add_row("Stored as SKOs", str(results["stored"]))
    table.add_row("Skipped", str(results["skipped"]))

    console.print(table)


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
        # Try prefix match
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


if __name__ == "__main__":
    cli()
