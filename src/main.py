# src/main.py

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))
import typer
from rich.console import Console
from rich.panel import Panel
from src.orchestrator.pipeline import PipelineOrchestrator
from src.config.loader import ConfigLoader
from src.logging.logger import setup_logging

app = typer.Typer()
console = Console()

@app.command()
def ingest(
    input_inventory_file: str = typer.Option("inventory.csv", help="Path to CSV file containing host inventory"),
    output_db: str = typer.Option("data/assessment_history.db", help="Path to SQLite database file"),
    max_workers: int = typer.Option(10, help="Number of concurrent workers for data ingestion"),
    dry_run: bool = typer.Option(False, help="Run without making changes to database or Neo4j"),
    verbose: bool = typer.Option(False, help="Enable verbose logging")
):
    """Run the ingestion phase only."""
    setup_logging(verbose=verbose)
    config = ConfigLoader().load()
    orchestrator = PipelineOrchestrator(config, output_db, input_inventory_file, dry_run, max_workers)
    orchestrator.run_ingestion()
    console.print(Panel("Ingestion complete.", title="[bold green]Success[/bold green]"))

@app.command()
def correlate(
    output_db: str = typer.Option("data/assessment_history.db", help="Path to SQLite database file"),
    dry_run: bool = typer.Option(False, help="Run without making changes to database or Neo4j"),
    verbose: bool = typer.Option(False, help="Enable verbose logging")
):
    """Run the correlation phase only."""
    setup_logging(verbose=verbose)
    config = ConfigLoader().load()
    orchestrator = PipelineOrchestrator(config, output_db, dry_run=dry_run)
    orchestrator.run_correlation()
    console.print(Panel("Correlation complete.", title="[bold green]Success[/bold green]"))

@app.command()
def export(
    output_db: str = typer.Option("data/assessment_history.db", help="Path to SQLite database file"),
    export_graph: str = typer.Option(None, help="Export correlation graph to specified .graphml file"),
    dry_run: bool = typer.Option(False, help="Run without making changes to database or Neo4j"),
    verbose: bool = typer.Option(False, help="Enable verbose logging")
):
    """Run the export phase only."""
    setup_logging(verbose=verbose)
    config = ConfigLoader().load()
    orchestrator = PipelineOrchestrator(config, output_db, dry_run=dry_run)
    orchestrator.run_export(export_graph)
    console.print(Panel("Export complete.", title="[bold green]Success[/bold green]"))

@app.command()
def full_pipeline(
    input_inventory_file: str = typer.Option("inventory.csv", help="Path to CSV file containing host inventory"),
    output_db: str = typer.Option("data/assessment_history.db", help="Path to SQLite database file"),
    config: str = typer.Option("knowledge_base.yaml", help="Path to configuration YAML file"),
    dry_run: bool = typer.Option(False, help="Run without making changes to database or Neo4j"),
    debug: bool = typer.Option(False, help="Enable debug logging"),
    max_workers: int = typer.Option(10, help="Number of concurrent workers for data ingestion"),
    export_graph: str = typer.Option(None, help="Export correlation graph to specified .graphml file"),
    verbose: bool = typer.Option(False, help="Enable verbose logging"),
    summary: bool = typer.Option(False, help="Output a summary table after ingestion")
):
    """Run the full pipeline: ingest, correlate, export."""
    setup_logging(verbose=verbose or debug)
    config_loader = ConfigLoader(config_path=config)
    config = config_loader.load()
    orchestrator = PipelineOrchestrator(config, output_db, input_inventory_file, dry_run, max_workers)
    orchestrator.run_full_pipeline(export_graph, summary)
    console.print(Panel("Full pipeline complete.", title="[bold green]Success[/bold green]"))

if __name__ == "__main__":
    app()