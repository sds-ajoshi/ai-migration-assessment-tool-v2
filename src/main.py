# src/main.py

import typer
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from pathlib import Path
import logging

from agents.agent_data_ingestion import DataIngestionAgent
from agents.agent_profiling import ProfilingAgent
from db.db_manager import DBManager
from db.neo4j_manager import Neo4jManager

# Suppress noisy logs from third-party libraries
logging.getLogger("paramiko").setLevel(logging.WARNING)
logging.getLogger("winrm").setLevel(logging.WARNING)

console = Console()

app = typer.Typer(
    name="ai-migration-assessment-tool",
    help="""
    An AI-Powered Migration Assessment Tool that discovers your IT landscape,
    builds a Digital Twin, and provides intelligent migration recommendations.
    """,
    no_args_is_help=True,
    rich_markup_mode="rich"
)

# A helper function to load the knowledge base
def _load_knowledge_base():
    try:
        with open("knowledge_base.yaml", 'r') as f:
            return yaml.safe_load(f)
    except (FileNotFoundError, yaml.YAMLError):
        return {}

@app.command(
    name="ingest",
    help="""
    [bold green]Phase 1:[/bold green] Ingests data from servers listed in the inventory file.
    Connects to hosts, gathers system information, and persists it to a local SQLite database.
    """
)
def ingest(
    inventory_file: Path = typer.Option("inventory.csv", "--inventory-file", "-i", help="Path to the inventory CSV file."),
    workers: int = typer.Option(10, "--workers", "-w", help="Number of concurrent workers for discovery."),
    db_file: str = typer.Option("assessment_history.db", "--db-file", help="Path to the SQLite database file.")
):
    console.print(Panel("Phase 1: Starting Data Ingestion", title="[bold cyan]AI-Powered Migration Assessment Tool[/bold cyan]", expand=False))
    console.log(f"Using database file: {db_file}")

    if not inventory_file.exists():
        console.print(f"[bold red]Error: Inventory file not found at '{inventory_file}'.[/bold red]")
        raise typer.Exit(code=1)

    db_manager = DBManager(db_file)
    ingestion_agent = DataIngestionAgent(inventory_path=inventory_file, db_manager=db_manager, max_workers=workers)
    
    ingestion_agent.run_discovery()
    
    console.log("Data ingestion complete.")
    db_manager.close()

@app.command(
    name="profile",
    help="""
    [bold green]Phase 2:[/bold green] Analyzes collected data to build the Digital Twin and find application clusters.
    """
)
def profile(
    db_file: str = typer.Option("assessment_history.db", "--db-file", help="Path to the SQLite database file."),
    export_to_neo4j: bool = typer.Option(False, "--export-to-neo4j", help="Export the final dependency graph to Neo4j."),
    fingerprint_services: bool = typer.Option(False, "--fingerprint-services", help="Attempt to fingerprint external services using nmap (requires nmap to be installed).")
):
    console.rule("[bold cyan]Phase 2: Analysis and Digital Twin Construction[/bold cyan]")
    db_manager = DBManager(db_file)
    
    # *** THIS IS THE FINAL FIX ***
    # This block correctly calls the new, refactored methods on the ProfilingAgent
    
    # 1. Initialize the agent, which builds the base graph of servers and processes
    profiling_agent = ProfilingAgent(db_manager)
    console.log(f"Base dependency graph built successfully with {profiling_agent.graph.number_of_nodes()} nodes and {profiling_agent.graph.number_of_edges()} edges.")
    
    # 2. Enrich the graph with correlations (software, files, storage)
    console.log("Correlating and enriching graph to create Digital Twin...")
    profiling_agent.enrich_and_correlate()
    console.log("Digital Twin enrichment complete.")

    # 3. Find and report application clusters from the enriched graph
    console.log("Finding application clusters from enriched graph...")
    profiling_agent.find_and_report_clusters()

    # 4. Identify and report external dependencies
    if fingerprint_services:
        console.log("Identifying and fingerprinting external dependencies...")
        profiling_agent.identify_external_dependencies()
    
    # 5. Optionally, export the final graph to Neo4j
    if export_to_neo4j:
        console.rule("[bold blue]Exporting to Neo4j[/bold blue]")
        knowledge_base = _load_knowledge_base()
        neo4j_config = knowledge_base.get('neo4j')
        
        # *** THIS IS THE FIX ***
        # Check if the Neo4j configuration exists before trying to connect.
        if not neo4j_config:
            console.print("[bold red]Error: 'neo4j' configuration not found in knowledge_base.yaml.[/bold red]")
        else:
            try:
                # Pass the credentials to the Neo4jManager
                neo4j_manager = Neo4jManager(
                    uri=neo4j_config.get('uri'),
                    user=neo4j_config.get('user'),
                    password=neo4j_config.get('password')
                )
                neo4j_manager.export_graph(db_manager)
                neo4j_manager.close()
                console.print("[green]Successfully exported graph to Neo4j.[/green]")
            except Exception as e:
                console.print(f"[bold red]Failed to export to Neo4j: {e}[/bold red]")
                console.print("Please ensure Neo4j is running and credentials in 'knowledge_base.yaml' are correct.")

    db_manager.close()

if __name__ == "__main__":
    app()