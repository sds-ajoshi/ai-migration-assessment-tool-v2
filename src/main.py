# src/main.py

import typer
from rich.console import Console
from rich.table import Table
import logging
from pathlib import Path

# The following imports assume the project structure where 'src' is the root
# for the execution context, or the path is correctly configured.
from agents.agent_data_ingestion import DataIngestionAgent
from agents.agent_profiling import ProfilingAgent
from db.db_manager import DBManager
from db.neo4j_manager import get_neo4j_manager_from_env

# Configure logging to show messages from our agents
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - [%(module)s] - %(message)s'
)

# Initialize Typer app and Rich console
app = typer.Typer()
console = Console()

@app.command()
def discover(
    inventory_file: Path = typer.Option(
        "inventory.csv", 
        "--inventory", 
        "-i", 
        help="Path to the inventory CSV file.",
    ),
    db_file: str = typer.Option(
        "assessment_history.db", 
        "--dbfile", 
        "-db", 
        help="Path to the SQLite database file."
    ),
    workers: int = typer.Option(
        10, 
        "--workers", 
        "-w", 
        help="Number of concurrent workers for discovery."
    ),
    export_to_neo4j: bool = typer.Option(
        False, 
        "--export-to-neo4j", 
        help="Flag to export the final graph to Neo4j."
    ),
    fingerprint_services: bool = typer.Option(
        False,
        "--fingerprint-services",
        help="Actively fingerprint external services using Nmap (requires Nmap to be installed)."
    )
):
    """
    Discover infrastructure, build a dependency graph, and run analysis.
    """
    console.rule("[bold green]AI-Powered Migration Assessment Tool[/bold green]")

    if not inventory_file.is_file():
        console.print(f"[bold red]Error: Inventory file not found at '{inventory_file}'[/bold red]")
        raise typer.Exit(code=1)

    # --- Phase 1: Data Ingestion ---
    console.log(f"Using database file: [yellow]{db_file}[/yellow]")
    db_manager = DBManager(db_file)
    db_manager.create_tables()

    console.log(f"Starting data ingestion from inventory '[cyan]{inventory_file.name}[/cyan]' with {workers} workers...")
    ingestion_agent = DataIngestionAgent(str(inventory_file), db_manager, max_workers=workers)
    ingestion_agent.run_discovery()
    console.log("[bold green]Data ingestion complete.[/bold green]")

    # --- Phase 2: Profiling, Graphing, and Correlation ---
    console.rule("[bold blue]Phase 2: Analysis and Digital Twin Construction[/bold blue]")
    profiling_agent = ProfilingAgent(db_manager)

    console.log("Building base dependency graph...")
    graph = profiling_agent.build_dependency_graph()
    if not graph or graph.number_of_nodes() == 0:
        console.print("[bold red]Error: Failed to build dependency graph or graph is empty. Aborting.[/bold red]")
        db_manager.close()
        raise typer.Exit(code=1)
    console.log(f"Base dependency graph built successfully with {graph.number_of_nodes()} nodes and {graph.number_of_edges()} edges.")

    console.log("[bold magenta]Correlating and enriching graph to create Digital Twin...[/bold magenta]")
    profiling_agent.correlate_and_enrich_graph()
    console.log("[bold green]Digital Twin enrichment complete.[/bold green]")
    
    console.log("Finding application clusters from enriched graph...")
    clusters = profiling_agent.find_application_clusters()
    if clusters:
        console.log(f"Discovered {len(clusters)} application clusters.")
    else:
        console.log("No distinct application clusters found.")

    console.log("Identifying external dependencies...")
    external_deps = profiling_agent.get_external_dependencies()

    if fingerprint_services and external_deps:
        console.log("[bold yellow]Actively fingerprinting external services with Nmap...[/bold yellow]")
        # This assumes a method `fingerprint_external_services` exists on the agent
        # that takes the list of deps and returns an updated map.
        external_deps = profiling_agent.fingerprint_external_services(external_deps)
        console.log("[bold green]Service fingerprinting complete.[/bold green]")

    # --- Reporting ---
    console.rule("[bold cyan]Assessment Summary Report[/bold cyan]")
    
    if external_deps:
        deps_table = Table(title="Discovered External Endpoints")
        deps_table.add_column("Endpoint (IP:Port)", style="yellow")
        deps_table.add_column("Fingerprinted Service", style="blue")
        for dep, details in external_deps.items():
            service_name = details.get('name', 'unknown')
            version = details.get('version', '')
            deps_table.add_row(dep, f"{service_name} {version}".strip())
        console.print(deps_table)
    else:
        console.print("[green]No external dependencies found.[/green]")

    if clusters:
        console.rule("[bold purple]Application Cluster Deep Dive[/bold purple]")
        for i, cluster in enumerate(clusters):
            cluster_name = f"Cluster-{i+1}"
            cluster_table = Table(title=f"Details for {cluster_name}", show_lines=True)
            cluster_table.add_column("Process", style="cyan", min_width=20)
            cluster_table.add_column("Software Package", style="green", min_width=20)
            cluster_table.add_column("Used Config File(s)", style="yellow")
            cluster_table.add_column("Used Storage Mount(s)", style="magenta")

            for process_id in sorted(cluster):
                process_attrs = graph.nodes[process_id]
                process_label = process_attrs.get('label', process_id)
                software, configs, storage = profiling_agent.get_correlated_details(process_id)
                configs_str = "\n".join(configs) if configs else "N/A"
                storage_str = "\n".join(storage) if storage else "N/A"
                cluster_table.add_row(process_label, software, configs_str, storage_str)
            console.print(cluster_table)

    # --- Phase 3: Export to Neo4j (Optional) ---
    if export_to_neo4j:
        console.rule("[bold magenta]Phase 3: Exporting to Neo4j[/bold magenta]")
        console.log("Attempting to export the enriched graph to Neo4j...")
        neo4j_manager = get_neo4j_manager_from_env()
        if neo4j_manager and neo4j_manager.driver:
            try:
                neo4j_manager.export_graph_to_neo4j(profiling_agent.graph)
                console.log("[bold green]Graph successfully exported to Neo4j.[/bold green]")
            except Exception as e:
                console.print(f"[bold red]Failed to export graph to Neo4j. Error: {e}[/bold red]")
            finally:
                neo4j_manager.close()
        else:
            console.print("[bold red]Cannot export to Neo4j. Ensure NEO4J_PASSWORD is set and the service is running.[/bold red]")

    db_manager.close()
    console.rule("[bold green]Assessment Complete[/bold green]")

if __name__ == "__main__":
    app()