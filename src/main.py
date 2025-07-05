import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn
import pandas as pd
import keyring
import yaml
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import os
import time
from typing import List, Dict

# Adjusting path to import from sibling directories
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from agents import agent_data_ingestion, agent_profiling
from db import db_manager, neo4j_manager

# --- Constants ---
CONNECTION_TIMEOUT = 15 # in seconds
KNOWLEDGE_BASE_FILE = "knowledge_base.yaml"

# Initialize Rich Console for beautiful output
console = Console()

# Create a Typer application
app = typer.Typer()

def load_knowledge_base() -> Dict:
    """Loads the YAML knowledge base file."""
    try:
        with open(KNOWLEDGE_BASE_FILE, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        console.print(f"[bold yellow]Warning: Knowledge base file not found at '{KNOWLEDGE_BASE_FILE}'. Using defaults.[/bold yellow]")
        return {}
    except yaml.YAMLError as e:
        console.print(f"[bold red]Error parsing knowledge base file: {e}[/bold red]")
        return {}

def discover_host(host_info: pd.Series, perf_duration_minutes: int, interval_seconds: int, windows_counters: List[str]):
    """
    Worker function executed by each thread. Connects to a single host,
    performs discovery, and returns the collected data.
    """
    ip = host_info['ip']
    os_type = host_info['os_type'].lower()
    user = host_info['user']
    result = {"ip": ip, "status": "Failed", "data": None, "perf_data": []}

    password = keyring.get_password("ai-migration-tool", user)
    if not password:
        result["data"] = f"Password for user '{user}' not found in keyring. Please run setup_credentials.py."
        return result

    try:
        if os_type == 'linux':
            ssh_client = agent_data_ingestion.paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(agent_data_ingestion.paramiko.AutoAddPolicy())
            ssh_client.connect(ip, username=user, password=password, timeout=CONNECTION_TIMEOUT)
            
            data, perf_data = agent_data_ingestion.get_all_linux_data(ssh_client, user, perf_duration_minutes, interval_seconds)
            
            ssh_client.close()
            result["data"] = data
            result["perf_data"] = perf_data
            result["status"] = "Success"

        elif os_type == 'windows':
            win_session = agent_data_ingestion.winrm.Protocol(
                endpoint=f"http://{ip}:5985/wsman", transport='ntlm',
                username=user, password=password, server_cert_validation='ignore',
                read_timeout_sec=CONNECTION_TIMEOUT + 10
            )
            
            data, perf_data = agent_data_ingestion.get_all_windows_data(win_session, perf_duration_minutes, interval_seconds, windows_counters)

            result["data"] = data
            result["perf_data"] = perf_data
            result["status"] = "Success"
        else:
            result["data"] = f"Unsupported OS type: {os_type}"
    except Exception as e:
        result["data"] = str(e)

    return result

@app.command()
def discover(
    inventory_file: str = typer.Option("inventory.csv", "--inventory", "-i", help="Path to the inventory CSV file."),
    max_workers: int = typer.Option(10, "--workers", "-w", help="Number of concurrent discovery workers."),
    perf_duration_minutes: int = typer.Option(0, "--perf-duration", "-p", help="Duration in minutes for performance baselining."),
    interval_seconds: int = typer.Option(60, "--interval", "-s", help="Interval in seconds for performance data collection."),
    export_to_neo4j: bool = typer.Option(False, "--export-to-neo4j", help="Export the final dependency graph to Neo4j.")
):
    """
    Initiates discovery, analysis, and optional graph export.
    """
    console.rule("[bold green]Phase 1: Discovery[/bold green]")

    # --- Discovery Phase Connection ---
    conn_discovery = db_manager.create_connection()
    if conn_discovery is None: raise typer.Exit(code=1)
    db_manager.create_tables(conn_discovery)

    try:
        inventory = pd.read_csv(inventory_file)
        console.print(f"Loaded [bold]{len(inventory)}[/bold] hosts from '{inventory_file}'.")
    except FileNotFoundError:
        console.print(f"[bold red]Error: Inventory file not found at '{inventory_file}'.[/bold red]"); raise typer.Exit(code=1)

    knowledge_base = load_knowledge_base()
    windows_counters = knowledge_base.get('performance_counters', {}).get('windows', [])

    progress_columns = [SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), TimeRemainingColumn()]

    with Progress(*progress_columns, console=console) as progress:
        inventory_task = progress.add_task("[green]Discovering inventory...", total=len(inventory))
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_host = {
                executor.submit(discover_host, row, perf_duration_minutes, interval_seconds, windows_counters): row 
                for _, row in inventory.iterrows()
            }
            
            for future in as_completed(future_to_host):
                res = future.result()
                progress.update(inventory_task, advance=1)
                
                if res['status'] == 'Success':
                    data = res['data']
                    server_tuple = (
                        data.get('hostname', res['ip']),
                        res['ip'],
                        data.get('os_name'),
                        data.get('os_version'),
                        data.get('cpu_cores'),
                        data.get('total_memory_gb'),
                        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    )
                    server_id = db_manager.add_server(conn_discovery, server_tuple)
                    
                    if res.get('data', {}).get('network_connections') and server_id:
                        connections_to_add = [(server_id, c['destination_ip'], c['destination_port'], c['state'], c['process_name'], c['process_pid']) for c in res['data']['network_connections']]
                        db_manager.add_network_connections(conn_discovery, connections_to_add)
                else:
                    console.print(f"\n[bold red]Discovery failed for {res['ip']}:[/bold red] {res['data']}")
    
    if conn_discovery:
        conn_discovery.close()
        console.print("\n[*] Discovery data persisted. Connection closed.")

    console.rule("[bold blue]Phase 2: Dependency Analysis[/bold blue]")
    
    # --- Analysis Phase Connection ---
    console.print("[*] Opening new connection for analysis...")
    conn_analysis = db_manager.create_connection()
    if conn_analysis is None: raise typer.Exit(code=1)

    dependency_graph = agent_profiling.build_dependency_graph(conn_analysis)
    application_clusters = agent_profiling.find_application_clusters(dependency_graph)
    
    cluster_table = Table(show_header=True, header_style="bold magenta", title="Discovered Application Clusters")
    cluster_table.add_column("Cluster ID", style="cyan", width=12)
    cluster_table.add_column("Member Servers (IP Addresses)")

    if not application_clusters:
        cluster_table.add_row("N/A", "No distinct application clusters were identified.")
    else:
        for i, (cluster_id, members) in enumerate(application_clusters.items()):
            members.sort()
            cluster_table.add_row(f"Cluster-{i+1}", ", ".join(members))

    console.print(cluster_table)

    if conn_analysis:
        conn_analysis.close()
        console.print("\n[*] Analysis complete. Connection closed.")
    
    # --- Phase 2.5: Graph Persistence (Refactored with try...finally) ---
    if export_to_neo4j:
        console.rule("[bold magenta]Phase 2.5: Exporting to Neo4j[/bold magenta]")
        if dependency_graph.number_of_nodes() > 0:
            neo4j_driver = None
            try:
                neo4j_driver = neo4j_manager.get_neo4j_driver()
                if neo4j_driver:
                    agent_profiling.export_graph_to_neo4j(dependency_graph, neo4j_driver)
            finally:
                if neo4j_driver:
                    neo4j_manager.close_driver(neo4j_driver)
        else:
            console.print("[yellow]Skipping Neo4j export: No dependency graph was built.[/yellow]")

    console.rule("[bold green]Assessment Complete[/bold green]")

if __name__ == "__main__":
    app()