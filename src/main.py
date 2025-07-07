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

import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from agents import agent_data_ingestion, agent_profiling
from db import db_manager, neo4j_manager

CONNECTION_TIMEOUT = 15
KNOWLEDGE_BASE_FILE = "knowledge_base.yaml"

console = Console()
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

def discover_host(host_info: pd.Series, perf_duration_minutes: int, interval_seconds: int, config_targets: Dict):
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
        result["data"] = f"Password for user '{user}' not found in keyring."
        return result
    try:
        if os_type == 'linux':
            ssh_client = agent_data_ingestion.paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(agent_data_ingestion.paramiko.AutoAddPolicy())
            ssh_client.connect(ip, username=user, password=password, timeout=CONNECTION_TIMEOUT)
            data, perf_data = agent_data_ingestion.get_all_linux_data(ssh_client, user, perf_duration_minutes, interval_seconds, config_targets)
            ssh_client.close()
            result["data"], result["perf_data"], result["status"] = data, perf_data, "Success"
        elif os_type == 'windows':
            win_session = agent_data_ingestion.winrm.Protocol(endpoint=f"http://{ip}:5985/wsman", transport='ntlm', username=user, password=password, server_cert_validation='ignore', read_timeout_sec=CONNECTION_TIMEOUT + 10)
            data, perf_data = agent_data_ingestion.get_all_windows_data(win_session, perf_duration_minutes, interval_seconds, config_targets)
            result["data"], result["perf_data"], result["status"] = data, perf_data, "Success"
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

    try:
        inventory = pd.read_csv(inventory_file)
        console.print(f"Loaded [bold]{len(inventory)}[/bold] hosts from '{inventory_file}'.")
    except FileNotFoundError:
        console.print(f"[bold red]Error: Inventory file not found at '{inventory_file}'.[/bold red]"); raise typer.Exit(code=1)

    knowledge_base = load_knowledge_base()
    config_targets = knowledge_base.get('config_files', [])

    all_results = []
    progress_columns = [SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), TimeRemainingColumn()]
    with Progress(*progress_columns, console=console) as progress:
        inventory_task = progress.add_task("[green]Discovering hosts...", total=len(inventory))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_host = {executor.submit(discover_host, row, perf_duration_minutes, interval_seconds, config_targets): row for _, row in inventory.iterrows()}
            for future in as_completed(future_to_host):
                res = future.result()
                all_results.append(res)
                progress.update(inventory_task, advance=1)
                if res['status'] != 'Success':
                    console.print(f"\n[bold red]Discovery failed for {res['ip']}:[/bold red] {res['data']}")

    console.rule("[bold blue]Phase 1.5: Persisting Data[/bold blue]")
    conn = db_manager.create_connection()
    if conn is None: raise typer.Exit(code=1)
    db_manager.create_tables(conn)

    successful_hosts = [res for res in all_results if res['status'] == 'Success']
    servers_to_add = [(res['data'].get('hostname', res['ip']), res['ip'], res['data'].get('os_name'), res['data'].get('os_version'), res['data'].get('cpu_cores'), res['data'].get('total_memory_gb'), datetime.now().strftime("%Y-%m-%d %H:%M:%S")) for res in successful_hosts]
    db_manager.add_servers_bulk(conn, servers_to_add)
    
    server_id_map = db_manager.get_server_ips_to_ids(conn)

    for res in successful_hosts:
        server_id = server_id_map.get(res['ip'])
        if not server_id: continue
        
        db_manager.clear_snapshot_data_for_server(conn, server_id)
        
        data = res.get('data', {})
        apps_to_add = [(server_id, p.get('process_name'), p.get('pid'), p.get('user'), str(p.get('state')), p.get('command_line')) for p in data.get('running_processes', [])]
        connections_to_add = [(server_id, c['destination_ip'], c['destination_port'], c['state'], c['process_name'], c['process_pid']) for c in data.get('network_connections', [])]
        software_to_add = [(server_id, s.get('name'), s.get('version'), s.get('vendor')) for s in data.get('installed_software', [])]
        mounts_to_add = [(server_id, m.get('source'), m.get('mount_point'), m.get('filesystem_type'), m.get('storage_type'), m.get('total_gb'), m.get('used_gb')) for m in data.get('storage_mounts', [])]
        configs_to_add = [(server_id, f.get('file_path'), f.get('content')) for f in data.get('config_files', [])]
        tasks_to_add = [(server_id, t.get('name'), t.get('command'), t.get('schedule'), t.get('enabled')) for t in data.get('scheduled_tasks', [])]
        
        db_manager.add_applications_bulk(conn, apps_to_add)
        db_manager.add_network_connections_bulk(conn, connections_to_add)
        db_manager.add_installed_software_bulk(conn, software_to_add)
        db_manager.add_storage_mounts_bulk(conn, mounts_to_add)
        db_manager.add_config_files_bulk(conn, configs_to_add)
        db_manager.add_scheduled_tasks_bulk(conn, tasks_to_add)

        if res.get('perf_data'):
            metrics_to_add = [(server_id, m['metric_name'], m['value'], m['timestamp']) for m in res['perf_data']]
            db_manager.add_performance_metrics_bulk(conn, metrics_to_add)

    console.rule("[bold cyan]Phase 2: Data Correlation & Analysis[/bold cyan]")
    agent_profiling.correlate_data(conn)
    
    dependency_graph = agent_profiling.build_dependency_graph(conn)
    resolved_graph = agent_profiling.resolve_service_names(dependency_graph)
    application_clusters = agent_profiling.find_application_clusters(resolved_graph)
    
    cluster_table = Table(show_header=True, header_style="bold magenta", title="Discovered Application Clusters")
    cluster_table.add_column("Cluster ID", style="cyan", width=12)
    cluster_table.add_column("Member Servers (IP Addresses)")
    if not application_clusters: cluster_table.add_row("N/A", "No distinct application clusters were identified.")
    else:
        for i, (cluster_id, members) in enumerate(application_clusters.items()):
            cluster_table.add_row(f"Cluster-{i+1}", ", ".join(sorted(members)))
    console.print(cluster_table)

    external_endpoints = agent_profiling.get_external_endpoints(resolved_graph)
    external_table = Table(show_header=True, header_style="bold magenta", title="Discovered External Endpoints")
    external_table.add_column("External Endpoint (IP:Port)", style="yellow")
    external_table.add_column("Service Name")
    external_table.add_column("Connected Internal Servers")
    if not external_endpoints: external_table.add_row("N/A", "N/A", "No external service connections were identified.")
    else:
        for endpoint, data in sorted(external_endpoints.items()):
            service_name = data.get('service_name', 'unknown')
            external_table.add_row(endpoint, service_name, ", ".join(sorted(data['connected_servers'])))
    console.print(external_table)

    console.rule("[bold blue]Phase 2.1: Deep Discovery Summary[/bold blue]")
    
    # --- Performance Summary Report ---
    if perf_duration_minutes > 0:
        perf_summary_table = Table(show_header=True, header_style="bold magenta", title="Performance Baseline Summary")
        perf_summary_table.add_column("Server IP", style="cyan")
        perf_summary_table.add_column("Metric Category", style="green")
        perf_summary_table.add_column("Avg Utilization")
        perf_summary_table.add_column("Max Utilization")
        
        cursor = conn.cursor()
        # This query now groups metrics into categories and calculates AVG/MAX
        query = """
        SELECT
            s.ip_address,
            CASE
                WHEN p.metric_name LIKE '%cpu_percent_utilization%' THEN 'CPU Utilization (%)'
                WHEN p.metric_name LIKE '%memory_percent_used%' THEN 'Memory Utilization (%)'
                WHEN p.metric_name LIKE '%disk_iops%' THEN 'Disk IOPS (Total)'
                WHEN p.metric_name LIKE '%network_throughput%' THEN 'Network Throughput (Mbps)'
                ELSE 'Other'
            END as metric_category,
            AVG(p.metric_value),
            MAX(p.metric_value)
        FROM performance_metrics p
        JOIN servers s ON p.server_id = s.id
        GROUP BY s.ip_address, metric_category
        HAVING metric_category != 'Other'
        ORDER BY s.ip_address, metric_category;
        """
        cursor.execute(query)
        perf_rows = cursor.fetchall()
        if not perf_rows:
            perf_summary_table.add_row("N/A", "No performance metrics were collected.", "N/A", "N/A")
        else:
            for row in perf_rows:
                perf_summary_table.add_row(str(row[0]), str(row[1]), f"{row[2]:.2f}", f"{row[3]:.2f}")
        console.print(perf_summary_table)
    
    storage_table = Table(show_header=True, header_style="bold magenta", title="Discovered Storage Mounts")
    storage_table.add_column("Server IP", style="cyan")
    storage_table.add_column("Mount Point")
    storage_table.add_column("Type", style="yellow")
    storage_table.add_column("Filesystem")
    storage_table.add_column("Total Size (GB)")
    storage_table.add_column("Used (GB)")
    
    cursor = conn.cursor()
    cursor.execute("SELECT s.ip_address, sm.mount_point, sm.storage_type, sm.filesystem_type, sm.total_gb, sm.used_gb FROM storage_mounts sm JOIN servers s ON sm.server_id = s.id ORDER BY s.ip_address, sm.mount_point")
    storage_rows = cursor.fetchall()
    if not storage_rows: storage_table.add_row("N/A", "No storage mounts discovered.", "", "", "", "")
    else:
        for row in storage_rows:
            storage_table.add_row(str(row[0]), str(row[1]), str(row[2]), str(row[3]), f"{row[4]:.2f}", f"{row[5]:.2f}")
    console.print(storage_table)

    software_table = Table(show_header=True, header_style="bold magenta", title="Installed Software Summary")
    software_table.add_column("Server IP", style="cyan")
    software_table.add_column("Total Packages Found")
    
    cursor.execute("SELECT s.ip_address, COUNT(sw.id) FROM installed_software sw JOIN servers s ON sw.server_id = s.id GROUP BY s.ip_address ORDER BY s.ip_address")
    software_rows = cursor.fetchall()
    if not software_rows: software_table.add_row("N/A", "No installed software discovered.")
    else:
        for row in software_rows:
            software_table.add_row(str(row[0]), str(row[1]))
    console.print(software_table)
    
    if conn:
        conn.close()
        console.print("\n[*] Analysis complete. Connection closed.")
    
    if export_to_neo4j:
        console.rule("[bold magenta]Phase 2.5: Exporting to Neo4j[/bold magenta]")
        if resolved_graph.number_of_nodes() > 0:
            neo4j_driver = None
            try:
                neo4j_driver = neo4j_manager.get_neo4j_driver()
                if neo4j_driver: agent_profiling.export_graph_to_neo4j(resolved_graph, neo4j_driver)
            finally:
                if neo4j_driver: neo4j_manager.close_driver(neo4j_driver)
        else:
            console.print("[yellow]Skipping Neo4j export: No dependency graph was built.[/yellow]")

    console.rule("[bold green]Assessment Complete[/bold green]")

if __name__ == "__main__":
    app()