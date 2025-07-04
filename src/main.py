import typer
from rich.console import Console
from rich.table import Table
import pandas as pd
import paramiko
import winrm
import keyring
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import os

# Adjusting path to import from sibling directories
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from agents import agent_data_ingestion
from db import db_manager

# --- Constants ---
CONNECTION_TIMEOUT = 15 # in seconds

# Initialize Rich Console for beautiful output
console = Console()

# Create a Typer application
app = typer.Typer()

def discover_host(host_info):
    """
    Worker function executed by each thread. Connects to a single host,
    performs discovery, and returns the collected data.

    Args:
        host_info (pd.Series): A series containing info for one host
                               (ip, os_type, user).

    Returns:
        dict: A dictionary containing the host's IP and the discovered data,
              or an error message.
    """
    ip = host_info['ip']
    os_type = host_info['os_type'].lower()
    user = host_info['user']
    result = {"ip": ip, "status": "Failed", "data": None}

    console.log(f"Starting discovery for [bold cyan]{ip}[/bold cyan] ({os_type})...")

    password = keyring.get_password("ai-migration-tool", user)
    if not password:
        result["data"] = f"Password for user '{user}' not found in keyring."
        console.log(f"[bold red]Error for {ip}:[/bold red] {result['data']}")
        return result

    try:
        if os_type == 'linux':
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            # Use the centralized timeout constant
            ssh_client.connect(ip, username=user, password=password, timeout=CONNECTION_TIMEOUT)
            
            # Pass username for better logging in the agent
            hw_data = agent_data_ingestion.discover_linux_hw(ssh_client, user)
            sw_data = agent_data_ingestion.discover_linux_sw(ssh_client)
            
            ssh_client.close()
            
            result["data"] = {**hw_data, **sw_data}
            result["status"] = "Success"

        elif os_type == 'windows':
            win_session = winrm.Protocol(
                endpoint=f"http://{ip}:5985/wsman",
                transport='ntlm',
                username=user,
                password=password,
                server_cert_validation='ignore',
                # Use the centralized timeout constant
                read_timeout_sec=CONNECTION_TIMEOUT
            )
            
            hw_data = agent_data_ingestion.discover_windows_hw(win_session)
            sw_data = agent_data_ingestion.discover_windows_sw(win_session)
            
            result["data"] = {**hw_data, **sw_data}
            result["status"] = "Success"

        else:
            result["data"] = f"Unsupported OS type: {os_type}"

    except Exception as e:
        result["data"] = str(e)
        console.log(f"[bold red]Failed discovery for {ip}:[/bold red] {e}")

    return result

@app.command()
def discover(
    inventory_file: str = typer.Option("inventory.csv", "--inventory", "-i", help="Path to the inventory CSV file."),
    max_workers: int = typer.Option(10, "--workers", "-w", help="Number of concurrent discovery workers.")
):
    """
    Initiates the discovery process for all hosts listed in the inventory file.
    """
    console.rule("[bold green]Starting AI-Powered Migration Assessment Discovery[/bold green]")

    conn = db_manager.create_connection()
    if conn is None:
        console.print("[bold red]Fatal: Could not create or connect to the database. Exiting.[/bold red]")
        raise typer.Exit(code=1)
    db_manager.create_tables(conn)

    try:
        inventory = pd.read_csv(inventory_file)
        console.print(f"Loaded [bold]{len(inventory)}[/bold] hosts from '{inventory_file}'.")
    except FileNotFoundError:
        console.print(f"[bold red]Error: Inventory file not found at '{inventory_file}'.[/bold red]")
        raise typer.Exit(code=1)

    all_results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_host = {executor.submit(discover_host, row): row for index, row in inventory.iterrows()}
        
        for future in as_completed(future_to_host):
            host_info = future_to_host[future]
            try:
                res = future.result()
                all_results.append(res)
                
                if res['status'] == 'Success':
                    console.log(f"[green]Successfully discovered {res['ip']}.[/green] Persisting to DB...")
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
                    server_id = db_manager.add_server(conn, server_tuple)
                    
                    if 'running_processes' in data and server_id:
                        for proc in data['running_processes']:
                            app_tuple = (
                                server_id,
                                proc.get('process_name'),
                                proc.get('pid'),
                                proc.get('user'),
                                str(proc.get('state'))
                            )
                            db_manager.add_application_process(conn, app_tuple)
                else:
                    console.log(f"[red]Failed discovery for {res['ip']}.[/red]")

            except Exception as e:
                console.print(f"[bold red]An error occurred processing host {host_info['ip']}: {e}[/bold red]")

    console.rule("[bold blue]Discovery Summary[/bold blue]")
    summary_table = Table(show_header=True, header_style="bold magenta")
    summary_table.add_column("IP Address", style="cyan")
    summary_table.add_column("Status", style="green")
    summary_table.add_column("Details")

    for res in all_results:
        status_style = "green" if res['status'] == 'Success' else "red"
        details = "Discovery successful" if res['status'] == 'Success' else str(res['data'])
        summary_table.add_row(res['ip'], f"[{status_style}]{res['status']}[/{status_style}]", details)
    
    console.print(summary_table)

    if conn:
        conn.close()
        console.print("[*] Database connection closed.")


if __name__ == "__main__":
    app()