import pandas as pd
import keyring
from getpass import getpass
from rich.console import Console
from rich.panel import Panel

# Initialize Rich Console
console = Console()

# --- Constants ---
SERVICE_NAME = "ai-migration-tool"
INVENTORY_FILE = "inventory.csv"

def setup_credentials():
    """
    Reads the inventory file, identifies unique users, and securely prompts
    for their passwords to store them in the OS keyring.
    """
    console.print(Panel(
        f"[bold yellow]Credential Setup for '{SERVICE_NAME}'[/bold yellow]\n\nThis script will securely store passwords for users found in '{INVENTORY_FILE}'.",
        title="[bold cyan]Welcome[/bold cyan]",
        border_style="cyan"
    ))

    # --- 1. Read Inventory File ---
    try:
        inventory = pd.read_csv(INVENTORY_FILE)
        # Find unique usernames to avoid asking for the same password multiple times
        unique_users = inventory['user'].unique()
        console.print(f"\n[*] Found {len(unique_users)} unique user(s) in '{INVENTORY_FILE}': [bold magenta]{', '.join(unique_users)}[/bold magenta]")
    except FileNotFoundError:
        console.print(f"\n[bold red]Error: Inventory file not found at '{INVENTORY_FILE}'. Please create it before running this script.[/bold red]")
        return
    except KeyError:
        console.print(f"\n[bold red]Error: The inventory file '{INVENTORY_FILE}' must contain a 'user' column.[/bold red]")
        return
    except Exception as e:
        console.print(f"\n[bold red]An error occurred while reading the inventory file: {e}[/bold red]")
        return

    # --- 2. Loop Through Unique Users and Set Passwords ---
    console.print("\n[*] Please enter the password for each user when prompted.")
    console.print("[dim]Note: Your typing will not be visible for security.[/dim]\n")

    for user in unique_users:
        try:
            # Use getpass for a secure password prompt
            password = getpass(f"  Enter password for user '[bold yellow]{user}[/bold yellow]': ")
            
            # Store the password in the keyring
            keyring.set_password(SERVICE_NAME, user, password)
            
            console.print(f"  [green]✔[/green] Password for user '[bold yellow]{user}[/bold yellow]' has been securely stored.\n")
        except Exception as e:
            console.print(f"\n[bold red]Could not set password for user '{user}'. Error: {e}[/bold red]")
            console.print("[bold red]Please ensure you have the necessary permissions to access the OS credential store.[/bold red]")
            return

    console.print(Panel(
        "[bold green]Credential setup complete! You can now run the main discovery tool.[/bold green]",
        title="[bold green]Success[/bold green]",
        border_style="green"
    ))

if __name__ == "__main__":
    setup_credentials()