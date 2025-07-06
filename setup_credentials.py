import pandas as pd
import keyring
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from keyring.errors import NoKeyringError

# Initialize Rich Console
console = Console()

# --- Constants ---
SERVICE_NAME = "ai-migration-tool"
INVENTORY_FILE = "inventory.csv"


def setup_credentials() -> None:
    """Read the inventory file, prompt for each unique user's password, and
    store the secret in the system keyring. Colours are handled by Rich and
    the password itself is masked by ``Prompt.ask(password=True)``.
    """
    console.print(
        Panel(
            f"[bold yellow]Credential Setup for '{SERVICE_NAME}'[/bold yellow]\n\n"
            f"This script will securely store passwords for users found in "
            f"'{INVENTORY_FILE}'.",
            title="[bold cyan]Welcome[/bold cyan]",
            border_style="cyan",
        )
    )

    # ── 1. Read inventory ────────────────────────────────────────────────
    try:
        inventory = pd.read_csv(INVENTORY_FILE, dtype=str)
        unique_users = inventory["user"].dropna().unique()
        console.print(
            f"\n[*] Found {len(unique_users)} unique user(s) in "
            f"'{INVENTORY_FILE}': [bold magenta]{', '.join(unique_users)}[/bold magenta]"
        )
    except FileNotFoundError:
        console.print(
            f"\n[bold red]Error: Inventory file not found at '{INVENTORY_FILE}'. "
            "Please create it before running this script.[/bold red]"
        )
        return
    except KeyError:
        console.print(
            f"\n[bold red]Error: The inventory file '{INVENTORY_FILE}' must contain a "
            "'user' column.[/bold red]"
        )
        return
    except Exception as exc:  # pragma: no cover – catch‑all for CSV parse failures
        console.print(
            f"\n[bold red]An error occurred while reading the inventory file: {exc}[/bold red]"
        )
        return

    if not unique_users.size:
        console.print("[yellow]No users found in the inventory – nothing to do.[/yellow]")
        return

    # ── 2. Prompt for passwords ──────────────────────────────────────────
    console.print("\n[*] Please enter the password for each user when prompted.")
    console.print("[dim]Note: Your input is hidden for security.[/dim]\n")

    for user in unique_users:
        try:
            password = Prompt.ask(
                f"  Enter password for user '[bold yellow]{user}[/bold yellow]'",
                password=True,
                console=console,
            )

            # Empty password? Ask again to avoid silent mistakes.
            if not password:
                console.print("[red]Password cannot be empty – try again.[/red]")
                password = Prompt.ask(
                    f"  Enter password for user '[bold yellow]{user}[/bold yellow]'",
                    password=True,
                    console=console,
                )

            keyring.set_password(SERVICE_NAME, user, password)
            console.print(
                f"  [green]✔[/green] Password for '[bold]{user}[/bold]' has been securely stored.\n"
            )
        except NoKeyringError:
            console.print(
                f"\n[bold red]No system keyring backend available on this machine. "
                "Install a backend (e.g. `secretstorage`, `pywin32`, or "
                "`keyrings.alt`) and try again.[/bold red]"
            )
            return
        except Exception as exc:
            console.print(
                f"\n[bold red]Could not store password for '{user}'. Error: {exc}[/bold red]"
            )
            return

    # ── 3. Done ─────────────────────────────────────────────────────────
    console.print(
        Panel(
            "[bold green]Credential setup complete! You can now run the main "
            "discovery tool.[/bold green]",
            title="[bold green]Success[/bold green]",
            border_style="green",
        )
    )


if __name__ == "__main__":
    setup_credentials()