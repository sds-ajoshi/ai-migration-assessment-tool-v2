# src/cli/setup_credentials.py
import typer
import structlog
import pandas as pd
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from typing import Optional
from src.secrets.keyring_backend import KeyringBackend
from src.secrets.vault_backend import VaultBackend
from src.secrets.base_backend import SecretBackend

app = typer.Typer()
console = Console()

# Configure structlog
structlog.configure(
    processors=[
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
)
logger = structlog.get_logger(__name__)

class CredentialSetupRunner:
    def __init__(self, backend: SecretBackend, inventory_path: str, dry_run: bool = False):
        self.backend = backend
        self.inventory_path = inventory_path
        self.dry_run = dry_run

    def run(self) -> None:
        try:
            inventory = pd.read_csv(self.inventory_path, dtype=str)
            unique_users = inventory["user"].dropna().unique()
            logger.info("Found unique users", count=len(unique_users), users=list(unique_users))
        except FileNotFoundError:
            console.print(f"[bold red]Error: Inventory file not found at '{self.inventory_path}'.[/bold red]")
            raise
        except KeyError:
            console.print(f"[bold red]Error: The inventory file '{self.inventory_path}' must contain a 'user' column.[/bold red]")
            raise
        except Exception as exc:
            logger.error("Error reading inventory", exc_info=exc)
            raise

        if not unique_users.size:
            console.print("[yellow]No users found in the inventory – nothing to do.[/yellow]")
            return

        for user in unique_users:
            password = self._prompt_password(user)
            if self._validate_password(password):
                if self.dry_run:
                    console.print(f"[yellow]Dry run: Would store password for '{user}'.[/yellow]")
                    logger.info("Dry run store", user=user)
                else:
                    self.backend.store_credential(user, password)
                    console.print(f"[green]✔ Password for '{user}' has been securely stored.[/green]")
                    logger.info("Stored credential", user=user)
            else:
                console.print(f"[red]Invalid password for '{user}' – skipping.[/red]")
                logger.warning("Invalid password skipped", user=user)

    def _prompt_password(self, user: str) -> str:
        while True:
            password = Prompt.ask(f"Enter password for user '[bold yellow]{user}[/bold yellow]'", password=True, console=console)
            if password:
                return password
            console.print("[red]Password cannot be empty – try again.[/red]")

    def _validate_password(self, password: str) -> bool:
        if len(password) < 12:
            console.print("[red]Password must be at least 12 characters long.[/red]")
            return False
        # Add more checks if needed (e.g., complexity)
        return True

@app.command()
def setup(
    inventory_path: str = typer.Option("inventory.csv", help="Path to inventory CSV file"),
    use_vault: bool = typer.Option(False, help="Use HashiCorp Vault backend instead of local keyring"),
    dry_run: bool = typer.Option(False, help="Simulate the setup without storing credentials"),
    verbose: bool = typer.Option(False, help="Enable verbose (JSON) logging")
):
    """Securely store passwords for users in the inventory."""
    if verbose:
        # Already configured for JSON
        pass

    console.print(Panel(f"Credential Setup for 'ai-migration-tool'", title="[bold cyan]Welcome[/bold cyan]", border_style="cyan"))

    if use_vault:
        backend = VaultBackend()
        logger.info("Using Vault backend")
    else:
        backend = KeyringBackend()
        logger.info("Using Keyring backend")

    runner = CredentialSetupRunner(backend, inventory_path, dry_run)
    try:
        runner.run()
        console.print(Panel("[bold green]Credential setup complete![/bold green]", title="[bold green]Success[/bold green]", border_style="green"))
    except Exception as e:
        logger.error("Setup failed", exc_info=e)
        console.print(f"[bold red]Setup failed: {e}[/bold red]")

if __name__ == "__main__":
    app()