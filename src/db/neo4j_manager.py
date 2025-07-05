import os
from neo4j import GraphDatabase, Driver
from neo4j.exceptions import ServiceUnavailable, AuthError
from rich.console import Console

# Initialize Rich Console
console = Console()

def get_neo4j_driver() -> Driver | None:
    """
    Creates and returns a Neo4j driver instance.

    This function securely loads connection details from environment variables
    (NEO4J_URI, NEO4J_USER, NEO4J_PASS) and attempts to establish a connection
    to the Neo4j database. It also verifies connectivity.

    Returns:
        neo4j.Driver | None: A connected Neo4j driver instance if successful, otherwise None.
    """
    uri = os.environ.get("NEO4J_URI")
    user = os.environ.get("NEO4J_USER")
    password = os.environ.get("NEO4J_PASS")

    if not all([uri, user, password]):
        console.print("[bold red]Error: Missing Neo4j environment variables.[/bold red]")
        console.print("[bold yellow]Please set NEO4J_URI, NEO4J_USER, and NEO4J_PASS.[/bold yellow]")
        return None

    try:
        driver = GraphDatabase.driver(uri, auth=(user, password))
        # Verify that the connection is valid
        driver.verify_connectivity()
        console.print(f"[*] Successful connection to Neo4j at [cyan]{uri}[/cyan]")
        return driver
    except AuthError:
        console.print(f"[bold red]Neo4j Authentication Failed.[/bold red] Please check your NEO4J_USER and NEO4J_PASS environment variables.")
        return None
    except ServiceUnavailable as e:
        console.print(f"[bold red]Neo4j Connection Failed: {e}[/bold red]")
        console.print(f"  - Is the Neo4j database running at {uri}?")
        console.print("  - Is the container port correctly mapped?")
        return None
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred while connecting to Neo4j: {e}[/bold red]")
        return None

def close_driver(driver: Driver | None):
    """
    Closes the Neo4j driver connection if it exists.

    Args:
        driver (neo4j.Driver | None): The driver instance to close.
    """
    if driver:
        driver.close()
        console.print("[*] Neo4j connection closed.")


# Example usage for standalone testing of this module
if __name__ == '__main__':
    console.rule("[bold blue]Testing Neo4j Connection Manager[/bold blue]")
    
    # For this test to work, you must have set the environment variables.
    # On Linux/macOS:
    # export NEO4J_URI="bolt://localhost:7687"
    # export NEO4J_USER="neo4j"
    # export NEO4J_PASS="password123"
    #
    # On Windows (Command Prompt):
    # set NEO4J_URI=bolt://localhost:7687
    # set NEO4J_USER=neo4j
    # set NEO4J_PASS=password123
    
    driver = get_neo4j_driver()

    if driver:
        console.print("[bold green]Connectivity test successful![/bold green]")
        # In a real application, you would now use the driver to run queries.
        close_driver(driver)
    else:
        console.print("[bold red]Connectivity test failed.[/bold red]")