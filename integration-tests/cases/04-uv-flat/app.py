"""Simple app — clean code for uv/flat security audit testing."""
import httpx
from rich.console import Console

console = Console()


def fetch(url: str) -> None:
    """Fetch a URL and display the response status."""
    with httpx.Client() as client:
        response = client.get(url)
    console.print(f"[green]Status:[/green] {response.status_code}")
