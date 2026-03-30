"""Simple CLI app — clean code for poetry/flat security audit testing."""
import click
import httpx

@click.command()
@click.option("--url", default="https://example.com", help="URL to fetch.")
def fetch(url: str) -> None:
    """Fetch a URL and print the HTTP status code."""
    with httpx.Client() as client:
        response = client.get(url)
    click.echo(f"Status: {response.status_code}")


if __name__ == "__main__":
    fetch()
