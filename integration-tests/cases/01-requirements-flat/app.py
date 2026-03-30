"""Simple HTTP client — clean code for security audit baseline testing."""
import requests
import click


@click.command()
@click.argument("url")
def fetch(url: str) -> None:
    """Fetch a URL and print the response status."""
    response = requests.get(url, timeout=10)
    click.echo(f"Status: {response.status_code}")


if __name__ == "__main__":
    fetch()
