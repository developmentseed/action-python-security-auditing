"""Simple app — clean code for pipenv/flat security audit testing."""
import httpx
import click


@click.command()
@click.argument("url")
def ping(url: str) -> None:
    """Ping a URL and print the status code."""
    with httpx.Client() as client:
        response = client.get(url)
    click.echo(f"Status: {response.status_code}")


if __name__ == "__main__":
    ping()
