"""HTTP fetcher — clean code, but depends on vulnerable requests version."""
import requests


def get_resource(url: str) -> bytes:
    """Fetch a remote resource and return its content."""
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    return response.content
