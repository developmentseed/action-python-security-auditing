"""Upsert a PR comment with security scan results using the gh CLI."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys

from .settings import Settings


def _resolve_exe(name: str) -> str:
    """Resolve an executable name to its full path via PATH, raising if not found."""
    resolved = shutil.which(name)
    if resolved is None:
        raise FileNotFoundError(f"Required tool not found on PATH: {name!r}")
    return resolved


def comment_marker(workflow: str) -> str:
    if workflow:
        return f"<!-- security-scan-results::{workflow} -->"
    return "<!-- security-scan-results -->"


def resolve_pr_number(settings: Settings) -> int | None:
    """Return a PR number from settings or by looking up the branch via gh CLI."""
    if settings.pr_number is not None:
        return settings.pr_number

    if not settings.github_head_ref or not settings.github_repository:
        return None

    result = subprocess.run(  # nosec B603,B605 -- list args, full path via _resolve_exe()
        [
            _resolve_exe("gh"),
            "pr",
            "list",
            "--head",
            settings.github_head_ref,
            "--json",
            "number",
            "--repo",
            settings.github_repository,
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None

    prs: list[dict[str, int]] = json.loads(result.stdout)
    return int(prs[0]["number"]) if prs else None


def upsert_pr_comment(markdown: str, settings: Settings) -> None:
    """Create or update the security-scan PR comment.

    Skips silently if no PR is found or if posting is disabled.
    """
    if not settings.github_token:
        return

    pr_number = resolve_pr_number(settings)
    if pr_number is None:
        print("No PR found — skipping comment.", file=sys.stderr)
        return

    marker = comment_marker(settings.github_workflow)
    body = f"{marker}\n{markdown}"
    repo = settings.github_repository

    # Find an existing comment with our marker
    existing_id: int | None = None
    list_result = subprocess.run(  # nosec B603,B605 -- list args, full path via _resolve_exe()
        [_resolve_exe("gh"), "api", f"repos/{repo}/issues/{pr_number}/comments"],
        capture_output=True,
        text=True,
    )
    if list_result.returncode == 0:
        for comment in json.loads(list_result.stdout):
            if marker in comment.get("body", ""):
                existing_id = int(comment["id"])
                break

    if existing_id is not None:
        subprocess.run(  # nosec B603,B605 -- list args, full path via _resolve_exe()
            [
                _resolve_exe("gh"),
                "api",
                "--method",
                "PATCH",
                f"repos/{repo}/issues/comments/{existing_id}",
                "--field",
                f"body={body}",
            ],
            check=True,
        )
    else:
        subprocess.run(  # nosec B603,B605 -- list args, full path via _resolve_exe()
            [_resolve_exe("gh"), "pr", "comment", str(pr_number), "--body", body, "--repo", repo],
            check=True,
        )
