"""Self-update — pull latest from origin and sync dependencies."""

import os
import subprocess
import sys
from pathlib import Path


def _find_repo_root():
    """Walk up from this file to find the git repo root."""
    path = Path(__file__).resolve()
    for parent in path.parents:
        if (parent / ".git").exists():
            return parent
    return None


def _run(cmd, cwd):
    """Run a shell command quietly, return result."""
    return subprocess.run(
        cmd, cwd=cwd, text=True,
        capture_output=True,
    )


def run(args):
    """Pull the latest version and sync dependencies."""
    repo = _find_repo_root()
    if repo is None:
        print("Error: could not find git repository root.")
        print("If you installed via pip, update with: pip install --upgrade network-audit-collector")
        sys.exit(1)

    print(f"Updating from {repo} ...")

    # Check for uncommitted changes
    result = _run(["git", "status", "--porcelain"], cwd=repo)
    stashed = False
    if result.stdout.strip():
        print("  Stashing local changes ...")
        _run(["git", "stash", "--quiet"], cwd=repo)
        stashed = True

    # Fetch + pull
    pull = _run(["git", "pull", "--ff-only"], cwd=repo)
    if pull.returncode != 0:
        print(f"  Pull failed: {pull.stderr.strip()}")
        if stashed:
            _run(["git", "stash", "pop", "--quiet"], cwd=repo)
        sys.exit(1)

    updated = "Already up to date" not in pull.stdout
    if updated:
        # Count new commits
        lines = [l for l in pull.stdout.strip().splitlines() if l.strip()]
        print(f"  Updated ({len(lines)} changes)")
    else:
        print("  Already up to date.")

    # Sync dependencies if something changed
    if updated:
        print("  Syncing dependencies ...")
        sync = _run(["uv", "sync"], cwd=repo)
        if sync.returncode != 0:
            print(f"  Warning: uv sync failed: {sync.stderr.strip()}")

    # Pop stash if we stashed
    if stashed:
        _run(["git", "stash", "pop", "--quiet"], cwd=repo)

    # Show current version
    result = _run(["git", "log", "--oneline", "-1"], cwd=repo)
    print(f"  Version: {result.stdout.strip()}")
