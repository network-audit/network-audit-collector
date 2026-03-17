"""Maintenance-aware gate for long-running scan jobs.

Checks the /status endpoint and blocks while maintenance is active,
resuming automatically when the window ends. Designed to be called
between device scans so in-flight work finishes cleanly.
"""

import time
from datetime import datetime, timezone

import requests

from .display import console

# How often to re-check while paused (seconds)
_POLL_INTERVAL = 60


def _is_maintenance_active(api_url: str) -> tuple[bool, str | None]:
    """Check /status for an active maintenance window.

    Returns:
        (active, description) — active is True if the current time falls
        within any planned_maintenance window.
    """
    try:
        resp = requests.get(f"{api_url}/status", timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException:
        # Can't reach status — don't block the scan on a transient failure
        return False, None

    now = datetime.now(timezone.utc)
    for m in data.get("planned_maintenance", []):
        try:
            start = datetime.fromisoformat(m["start"].replace("Z", "+00:00"))
            end = datetime.fromisoformat(m["end"].replace("Z", "+00:00"))
        except (KeyError, ValueError):
            continue
        if start <= now <= end:
            return True, m.get("description", "Scheduled maintenance")

    return False, None


def wait_if_maintenance(api_url: str) -> None:
    """Block until no maintenance window is active.

    Prints a status message while paused and a resume message when cleared.
    Safe to call from worker threads — output uses Rich console which is
    thread-safe.
    """
    active, description = _is_maintenance_active(api_url)
    if not active:
        return

    console.print(
        f"\n[bold yellow]⏸  Maintenance in progress: {description}[/]"
        f"\n[dim]Pausing scan — will resume automatically when maintenance ends "
        f"(checking every {_POLL_INTERVAL}s)...[/]"
    )

    while active:
        time.sleep(_POLL_INTERVAL)
        active, description = _is_maintenance_active(api_url)

    console.print("[bold green]▶  Maintenance ended — resuming scan[/]\n")
