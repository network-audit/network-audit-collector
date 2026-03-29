"""Check network-audit.io API status."""

import json
import sys
from datetime import datetime, timezone

import requests
from rich.panel import Panel
from rich.table import Table

from ..config import load_config
from ..display import console


def _parse_utc(ts: str) -> datetime | None:
    """Parse an ISO 8601 timestamp to a timezone-aware UTC datetime."""
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc)
    except (ValueError, AttributeError):
        return None


def _check_maintenance(maintenance: list[dict]) -> tuple[bool, str | None]:
    """Return (active_now, minutes_until_next) for the maintenance windows."""
    now = datetime.now(timezone.utc)
    active = False
    nearest_minutes: int | None = None

    for m in maintenance:
        start = _parse_utc(m.get("start", ""))
        end = _parse_utc(m.get("end", ""))
        if not start or not end:
            continue
        if start <= now <= end:
            active = True
        elif start > now:
            minutes = int((start - now).total_seconds() / 60)
            if nearest_minutes is None or minutes < nearest_minutes:
                nearest_minutes = minutes

    return active, nearest_minutes


def run(args: object) -> None:
    """Run the status subcommand."""
    api_url, api_key = load_config()
    use_json = getattr(args, "json", False) and not getattr(args, "rich", False)

    # --- Fetch platform status (public endpoint) ---
    try:
        status_resp = requests.get(f"{api_url}/status", timeout=15)
        status_resp.raise_for_status()
        status_data = status_resp.json()
    except requests.RequestException as e:
        if use_json:
            json.dump({"healthy": False, "should_backoff": True, "error": str(e)}, sys.stdout)
            print()
            sys.exit(1)
        console.print(Panel(f"[bold red]Could not reach API: {e}[/]", title="Status Error"))
        sys.exit(1)

    # --- Validate API key ---
    key_valid = False
    try:
        key_resp = requests.get(
            f"{api_url}/api/v1/account",
            headers={"X-API-Key": api_key},
            timeout=15,
        )
        key_valid = key_resp.status_code == 200
    except requests.RequestException:
        pass

    platform_status = status_data.get("status", "unknown")
    updated_at = status_data.get("updated_at", "")
    maintenance = status_data.get("planned_maintenance", [])
    maintenance_active, maintenance_minutes = _check_maintenance(maintenance)

    healthy = platform_status == "operational" and key_valid
    should_backoff = not healthy or maintenance_active

    # --- JSON output for scripting/cron ---
    if use_json:
        result: dict = {
            "healthy": healthy,
            "should_backoff": should_backoff,
            "status": platform_status,
            "updated_at": updated_at,
            "api_key_valid": key_valid,
            "maintenance_active": maintenance_active,
            "maintenance_starts_in_minutes": maintenance_minutes,
            "planned_maintenance": maintenance,
        }
        json.dump(result, sys.stdout, indent=2)
        print()
        sys.exit(0)

    # --- Rich output ---
    status_color = "green" if platform_status == "operational" else "red"
    key_color = "green" if key_valid else "red"
    key_text = "Valid" if key_valid else "Invalid"

    panel_lines = [
        f"Status: [{status_color}]{platform_status.title()}[/]",
        f"API Key: [{key_color}]{key_text}[/]",
        f"Updated: {updated_at}",
    ]
    console.print(Panel("\n".join(panel_lines), title="network-audit.io"))

    if maintenance:
        table = Table(title="Planned Maintenance")
        table.add_column("Start")
        table.add_column("End")
        table.add_column("Description")
        for m in maintenance:
            table.add_row(m.get("start", ""), m.get("end", ""), m.get("description", ""))
        console.print(table)
