"""Check network-audit.io API status."""

import sys

import requests
from rich.panel import Panel
from rich.table import Table

from ..display import console


def run(args: object) -> None:
    """Run the status subcommand."""
    try:
        resp = requests.get("https://network-audit.io/status", timeout=15)
    except requests.RequestException as e:
        console.print(Panel(f"[bold red]Could not reach network-audit.io: {e}[/]",
                            title="Status Error"))
        sys.exit(1)

    if resp.status_code != 200:
        console.print(Panel(f"[bold red]Status check failed: HTTP {resp.status_code}[/]",
                            title="Status Error"))
        sys.exit(1)

    data = resp.json()
    status = data.get("status", "unknown")
    message = data.get("message")
    planned = data.get("planned_maintenance", [])
    updated_at = data.get("updated_at", "")

    # Status display
    if status == "operational":
        status_display = "[bold green]Operational[/bold green]"
    elif status == "maintenance":
        status_display = "[bold yellow]Maintenance[/bold yellow]"
    else:
        status_display = f"[bold red]{status}[/bold red]"

    lines = [f"Status: {status_display}"]
    if message:
        lines.append(f"Message: {message}")
    if updated_at:
        lines.append(f"[dim]Updated: {updated_at}[/dim]")

    console.print(Panel("\n".join(lines), title="network-audit.io"))

    # Planned maintenance windows
    if planned:
        table = Table(title="Planned Maintenance", show_lines=True)
        table.add_column("Start", style="yellow")
        table.add_column("End", style="yellow")
        table.add_column("Description")

        for window in planned:
            table.add_row(
                window.get("start", ""),
                window.get("end", ""),
                window.get("description", ""),
            )

        console.print(table)

    # Exit code for scripting: 0 = operational, 1 = anything else
    if status != "operational":
        sys.exit(1)
