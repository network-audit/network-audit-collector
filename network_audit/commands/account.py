"""Check network-audit.io account status and remaining queries."""

import sys

from rich.table import Table

from ..config import load_config
from ..display import console


def run(args):
    """Run the account subcommand."""
    if args.import_key:
        from ..config import import_key
        import_key()
        return

    import requests

    api_url, api_key = load_config()

    resp = requests.get(
        f"{api_url}/api/v1/account", headers={"X-API-Key": api_key}, timeout=15
    )

    if resp.status_code == 401:
        console.print("[bold red]Invalid API key.[/bold red]")
        sys.exit(1)

    if resp.status_code != 200:
        console.print(f"[bold red]Error: {resp.status_code} — {resp.text}[/bold red]")
        sys.exit(1)

    d = resp.json()["data"]
    remaining = d["rate_limit_daily"] - d["queries_today"]

    table = Table(title="Network-Audit.io Account", show_header=False, show_lines=False)
    table.add_column("Field", style="bold")
    table.add_column("Value")

    if args.account:
        table.add_row("Account", d["account_number"])
    table.add_row("Tier", d["tier"])
    table.add_row(
        "Today", f"{d['queries_today']} / {d['rate_limit_daily']} queries used"
    )
    table.add_row("Remaining", str(remaining))
    table.add_row("All-time", f"{d['queries_total']} total queries")
    table.add_row("Created", d["created_at"])

    console.print()
    console.print(table)
    console.print()
