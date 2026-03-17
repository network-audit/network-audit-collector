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

    if args.api_key is not None:
        if args.api_key == "__show__":
            from ..config import show_api_key
            show_api_key()
        else:
            from ..config import set_api_key
            set_api_key(args.api_key)
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
    monthly_limit = d.get("rate_limit_monthly", d.get("rate_limit_daily", 0))
    monthly_used = d.get("queries_this_month", d.get("queries_today", 0))
    remaining = monthly_limit - monthly_used

    table = Table(title="Network-Audit.io Account", show_header=False, show_lines=False)
    table.add_column("Field", style="bold")
    table.add_column("Value")

    if args.account:
        table.add_row("Account", d["account_number"])
    table.add_row("Tier", d["tier"])
    table.add_row(
        "This month", f"{monthly_used} / {monthly_limit} queries used"
    )
    table.add_row("Remaining", str(remaining))
    table.add_row("All-time", f"{d['queries_total']} total queries")
    table.add_row("Created", d["created_at"])

    console.print()
    console.print(table)
    console.print()
