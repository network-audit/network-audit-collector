"""Configuration and inventory loading."""

import csv
import json
import os
import sys

from dotenv import load_dotenv

from .display import console


def load_config():
    """Load API credentials from .env file."""
    load_dotenv()
    api_url = os.getenv("api_url")
    api_key = os.getenv("api_key")
    if not api_url or not api_key:
        from rich.panel import Panel
        console.print(Panel("[bold red]Missing api_url or api_key in .env file.[/]",
                            title="Configuration Error"))
        sys.exit(1)
    return api_url.rstrip("/"), api_key


def _load_json_inventory(path: str) -> list[dict]:
    """Load inventory from a JSON file."""
    from rich.panel import Panel

    try:
        with open(path) as f:
            inventory = json.load(f)
    except json.JSONDecodeError as e:
        console.print(Panel(f"[bold red]Invalid JSON in {path}: {e}[/]",
                            title="Inventory Error"))
        sys.exit(1)

    if not isinstance(inventory, list) or not inventory:
        console.print(Panel("[bold red]Inventory must be a non-empty JSON array.[/]",
                            title="Inventory Error"))
        sys.exit(1)

    return inventory


def _load_csv_inventory(path: str) -> list[dict]:
    """Load inventory from a CSV file.

    Expects a 'host' column. An optional 'name' column is also supported.
    """
    from rich.panel import Panel

    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None or "host" not in reader.fieldnames:
            console.print(Panel(f"[bold red]CSV inventory must have a 'host' column: {path}[/]",
                                title="Inventory Error"))
            sys.exit(1)
        inventory = list(reader)

    if not inventory:
        console.print(Panel(f"[bold red]CSV inventory is empty: {path}[/]",
                            title="Inventory Error"))
        sys.exit(1)

    return inventory


def load_inventory(path: str) -> list[dict]:
    """Load and validate an inventory file (JSON or CSV).

    Args:
        path: Path to inventory file. Format is detected by extension
              (.csv for CSV, anything else treated as JSON).

    Returns:
        List of dicts with at least a 'host' and 'name' key each.
    """
    from rich.panel import Panel

    try:
        if path.lower().endswith(".csv"):
            inventory = _load_csv_inventory(path)
        else:
            inventory = _load_json_inventory(path)
    except FileNotFoundError:
        console.print(Panel(f"[bold red]Inventory file not found: {path}[/]",
                            title="Inventory Error"))
        sys.exit(1)

    for entry in inventory:
        if "host" not in entry:
            console.print(Panel(f"[bold red]Inventory entry missing 'host': {entry}[/]",
                                title="Inventory Error"))
            sys.exit(1)
        entry.setdefault("name", entry["host"])

    return inventory
