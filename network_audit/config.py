"""Configuration and inventory loading."""

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


def load_inventory(path):
    """Load and validate a JSON inventory file."""
    from rich.panel import Panel

    try:
        with open(path) as f:
            inventory = json.load(f)
    except FileNotFoundError:
        console.print(Panel(f"[bold red]Inventory file not found: {path}[/]",
                            title="Inventory Error"))
        sys.exit(1)
    except json.JSONDecodeError as e:
        console.print(Panel(f"[bold red]Invalid JSON in {path}: {e}[/]",
                            title="Inventory Error"))
        sys.exit(1)

    if not isinstance(inventory, list) or not inventory:
        console.print(Panel("[bold red]Inventory must be a non-empty JSON array.[/]",
                            title="Inventory Error"))
        sys.exit(1)

    for entry in inventory:
        if "host" not in entry:
            console.print(Panel(f"[bold red]Inventory entry missing 'host': {entry}[/]",
                                title="Inventory Error"))
            sys.exit(1)
        entry.setdefault("name", entry["host"])

    return inventory
