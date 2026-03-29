"""Configuration and inventory loading."""

import csv
import json
import os
import stat
import sys
from pathlib import Path

from dotenv import load_dotenv


_DEV_TARGETS = {
    "dev": "https://api.network-audit.dev",
    "local": "http://127.0.0.1:5004",
}


def resolve_dev_url(target: str) -> str:
    """Resolve a --dev target to an API URL.

    Args:
        target: 'dev', 'local', an IP, or a full URL.

    Returns:
        Resolved API URL string.
    """
    if target in _DEV_TARGETS:
        return _DEV_TARGETS[target]
    if target.startswith(("http://", "https://")):
        return target.rstrip("/")
    return f"http://{target}"

from .display import console

CONFIG_DIR = Path.home() / ".config" / "network-audit-collector"
CONFIG_ENV = CONFIG_DIR / ".env"


def load_config():
    """Load API credentials from .env file.

    Checks ~/.config/network-audit-collector/.env first, then falls back
    to a local .env in the current directory.
    """
    # Local .env takes priority over the global config
    load_dotenv()
    if CONFIG_ENV.exists():
        load_dotenv(CONFIG_ENV, override=False)

    api_url = os.getenv("api_url")
    api_key = os.getenv("api_key")
    if not api_url or not api_key:
        from rich.panel import Panel
        console.print(Panel(
            "[bold red]Missing api_url or api_key.[/]\n"
            "Run [cyan]uv run main.py account --import-key[/] to configure, "
            "or create a .env file manually.",
            title="Configuration Error"))
        sys.exit(1)
    return api_url.rstrip("/"), api_key


def import_key():
    """Interactively import API credentials to ~/.config/network-audit-collector/.env."""
    from rich.panel import Panel

    console.print(Panel(
        "Import your network-audit.io API credentials.\n"
        f"Credentials will be saved to [cyan]{CONFIG_ENV}[/]",
        title="API Key Import"))

    if CONFIG_ENV.exists():
        load_dotenv(CONFIG_ENV)
        existing_key = os.getenv("api_key", "")
        masked = f"...{existing_key[-4:]}" if len(existing_key) >= 4 else "***"
        console.print(f"[yellow]Existing API key found ({masked})[/]")
        confirm = input("Overwrite? [y/N]: ").strip().lower()
        if confirm != "y":
            console.print("Aborted.")
            return

    api_url = input("API URL [https://api.network-audit.io]: ").strip()
    if not api_url:
        api_url = "https://api.network-audit.io"

    api_key = input("API Key: ").strip()
    if not api_key:
        console.print("[bold red]API key cannot be empty.[/]")
        sys.exit(1)

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_ENV.write_text(f"api_url={api_url}\napi_key={api_key}\n")
    CONFIG_ENV.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 600

    console.print(f"\n[green]Credentials saved to {CONFIG_ENV} (mode 600)[/]")
    console.print(f"API Key: ...{api_key[-4:]}")


def show_api_key():
    """Display the current API key from the global config (masked)."""
    if not CONFIG_ENV.exists():
        console.print("[yellow]No global config found.[/]")
        console.print(f"Run [cyan]account --import-key[/] or [cyan]account --api-key KEY[/] to configure.")
        return

    load_dotenv(CONFIG_ENV)
    api_key = os.getenv("api_key", "")
    api_url = os.getenv("api_url", "")

    if not api_key:
        console.print("[yellow]No API key set in global config.[/]")
        return

    masked = f"...{api_key[-4:]}" if len(api_key) >= 4 else "***"
    console.print(f"Config:  [dim]{CONFIG_ENV}[/]")
    console.print(f"API URL: {api_url}")
    console.print(f"API Key: {masked}")


def set_api_key(new_key: str):
    """Set or update the API key in the global config.

    Args:
        new_key: The new API key to save.
    """
    api_url = "https://api.network-audit.io"

    if CONFIG_ENV.exists():
        load_dotenv(CONFIG_ENV)
        api_url = os.getenv("api_url", api_url)

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_ENV.write_text(f"api_url={api_url}\napi_key={new_key}\n")
    CONFIG_ENV.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 600

    masked = f"...{new_key[-4:]}" if len(new_key) >= 4 else "***"
    console.print(f"[green]API key updated ({masked}) in {CONFIG_ENV}[/]")


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
