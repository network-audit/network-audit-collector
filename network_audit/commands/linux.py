"""Linux host collector — SSH, parse os-release, check EOL via network-audit.io."""

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote

from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from ..api import api_get
from ..config import load_config, load_inventory
from ..display import build_live_display, console, create_progress
from ..export import default_csv_path, export_csv
from ..ssh import ssh_connect


# ---------------------------------------------------------------------------
# SSH Collection
# ---------------------------------------------------------------------------

def ssh_collect(host, username, password, timeout):
    """SSH into a Linux host and return /etc/os-release content.

    Also checks for Proxmox VE by running pveversion, appending the result
    as a synthetic PVE_VERSION line so the parser can detect it.
    """
    client = ssh_connect(host, username, password, timeout, use_keys=not password)
    try:
        _, stdout, _ = client.exec_command("cat /etc/os-release", timeout=timeout)
        os_release = stdout.read().decode("utf-8", errors="replace")

        # Detect Proxmox VE (pveversion outputs e.g. "pve-manager/9.1.2/...")
        _, pve_stdout, _ = client.exec_command("pveversion 2>/dev/null", timeout=timeout)
        pve_line = pve_stdout.read().decode("utf-8", errors="replace").strip()
        if pve_line.startswith("pve-manager/"):
            pve_ver = pve_line.split("/")[1]
            os_release += f"\nPVE_VERSION={pve_ver}\n"

        return os_release
    finally:
        client.close()


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_os_release(output):
    """Parse /etc/os-release → {distro, version, pretty_name}.

    Detects Proxmox VE via the synthetic PVE_VERSION line appended by
    ssh_collect, overriding the base Debian identity.
    """
    result = {"distro": "Unknown", "version": "Unknown", "pretty_name": "Unknown"}

    fields = {}
    for line in output.strip().splitlines():
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        fields[key.strip()] = val.strip().strip('"')

    if "PVE_VERSION" in fields:
        pve_full = fields["PVE_VERSION"]
        pve_major = pve_full.split(".")[0]
        result["distro"] = "proxmox"
        result["version"] = pve_major
        result["pretty_name"] = f"Proxmox VE {pve_full}"
    else:
        if "ID" in fields:
            result["distro"] = fields["ID"]
        if "VERSION_ID" in fields:
            result["version"] = fields["VERSION_ID"]
        if "PRETTY_NAME" in fields:
            result["pretty_name"] = fields["PRETTY_NAME"]

    return result


# ---------------------------------------------------------------------------
# API Queries
# ---------------------------------------------------------------------------

def query_distro_version(api_url, api_key, distro, version):
    """GET /api/v1/linux/distro/{distro}/{version} → release detail or error string."""
    return api_get(api_url, api_key,
                   f"/api/v1/linux/distro/{quote(distro, safe='')}/{quote(version, safe='')}")


# ---------------------------------------------------------------------------
# Per-device orchestration
# ---------------------------------------------------------------------------

def scan_device(device, username, password, timeout, api_url, api_key, debug=False):
    """Scan a single Linux host: SSH → parse → API. Returns result dict."""
    result = {
        "name": device["name"],
        "host": device["host"],
        "distro": "Unknown",
        "version": "Unknown",
        "pretty_name": "Unknown",
        "codename": "",
        "lts": False,
        "eol_status": None,
        "eol_date": None,
        "days_until_eol": None,
        "is_eol": None,
        "api_response": None,
        "error": None,
    }

    # Connect + parse
    try:
        os_release = ssh_collect(device["host"], username, password, timeout)
        parsed = parse_os_release(os_release)
        result["distro"] = parsed["distro"]
        result["version"] = parsed["version"]
        result["pretty_name"] = parsed["pretty_name"]
    except Exception as e:
        result["error"] = str(e)
        return result

    # API call
    if result["distro"] != "Unknown" and result["version"] != "Unknown":
        api_data = query_distro_version(api_url, api_key, result["distro"], result["version"])
        result["api_response"] = api_data
        if debug and isinstance(api_data, dict):
            console.print(Panel(
                json.dumps(api_data, indent=2),
                title=f"[dim]DEBUG API response for {device['name']}[/dim]",
            ))
        if isinstance(api_data, dict):
            data = api_data.get("data", api_data)
            result["eol_status"] = data.get("status", "Unknown")
            result["eol_date"] = data.get("eol_date", "")
            result["days_until_eol"] = data.get("days_until_eol")
            result["is_eol"] = data.get("is_eol")
            result["codename"] = data.get("codename", "")
            result["lts"] = data.get("lts", False)
        elif isinstance(api_data, str):
            result["eol_status"] = api_data

    return result


# ---------------------------------------------------------------------------
# CSV Export
# ---------------------------------------------------------------------------

FIELDNAMES = ["name", "host", "distro", "version", "codename", "lts",
              "eol_status", "eol_date", "days_until_eol", "error"]


def _build_csv_rows(results):
    rows = []
    for r in results:
        rows.append({
            "name": r["name"],
            "host": r["host"],
            "distro": r["distro"],
            "version": r["version"],
            "codename": r["codename"] or "",
            "lts": r["lts"],
            "eol_status": r["eol_status"] or "N/A",
            "eol_date": r["eol_date"] or "",
            "days_until_eol": r["days_until_eol"] if r["days_until_eol"] is not None else "",
            "error": r["error"] or "",
        })
    return rows


# ---------------------------------------------------------------------------
# Rich Display
# ---------------------------------------------------------------------------

def display_summary(results, csv_file):
    table = Table(title="Linux Audit Results", show_lines=False)
    table.add_column("Name", style="cyan")
    table.add_column("Host", style="dim")
    table.add_column("Distro", style="magenta")
    table.add_column("Version", style="blue")
    table.add_column("Codename", style="white")
    table.add_column("LTS", justify="center")
    table.add_column("EOL Status")
    table.add_column("EOL Date")
    table.add_column("Days Left", justify="right")
    table.add_column("Error", style="red")

    total = len(results)
    errors = 0
    eol_flagged = 0
    eol_warning = 0

    for r in results:
        eol_status = r["eol_status"] or "N/A"
        eol_date = r["eol_date"] or ""
        days_left = r["days_until_eol"]

        # EOL status display
        if eol_status in ("Not Found", "N/A", "Unknown"):
            eol_display = f"[dim]{eol_status}[/dim]"
        elif "error" in eol_status.lower() or "limit" in eol_status.lower():
            eol_display = f"[yellow]{eol_status}[/yellow]"
        elif eol_status.lower() == "eol" or r.get("is_eol"):
            eol_display = "[bold red]EOL[/bold red]"
            eol_flagged += 1
        elif eol_status.lower() == "warning":
            eol_display = "[bold yellow]Warning[/bold yellow]"
            eol_warning += 1
        elif eol_status.lower() in ("current", "active", "supported"):
            eol_display = f"[green]{eol_status.title()}[/green]"
        else:
            eol_display = f"[yellow]{eol_status}[/yellow]"

        # Days left display
        if days_left is not None:
            if days_left <= 0:
                days_display = "[bold red]EXPIRED[/bold red]"
            elif days_left <= 180:
                days_display = f"[bold yellow]{days_left}[/bold yellow]"
            else:
                days_display = f"[green]{days_left}[/green]"
        else:
            days_display = ""

        # LTS badge
        lts_display = "[green]Yes[/green]" if r["lts"] else "[dim]No[/dim]"

        if r["error"]:
            errors += 1

        table.add_row(
            r["name"], r["host"], r["distro"], r["version"],
            r["codename"], lts_display, eol_display, eol_date,
            days_display, r["error"] or "",
        )

    console.print()
    console.print(table)
    console.print()
    console.print(Panel(
        f"[bold]Total hosts:[/] {total}  |  "
        f"[bold red]Errors:[/] {errors}  |  "
        f"[bold red]EOL:[/] {eol_flagged}  |  "
        f"[bold yellow]Warning:[/] {eol_warning}  |  "
        f"[bold]CSV:[/] {csv_file}",
        title="Summary",
    ))


# ---------------------------------------------------------------------------
# Subcommand entry point
# ---------------------------------------------------------------------------

def run(args):
    """Run the linux collector subcommand."""
    console.print(Panel("[bold cyan]Linux Audit Scan[/]\n[dim]Powered by network-audit.io[/]",
                        expand=False))

    api_url, api_key = load_config()
    inventory = load_inventory(args.inventory)

    password = None
    if args.ask_pass:
        import getpass
        password = getpass.getpass(f"SSH password for {args.username}: ")

    results = []
    status_lines = []

    try:
        with Live(console=console, refresh_per_second=4) as live:
            progress = create_progress()
            task_id = progress.add_task("Scanning hosts...", total=len(inventory))

            def _scan(device):
                user = device.get("username", args.username)
                return scan_device(device, user, password, args.timeout, api_url, api_key,
                                   debug=args.debug)

            with ThreadPoolExecutor(max_workers=args.concurrent) as pool:
                futures = {}
                for i, device in enumerate(inventory):
                    if i > 0 and args.delay > 0:
                        time.sleep(args.delay)
                    status_lines.append(f"[yellow]Scanning {device['name']} ({device['host']})...[/]")
                    live.update(build_live_display(progress, status_lines))
                    futures[pool.submit(_scan, device)] = device

                for future in as_completed(futures):
                    device = futures[future]
                    result = future.result()
                    results.append(result)

                    if result["error"]:
                        status_lines.append(f"[red]\u2718 {device['name']}: {result['error']}[/]")
                    else:
                        status_lines.append(
                            f"[green]\u2714 {device['name']}: {result['pretty_name']}[/]"
                        )

                    progress.advance(task_id)
                    live.update(build_live_display(progress, status_lines))
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan cancelled by user[/]")
        return

    csv_file = args.output or default_csv_path("linux")
    export_csv(_build_csv_rows(results), FIELDNAMES, csv_file)
    display_summary(results, csv_file)
