"""Linux host collector — SSH, parse os-release, check EOL via network-audit.io."""

import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote

import paramiko

from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from ..api import api_get
from ..config import load_config, load_inventory
from .. import display as _display
from ..display import build_live_display, create_progress
from ..export import default_csv_path, export_csv
from ..maintenance import wait_if_maintenance
from ..ssh import ssh_connect


# ---------------------------------------------------------------------------
# SSH Collection
# ---------------------------------------------------------------------------

def ssh_collect(host, username, password, timeout, check_sysinfo=False):
    """SSH into a Linux host and return /etc/os-release content.

    Also checks for Proxmox VE by running pveversion, appending the result
    as a synthetic PVE_VERSION line so the parser can detect it.
    When check_sysinfo is True, appends CPU, memory, storage, and uptime info.
    """
    client = ssh_connect(host, username, password, timeout, use_keys=not password)
    try:
        _, stdout, _ = client.exec_command("cat /etc/os-release", timeout=timeout)
        os_release = stdout.read().decode("utf-8", errors="replace")

        # Detect Proxmox VE (pveversion outputs e.g. "pve-manager/9.1.2/...")
        _, pve_stdout, _ = client.exec_command("pveversion 2>/dev/null", timeout=timeout)
        pve_line = pve_stdout.read().decode("utf-8", errors="replace").strip()
        try:
            if pve_line.startswith("pve-manager/"):
                pve_ver = pve_line.split("/")[1]
                os_release += f"\nPVE_VERSION={pve_ver}\n"
        except (IndexError, ValueError):
            pass

        # System info (opt-in via --sysinfo)
        if check_sysinfo:
            _, si_stdout, _ = client.exec_command(
                _SYSINFO_CMD, timeout=timeout,
            )
            sysinfo = si_stdout.read().decode("utf-8", errors="replace").strip()
            if sysinfo:
                os_release += f"\n{sysinfo}\n"

        return os_release
    finally:
        client.close()


# Shell snippet that outputs system info as KEY=VALUE lines.
_SYSINFO_CMD = (
    # CPU: model name from /proc/cpuinfo (first match)
    "echo \"SYSINFO_CPU=$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null"
    " | cut -d: -f2 | sed 's/^ //')\";"
    # CPU cores
    "echo \"SYSINFO_CORES=$(nproc 2>/dev/null)\";"
    # Memory: total/used/free in MB
    "awk '/MemTotal/{t=$2} /MemAvailable/{a=$2}"
    " END{u=t-a; printf \"SYSINFO_MEM_TOTAL_MB=%d\\nSYSINFO_MEM_USED_MB=%d\\n\","
    " t/1024, u/1024}' /proc/meminfo 2>/dev/null;"
    # Storage: root filesystem usage
    "df -BM / 2>/dev/null | awk 'NR==2{"
    " gsub(/M/,\"\"); printf \"SYSINFO_DISK_TOTAL_MB=%s\\nSYSINFO_DISK_USED_MB=%s\\n\", $2, $3}';"
    # Uptime: seconds since boot
    "echo \"SYSINFO_UPTIME_SECS=$(cut -d. -f1 /proc/uptime 2>/dev/null)\""
)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_os_release(output):
    """Parse /etc/os-release → {distro, version, pretty_name}.

    Detects Proxmox VE via the synthetic PVE_VERSION line appended by
    ssh_collect, overriding the base Debian identity.
    """
    result = {"distro": "Unknown", "version": "Unknown", "pretty_name": "Unknown",
              "sysinfo": None}

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

    if "SYSINFO_CPU" in fields:
        total_mb = int(fields.get("SYSINFO_MEM_TOTAL_MB", 0) or 0)
        used_mb = int(fields.get("SYSINFO_MEM_USED_MB", 0) or 0)
        disk_total_mb = int(fields.get("SYSINFO_DISK_TOTAL_MB", 0) or 0)
        disk_used_mb = int(fields.get("SYSINFO_DISK_USED_MB", 0) or 0)
        uptime_secs = int(fields.get("SYSINFO_UPTIME_SECS", 0) or 0)

        result["sysinfo"] = {
            "cpu": fields.get("SYSINFO_CPU", ""),
            "cores": int(fields.get("SYSINFO_CORES", 0) or 0),
            "memory_total_mb": total_mb,
            "memory_used_mb": used_mb,
            "disk_total_mb": disk_total_mb,
            "disk_used_mb": disk_used_mb,
            "uptime": _format_uptime(uptime_secs),
            "uptime_secs": uptime_secs,
        }

    return result


def _format_uptime(secs):
    """Format seconds into a human-readable uptime string."""
    days, rem = divmod(secs, 86400)
    hours, rem = divmod(rem, 3600)
    mins, _ = divmod(rem, 60)
    if days > 0:
        return f"{days}d {hours}h {mins}m"
    if hours > 0:
        return f"{hours}h {mins}m"
    return f"{mins}m"


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

def scan_device(device, username, password, timeout, api_url, api_key,
                check_sysinfo=False, no_api=False, debug=False):
    """Scan a single Linux host: SSH → parse → API. Returns result dict."""
    result = {
        "name": device["name"],
        "host": device["host"],
        "distro": "Unknown",
        "version": "Unknown",
        "pretty_name": "Unknown",
        "codename": "",
        "lts": False,
        "sysinfo": None,
        "eol_status": None,
        "eol_date": None,
        "days_until_eol": None,
        "is_eol": None,
        "api_response": None,
        "error": None,
    }

    # Connect + parse
    try:
        os_release = ssh_collect(device["host"], username, password, timeout,
                                 check_sysinfo=check_sysinfo)
        parsed = parse_os_release(os_release)
        result["distro"] = parsed["distro"]
        result["version"] = parsed["version"]
        result["pretty_name"] = parsed["pretty_name"]
        result["sysinfo"] = parsed["sysinfo"]
    except (OSError, paramiko.SSHException) as e:
        result["error"] = str(e)
        return result

    # API call
    if not no_api and result["distro"] != "Unknown" and result["version"] != "Unknown":
        api_data = query_distro_version(api_url, api_key, result["distro"], result["version"])
        result["api_response"] = api_data
        if debug and isinstance(api_data, dict):
            _display.console.print(Panel(
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

    _display.console.print()
    _display.console.print(table)
    _display.console.print()
    summary = (
        f"[bold]Total hosts:[/] {total}  |  "
        f"[bold red]Errors:[/] {errors}  |  "
        f"[bold red]EOL:[/] {eol_flagged}  |  "
        f"[bold yellow]Warning:[/] {eol_warning}"
    )
    if csv_file:
        summary += f"  |  [bold]CSV:[/] {csv_file}"
    _display.console.print(Panel(summary, title="Summary"))


# ---------------------------------------------------------------------------
# Subcommand entry point
# ---------------------------------------------------------------------------

def _build_json_results(results, include_sysinfo=False):
    """Build a JSON-serializable list from scan results."""
    output = []
    for r in results:
        entry = {
            "name": r["name"],
            "host": r["host"],
            "distro": r["distro"],
            "version": r["version"],
            "pretty_name": r["pretty_name"],
            "codename": r["codename"],
            "lts": r["lts"],
            "eol_status": r["eol_status"],
            "eol_date": r["eol_date"],
            "days_until_eol": r["days_until_eol"],
            "is_eol": r["is_eol"],
            "api_response": r["api_response"] if isinstance(r["api_response"], dict) else None,
            "error": r["error"],
        }
        if include_sysinfo:
            entry["sysinfo"] = r["sysinfo"]
        output.append(entry)
    return output


def run(args):
    """Run the linux collector subcommand."""
    if args.no_rich:
        from ..display import quiet_console
        quiet_console()
    elif args.json:
        from ..display import redirect_console_to_stderr
        redirect_console_to_stderr()

    _display.console.print(Panel("[bold cyan]Linux Audit Scan[/]\n[dim]Powered by network-audit.io[/]",
                        expand=False))

    if args.no_api:
        api_url, api_key = "", ""
    else:
        api_url, api_key = load_config()
    inventory = load_inventory(args.inventory)

    password = None
    if args.ask_pass:
        import getpass
        password = getpass.getpass(f"SSH password for {args.username}: ")

    results = []
    status_lines = []
    status_lock = threading.Lock()

    try:
        with Live(console=_display.console, refresh_per_second=4) as live:
            progress = create_progress()
            task_id = progress.add_task("Scanning hosts...", total=len(inventory))

            def _scan(device):
                if not args.no_api:
                    wait_if_maintenance(api_url)
                user = device.get("username", args.username)
                return scan_device(device, user, password, args.timeout, api_url, api_key,
                                   check_sysinfo=args.sysinfo, no_api=args.no_api,
                                   debug=args.debug)

            with ThreadPoolExecutor(max_workers=args.concurrent) as pool:
                futures = {}
                for i, device in enumerate(inventory):
                    if i > 0 and args.delay > 0:
                        time.sleep(args.delay)
                    with status_lock:
                        status_lines.append(f"[yellow]Scanning {device['name']} ({device['host']})...[/]")
                    live.update(build_live_display(progress, status_lines))
                    futures[pool.submit(_scan, device)] = device

                for future in as_completed(futures):
                    device = futures[future]
                    result = future.result()
                    results.append(result)

                    with status_lock:
                        if result["error"]:
                            status_lines.append(f"[red]\u2718 {device['name']}: {result['error']}[/]")
                        else:
                            status_lines.append(
                                f"[green]\u2714 {device['name']}: {result['pretty_name']}[/]"
                            )

                    progress.advance(task_id)
                    live.update(build_live_display(progress, status_lines))
    except KeyboardInterrupt:
        _display.console.print("\n[yellow]Scan cancelled by user[/]")
        return

    if not args.no_csv:
        csv_file = args.output or default_csv_path("linux")
        export_csv(_build_csv_rows(results), FIELDNAMES, csv_file)
    else:
        csv_file = None

    if args.json:
        json.dump(_build_json_results(results, include_sysinfo=args.sysinfo),
                  sys.stdout, indent=2)
        print()

    if not args.no_rich and not args.json:
        display_summary(results, csv_file)
