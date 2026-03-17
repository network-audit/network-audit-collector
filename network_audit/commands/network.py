"""Cisco network device collector — SSH/Telnet, parse show version/inventory, check EOL/CVE."""

import getpass
import re
import socket
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
from ..display import build_live_display, console, create_progress
from ..export import default_csv_path, export_csv
from ..maintenance import wait_if_maintenance
from ..ssh import create_ssh_client


# ---------------------------------------------------------------------------
# SSH Collection
# ---------------------------------------------------------------------------

def ssh_collect(host, username, password, timeout):
    """SSH into a Cisco device and return raw show version + show inventory output."""
    client = create_ssh_client()
    try:
        client.connect(host, username=username, password=password,
                       timeout=timeout, look_for_keys=False, allow_agent=False)
        shell = client.invoke_shell()
        time.sleep(1)
        # Drain banner
        if shell.recv_ready():
            shell.recv(65535)

        shell.send("terminal length 0\n")
        time.sleep(0.5)
        if shell.recv_ready():
            shell.recv(65535)

        # show version
        shell.send("show version\n")
        time.sleep(2)
        version_output = ""
        while shell.recv_ready():
            version_output += shell.recv(65535).decode("utf-8", errors="replace")

        # show inventory
        shell.send("show inventory\n")
        time.sleep(2)
        inventory_output = ""
        while shell.recv_ready():
            inventory_output += shell.recv(65535).decode("utf-8", errors="replace")

        return version_output, inventory_output
    finally:
        client.close()


# ---------------------------------------------------------------------------
# Telnet Collection
# ---------------------------------------------------------------------------

def _telnet_read_until(sock, markers, timeout):
    """Read from socket until any marker bytes are found or timeout expires.

    Args:
        sock: Connected socket.
        markers: A single bytes marker or a sequence of bytes markers.
            Reading stops when any marker is found in the buffer.
        timeout: Read timeout in seconds.
    """
    if isinstance(markers, bytes):
        markers = (markers,)
    buf = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        sock.settimeout(remaining)
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            # Strip telnet IAC negotiation sequences (IAC = 0xFF)
            clean = b""
            i = 0
            while i < len(chunk):
                if chunk[i] == 0xFF and i + 1 < len(chunk):
                    if chunk[i + 1] in (0xFB, 0xFC, 0xFD, 0xFE) and i + 2 < len(chunk):
                        # WILL/WONT/DO/DONT + option — respond with refusal
                        cmd = chunk[i + 1]
                        opt = chunk[i + 2]
                        if cmd == 0xFD:       # DO → WONT
                            sock.sendall(bytes([0xFF, 0xFC, opt]))
                        elif cmd == 0xFB:     # WILL → DONT
                            sock.sendall(bytes([0xFF, 0xFE, opt]))
                        i += 3
                        continue
                    elif chunk[i + 1] == 0xFF:
                        clean += b"\xff"
                        i += 2
                        continue
                    else:
                        i += 2
                        continue
                clean += bytes([chunk[i]])
                i += 1
            buf += clean
            if any(m in buf for m in markers):
                break
        except socket.timeout:
            break
    return buf


def telnet_collect(host, username, password, timeout):
    """Telnet into a Cisco device and return raw show version + show inventory output."""
    sock = socket.create_connection((host, 23), timeout)
    try:
        _telnet_read_until(sock, b"Username:", timeout)
        sock.sendall(username.encode("ascii") + b"\n")
        _telnet_read_until(sock, b"Password:", timeout)
        sock.sendall(password.encode("ascii") + b"\n")

        # Wait for prompt (# = privileged, > = user mode)
        prompt_markers = (b"#", b">")
        _telnet_read_until(sock, prompt_markers, timeout)

        sock.sendall(b"terminal length 0\n")
        time.sleep(0.5)
        _telnet_read_until(sock, prompt_markers, timeout)

        # show version
        sock.sendall(b"show version\n")
        version_output = _telnet_read_until(sock, prompt_markers, timeout).decode("utf-8", errors="replace")

        # show inventory
        sock.sendall(b"show inventory\n")
        inventory_output = _telnet_read_until(sock, prompt_markers, timeout).decode("utf-8", errors="replace")

        return version_output, inventory_output
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_show_version(output):
    """Parse show version output → {hostname, model, os_version}."""
    result = {"hostname": "Unknown", "model": "Unknown", "os_version": "Unknown"}

    # Hostname: prompt line or uptime line
    m = re.search(r"(\S+)\s+uptime is", output)
    if m:
        result["hostname"] = m.group(1)
    else:
        m = re.search(r"^(\S+)[#>]", output, re.MULTILINE)
        if m:
            result["hostname"] = m.group(1)

    # OS Version
    m = re.search(r"Cisco IOS.*?Version\s+([\S]+?),", output)
    if m:
        result["os_version"] = m.group(1)
    else:
        m = re.search(r"(?:NXOS|NX-OS).*?[Vv]ersion\s+([\S]+)", output)
        if m:
            result["os_version"] = m.group(1)

    # Model — priority 1: "Model number" field (IOS switches)
    m = re.search(r"[Mm]odel\s+[Nn]umber\s*:\s*(\S+)", output)
    if m:
        result["model"] = m.group(1)
    else:
        # Priority 2: hardware line — "cisco MODEL (...) processor/with"
        m = re.search(r"[Cc]isco\s+([\w/-]+)\s+\(", output)
        if m:
            result["model"] = m.group(1)

    return result


def parse_show_inventory(output):
    """Fallback model parse from show inventory PID line."""
    m = re.search(r"PID:\s*([\w/-]+)", output)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# API Queries
# ---------------------------------------------------------------------------

def query_eol(api_url, api_key, model):
    """GET /api/v1/eol/cisco/{model} → EOL data dict or error string."""
    return api_get(api_url, api_key,
                   f"/api/v1/eol/cisco/{quote(model, safe='')}")


def query_cve(api_url, api_key, model, os_version=None):
    """GET /api/v1/cve/cisco/{model}?os_version=... → CVE data dict or error string."""
    params = {}
    if os_version and os_version != "Unknown":
        params["os_version"] = os_version
    return api_get(api_url, api_key,
                   f"/api/v1/cve/cisco/{quote(model, safe='')}",
                   params=params or None)


# ---------------------------------------------------------------------------
# Per-device orchestration
# ---------------------------------------------------------------------------

def scan_device(device, username, password, timeout, api_url, api_key, use_telnet=False):
    """Scan a single device: SSH/Telnet → parse → API. Returns result dict."""
    result = {
        "name": device["name"],
        "host": device["host"],
        "hostname": "Unknown",
        "model": "Unknown",
        "os_version": "Unknown",
        "eol": None,
        "cve": None,
        "error": None,
    }

    # Connect + parse
    try:
        if use_telnet:
            ver_out, inv_out = telnet_collect(device["host"], username, password, timeout)
        else:
            ver_out, inv_out = ssh_collect(device["host"], username, password, timeout)
        parsed = parse_show_version(ver_out)
        result["hostname"] = parsed["hostname"]
        result["model"] = parsed["model"]
        result["os_version"] = parsed["os_version"]

        # Fallback model from inventory
        if result["model"] == "Unknown":
            pid = parse_show_inventory(inv_out)
            if pid:
                result["model"] = pid
    except (OSError, paramiko.SSHException) as e:
        result["error"] = str(e)
        return result

    # API calls (skip if model unknown)
    if result["model"] != "Unknown":
        result["eol"] = query_eol(api_url, api_key, result["model"])
        result["cve"] = query_cve(api_url, api_key, result["model"], result["os_version"])

    return result


# ---------------------------------------------------------------------------
# Helpers for CSV / display
# ---------------------------------------------------------------------------

def _extract_eol_status(eol_data):
    if eol_data is None:
        return "N/A"
    if isinstance(eol_data, str):
        return eol_data
    if isinstance(eol_data, dict):
        data = eol_data.get("data", eol_data)
        return data.get("status", "Unknown")
    return "Unknown"


def _extract_eol_details(eol_data):
    """Extract the full milestones dict from EOL response, or None."""
    if isinstance(eol_data, dict):
        data = eol_data.get("data", eol_data)
        return data.get("milestones")
    return None


def _extract_cve_count(cve_data):
    if cve_data is None:
        return 0
    if isinstance(cve_data, str):
        return 0
    if isinstance(cve_data, dict):
        data = cve_data.get("data", cve_data)
        total = data.get("total")
        if isinstance(total, int):
            return total
        cves = data.get("cves", [])
        return len(cves) if isinstance(cves, list) else 0
    if isinstance(cve_data, list):
        return len(cve_data)
    return 0


# ---------------------------------------------------------------------------
# CSV Export
# ---------------------------------------------------------------------------

def _build_csv_rows(results):
    """Transform results into flat CSV row dicts."""
    rows = []
    for r in results:
        rows.append({
            "name": r["name"],
            "host": r["host"],
            "hostname": r["hostname"],
            "model": r["model"],
            "os_version": r["os_version"],
            "eol_status": _extract_eol_status(r["eol"]),
            "cve_count": _extract_cve_count(r["cve"]),
            "error": r["error"] or "",
        })
    return rows


FIELDNAMES = ["name", "host", "hostname", "model", "os_version",
              "eol_status", "cve_count", "error"]


# ---------------------------------------------------------------------------
# Rich Display
# ---------------------------------------------------------------------------

def display_summary(results, csv_file):
    """Print a Rich summary table and footer stats."""
    table = Table(title="Network Audit Results", show_lines=False)
    table.add_column("Name", style="cyan")
    table.add_column("Host", style="dim")
    table.add_column("Hostname", style="white")
    table.add_column("Model", style="magenta")
    table.add_column("OS Version", style="blue")
    table.add_column("EOL Status")
    table.add_column("CVEs")
    table.add_column("Error", style="red")

    total = len(results)
    errors = 0
    eol_flagged = 0

    for r in results:
        eol_status = _extract_eol_status(r["eol"])
        cve_count = _extract_cve_count(r["cve"])

        # Color-code EOL
        if eol_status in ("Not Found", "N/A", "Unknown"):
            eol_display = f"[dim]{eol_status}[/dim]"
        elif "error" in eol_status.lower() or "limit" in eol_status.lower():
            eol_display = f"[yellow]{eol_status}[/yellow]"
        elif eol_status.lower() == "eol":
            eol_display = "[bold red]EOL[/bold red]"
            eol_flagged += 1
        elif eol_status.lower() == "active":
            eol_display = "[green]Active[/green]"
        else:
            eol_display = f"[yellow]{eol_status}[/yellow]"

        # Color-code CVE count
        if cve_count == 0:
            cve_display = "[green]0[/green]"
        elif cve_count < 5:
            cve_display = f"[yellow]{cve_count}[/yellow]"
        else:
            cve_display = f"[bold red]{cve_count}[/bold red]"

        if r["error"]:
            errors += 1

        table.add_row(
            r["name"], r["host"], r["hostname"], r["model"], r["os_version"],
            eol_display, cve_display, r["error"] or "",
        )

    console.print()
    console.print(table)
    console.print()
    console.print(Panel(
        f"[bold]Total devices:[/] {total}  |  "
        f"[bold red]Errors:[/] {errors}  |  "
        f"[bold red]EOL flagged:[/] {eol_flagged}  |  "
        f"[bold]CSV:[/] {csv_file}",
        title="Summary",
    ))


# ---------------------------------------------------------------------------
# Subcommand entry point
# ---------------------------------------------------------------------------

def run(args):
    """Run the network collector subcommand."""
    console.print(Panel("[bold cyan]Network Audit Scan[/]\n[dim]Powered by network-audit.io[/]",
                        expand=False))

    api_url, api_key = load_config()
    inventory = load_inventory(args.inventory)

    proto = "Telnet" if args.telnet else "SSH"
    password = getpass.getpass(f"{proto} password for {args.username}: ")

    results = []
    status_lines = []
    status_lock = threading.Lock()

    try:
        with Live(console=console, refresh_per_second=4) as live:
            progress = create_progress()
            task_id = progress.add_task("Scanning devices...", total=len(inventory))

            def _scan(device):
                wait_if_maintenance(api_url)
                return scan_device(device, args.username, password, args.timeout, api_url, api_key,
                                   use_telnet=args.telnet)

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
                            status_lines.append(f"[red]\u2718 {device['name']} ({device['host']}): {result['error']}[/]")
                        else:
                            status_lines.append(f"[green]\u2714 {device['name']} ({device['host']}): {result['model']}[/]")

                    progress.advance(task_id)
                    live.update(build_live_display(progress, status_lines))
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan cancelled by user[/]")
        return

    csv_file = args.output or default_csv_path("network")
    export_csv(_build_csv_rows(results), FIELDNAMES, csv_file)
    display_summary(results, csv_file)
