"""Cisco network device collector — SSH/Telnet, parse show version/inventory, check EOL/CVE."""

import getpass
import json
import re
import sys
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
from ..config import load_config, load_inventory, resolve_dev_url
from .. import display as _display
from ..display import build_live_display, create_progress
from ..export import default_csv_path, export_csv
from ..maintenance import wait_if_maintenance
from ..ssh import create_ssh_client


# ---------------------------------------------------------------------------
# SSH Collection
# ---------------------------------------------------------------------------

def _parse_host_port(host, default_port=22):
    """Split host into (hostname, port), supporting host:port notation."""
    if ":" in host:
        parts = host.rsplit(":", 1)
        try:
            return parts[0], int(parts[1])
        except ValueError:
            pass
    return host, default_port


def ssh_collect(host, username, password, timeout):
    """SSH into a Cisco device and return raw show version + show inventory output."""
    hostname, port = _parse_host_port(host)
    client = create_ssh_client()
    try:
        client.connect(hostname, port=port, username=username, password=password,
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
    """Parse show version output → {hostname, model, os_version}.

    Supports Cisco IOS/IOS-XE/NX-OS/ASA/WLC/AireOS, Arista EOS,
    and Juniper JunOS.
    """
    result = {"hostname": "Unknown", "model": "Unknown", "os_version": "Unknown", "vendor": "cisco"}

    # --- Detect vendor ---
    is_arista = "Arista" in output
    is_juniper = "Junos:" in output or "JUNOS" in output
    is_asa = "Adaptive Security Appliance" in output and "Firepower" not in output
    is_ftd = "Firepower" in output or "FPR" in output
    is_aireos = "AireOS" in output
    is_iosxr = "IOS XR" in output

    if is_arista:
        result["vendor"] = "arista"
    elif is_juniper:
        result["vendor"] = "juniper"

    # --- Hostname ---
    if is_juniper:
        m = re.search(r"^Hostname:\s*(\S+)", output, re.MULTILINE)
        if m:
            result["hostname"] = m.group(1)
    elif is_ftd:
        # FTD: "---[ hostname ]---" or "hostname up N days"
        m = re.search(r"---+\[\s*(\S+)\s*\]---+", output)
        if not m:
            m = re.search(r"^(\S+)\s+up\s+\d+", output, re.MULTILINE)
        if m:
            result["hostname"] = m.group(1)
    elif is_asa:
        # ASA: "hostname up 312 days..."
        m = re.search(r"^(\S+)\s+up\s+\d+", output, re.MULTILINE)
        if m:
            result["hostname"] = m.group(1)
    elif is_iosxr:
        # IOS-XR: "System uptime is..." — hostname from prompt
        pass
    elif is_aireos:
        m = re.search(r"System Name\.*\s+(\S+)", output)
        if m:
            result["hostname"] = m.group(1)
    else:
        m = re.search(r"(\S+)\s+uptime is", output)
        if m:
            result["hostname"] = m.group(1)
    # Fallback: prompt line
    if result["hostname"] == "Unknown":
        m = re.search(r"^(\S+)[#>]", output, re.MULTILINE)
        if m:
            result["hostname"] = m.group(1)

    # --- OS Version ---
    if is_arista:
        m = re.search(r"Software image version:\s*(\S+)", output)
        if m:
            result["os_version"] = m.group(1)
    elif is_juniper:
        m = re.search(r"^Junos:\s*(\S+)", output, re.MULTILINE)
        if m:
            result["os_version"] = m.group(1)
    elif is_ftd:
        # FTD: "Version X.Y.Z (Build NN)" or fallback to ASA version line
        m = re.search(r"Version\s+(\d+\.\d+\.\d+)\s+\(Build", output)
        if not m:
            m = re.search(r"Adaptive Security Appliance Software Version\s+(\S+)", output)
        if m:
            result["os_version"] = m.group(1)
    elif is_asa:
        m = re.search(r"Adaptive Security Appliance Software Version\s+(\S+)", output)
        if m:
            result["os_version"] = m.group(1)
    elif is_iosxr:
        m = re.search(r"Cisco IOS XR Software, Version\s+(\S+)", output)
        if m:
            result["os_version"] = m.group(1)
    elif is_aireos:
        m = re.search(r"Product Version\s+(\S+)", output)
        if m:
            result["os_version"] = m.group(1)
    else:
        m = re.search(r"Cisco IOS.*?Version\s+([\S]+?),", output)
        if m:
            result["os_version"] = m.group(1)
        else:
            m = re.search(r"(?:NXOS|NX-OS).*?[Vv]ersion\s+([\S]+)", output)
            if m:
                result["os_version"] = m.group(1)

    # --- Model ---
    if is_arista:
        # "Arista DCS-7050SX3-48YC12" or "Arista vEOS"
        m = re.search(r"Arista\s+(?:DCS-)?(\S+)", output)
        if m:
            result["model"] = m.group(1)
    elif is_juniper:
        m = re.search(r"^Model:\s*(\S+)", output, re.MULTILINE)
        if m:
            result["model"] = m.group(1)
    elif is_ftd:
        # FTD: "Model : Cisco Firepower FPR-4120" or "Hardware: FPR-4120,"
        m = re.search(r"Model\s*:\s*Cisco Firepower\s+(\S+)", output)
        if not m:
            m = re.search(r"Hardware:\s*(\S+),", output)
        if m:
            result["model"] = m.group(1)
    elif is_asa:
        # "Hardware:   ASA5525-X, 8192 MB RAM"
        m = re.search(r"Hardware:\s*(\S+),", output)
        if m:
            result["model"] = m.group(1)
    elif is_iosxr:
        # "cisco ASR-9006-AC () processor"
        m = re.search(r"[Cc]isco\s+([\w/-]+)\s+\(", output)
        if m:
            result["model"] = m.group(1)
    elif is_aireos:
        m = re.search(r"Model Number\.*\s+(\S+)", output)
        if m:
            result["model"] = m.group(1)
    else:
        # Cisco IOS/IOS-XE/NX-OS
        m = re.search(r"[Mm]odel\s+[Nn]umber\s*:\s*(\S+)", output)
        if m:
            result["model"] = m.group(1)
        else:
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

# Map detected vendor names to API vendor path segments.
# EOL and CVE databases may use different vendor strings.
_VENDOR_EOL_MAP = {
    "cisco": "cisco",
    "arista": "arista",
    "juniper": "juniper",
}
_VENDOR_CVE_MAP = {
    "cisco": "cisco",
    "arista": "arista networks",
    "juniper": "juniper networks",
}


def query_eol(api_url, api_key, vendor, model):
    """GET /api/v1/eol/{vendor}/{model} → EOL data dict or error string."""
    v = _VENDOR_EOL_MAP.get(vendor, vendor)
    return api_get(api_url, api_key,
                   f"/api/v1/eol/{quote(v, safe='')}/{quote(model, safe='')}")


def query_cve(api_url, api_key, vendor, model, os_version=None):
    """GET /api/v1/cve/{vendor}/{model}?os_version=... → CVE data dict or error string."""
    v = _VENDOR_CVE_MAP.get(vendor, vendor)
    params = {}
    if os_version and os_version != "Unknown":
        params["os_version"] = os_version
    return api_get(api_url, api_key,
                   f"/api/v1/cve/{quote(v, safe='')}/{quote(model, safe='')}",
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
        "vendor": "cisco",
        "model": "Unknown",
        "os_version": "Unknown",
        "status": "no_match",
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
        result["vendor"] = parsed["vendor"]
        result["model"] = parsed["model"]
        result["os_version"] = parsed["os_version"]

        # Fallback model from inventory
        if result["model"] == "Unknown":
            pid = parse_show_inventory(inv_out)
            if pid:
                result["model"] = pid
    except (OSError, paramiko.SSHException) as e:
        result["status"] = "error"
        result["error"] = str(e)
        return result

    # API calls (skip if model unknown)
    if result["model"] != "Unknown":
        result["eol"] = query_eol(api_url, api_key, result["vendor"], result["model"])
        # Juniper/Arista CVEs are indexed by OS name, not hardware model.
        # Don't pass os_version — their version-based index uses different formats.
        cve_model = result["model"]
        cve_version = result["os_version"]
        if result["vendor"] == "juniper":
            cve_model = "junos"
            cve_version = None
        elif result["vendor"] == "arista":
            cve_model = "eos"
            cve_version = None
        result["cve"] = query_cve(api_url, api_key, result["vendor"], cve_model, cve_version)
        if isinstance(result["eol"], dict):
            result["status"] = "found"
        elif isinstance(result["eol"], str):
            if result["eol"] == "Not Found":
                result["status"] = "no_match"
            else:
                result["status"] = "error"
                result["error"] = result["eol"]
        if isinstance(result["cve"], str) and result["status"] == "found":
            result["status"] = "error"
            result["error"] = result["cve"]

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
        # Prefer is_eol boolean (accounts for end-of-sale, not just last_support)
        if data.get("is_eol"):
            return "EOL"
        status = data.get("status", "Unknown")
        if status == "current":
            return "Active"
        if status == "warning":
            return "EOL Warning"
        if status == "eol":
            return "EOL"
        return status
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

def _display_condensed_summary(results, csv_file):
    """Show a grouped summary instead of per-device table (for >10 results)."""
    total = len(results)
    errors = sum(1 for r in results if r["error"])
    by_status = {"eol": 0, "active": 0, "other": 0, "error": 0}
    total_cves = 0
    by_model: dict[str, dict] = {}

    for r in results:
        eol_status = _extract_eol_status(r["eol"])
        cve_count = _extract_cve_count(r["cve"])
        total_cves += cve_count

        if r["error"]:
            by_status["error"] += 1
        elif eol_status.lower() == "eol":
            by_status["eol"] += 1
        elif eol_status.lower() == "active":
            by_status["active"] += 1
        else:
            by_status["other"] += 1

        key = r["model"] or "Unknown"
        if key not in by_model:
            by_model[key] = {"count": 0, "eol": 0, "cves": 0}
        by_model[key]["count"] += 1
        if eol_status.lower() == "eol":
            by_model[key]["eol"] += 1
        by_model[key]["cves"] += cve_count

    # --- Status breakdown ---
    status_table = Table(title="Network Audit Results", show_lines=False)
    status_table.add_column("Status")
    status_table.add_column("Devices", justify="right")
    if by_status["eol"]:
        status_table.add_row("[bold red]EOL[/bold red]", str(by_status["eol"]))
    if by_status["active"]:
        status_table.add_row("[green]Active[/green]", str(by_status["active"]))
    if by_status["other"]:
        status_table.add_row("[dim]Other[/dim]", str(by_status["other"]))
    if by_status["error"]:
        status_table.add_row("[red]Error[/red]", str(by_status["error"]))

    _display.console.print()
    _display.console.print(status_table)

    # --- Top issues (models with EOL or high CVEs) ---
    issues = {k: v for k, v in by_model.items() if v["eol"] > 0 or v["cves"] >= 5}
    if issues:
        issue_table = Table(title="Top Issues", show_lines=False)
        issue_table.add_column("Model", style="magenta")
        issue_table.add_column("Devices", justify="right")
        issue_table.add_column("EOL", justify="right")
        issue_table.add_column("CVEs", justify="right")
        for model, info in sorted(issues.items(), key=lambda x: (-x[1]["eol"], -x[1]["cves"])):
            eol_str = f"[bold red]{info['eol']}[/bold red]" if info["eol"] else "[dim]0[/dim]"
            cve_str = f"[bold red]{info['cves']}[/bold red]" if info["cves"] >= 5 else str(info["cves"])
            issue_table.add_row(model, str(info["count"]), eol_str, cve_str)
        _display.console.print()
        _display.console.print(issue_table)

    _display.console.print()
    summary = (
        f"[bold]Total devices:[/] {total}  |  "
        f"[bold red]Errors:[/] {errors}  |  "
        f"[bold red]EOL flagged:[/] {by_status['eol']}  |  "
        f"[bold red]CVEs:[/] {total_cves}"
    )
    if csv_file:
        summary += f"  |  [bold]CSV:[/] {csv_file}"
    else:
        summary += "  |  [dim]Use --json for full output[/dim]"
    _display.console.print(Panel(summary, title="Summary"))


def display_summary(results, csv_file):
    """Print a Rich summary table and footer stats."""
    if len(results) > 10:
        return _display_condensed_summary(results, csv_file)

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

    _display.console.print()
    _display.console.print(table)
    _display.console.print()
    summary = (
        f"[bold]Total devices:[/] {total}  |  "
        f"[bold red]Errors:[/] {errors}  |  "
        f"[bold red]EOL flagged:[/] {eol_flagged}"
    )
    if csv_file:
        summary += f"  |  [bold]CSV:[/] {csv_file}"
    _display.console.print(Panel(summary, title="Summary"))


# ---------------------------------------------------------------------------
# Subcommand entry point
# ---------------------------------------------------------------------------

def _build_json_results(results):
    """Build a JSON-serializable list from scan results."""
    output = []
    for r in results:
        output.append({
            "name": r["name"],
            "host": r["host"],
            "hostname": r["hostname"],
            "model": r["model"],
            "os_version": r["os_version"],
            "status": r["status"],
            "eol_status": _extract_eol_status(r["eol"]),
            "eol_details": _extract_eol_details(r["eol"]),
            "cve_count": _extract_cve_count(r["cve"]),
            "eol_raw": r["eol"] if isinstance(r["eol"], dict) else None,
            "cve_raw": r["cve"] if isinstance(r["cve"], (dict, list)) else None,
            "error": r["error"],
        })
    return output


def run(args):
    """Run the network collector subcommand."""
    # --json implies no Rich output and no CSV (clean stdout)
    if args.json:
        args.no_rich = True
        args.no_csv = True

    if args.json:
        from ..display import redirect_console_to_stderr
        redirect_console_to_stderr()
    elif args.no_rich:
        from ..display import quiet_console
        quiet_console()

    if not args.json:
        _display.console.print(Panel("[bold cyan]Network Audit Scan[/]\n[dim]Powered by network-audit.io[/]",
                            expand=False))

    api_url, api_key = load_config()
    if getattr(args, "dev", None):
        api_url = resolve_dev_url(args.dev)
    inventory = load_inventory(args.inventory)

    proto = "Telnet" if args.telnet else "SSH"
    password = getpass.getpass(f"{proto} password for {args.username}: ")

    results = []
    status_lines = []
    status_lock = threading.Lock()

    try:
        with Live(console=_display.console, refresh_per_second=4) as live:
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
        _display.console.print("\n[yellow]Scan cancelled by user[/]")
        return

    if not args.no_csv:
        csv_file = args.output or default_csv_path("network")
        export_csv(_build_csv_rows(results), FIELDNAMES, csv_file)
    else:
        csv_file = None

    if args.json:
        json.dump(_build_json_results(results), sys.stdout, indent=2)
        print()

    if not args.no_rich and not args.json:
        display_summary(results, csv_file)
