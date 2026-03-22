"""Windows host collector — WinRM (default) or SSH, parse OS info, check EOL via network-audit.io."""

import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote

import paramiko
import winrm

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
# PowerShell command (shared by both transports)
# ---------------------------------------------------------------------------

_PS_SCRIPT = (
    "$os = Get-CimInstance Win32_OperatingSystem;"
    "Write-Output \"Caption=$($os.Caption)\";"
    "Write-Output \"Version=$($os.Version)\";"
    "Write-Output \"BuildNumber=$($os.BuildNumber)\";"
    "try { $rv = (Get-ItemProperty"
    " 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').DisplayVersion;"
    " Write-Output \"DisplayVersion=$rv\" } catch {};"
    "try {"
    " $s = New-Object -ComObject Microsoft.Update.Session;"
    " $q = $s.CreateUpdateSearcher();"
    " $c = $q.GetTotalHistoryCount();"
    " if ($c -gt 0) {"
    "   $h = $q.QueryHistory(0, $c);"
    "   foreach ($u in $h) {"
    "     if ($u.Title -match 'KB(\\d+)' -and $u.Title -notmatch 'Defender') {"
    "       Write-Output \"LastPatchKB=KB$($Matches[1])\";"
    "       Write-Output \"LastPatchTitle=$($u.Title)\";"
    "       Write-Output \"LastPatchDate=$($u.Date.ToString('yyyy-MM-dd'))\";"
    "       break"
    "     }"
    "   }"
    " }"
    "} catch {}"
)

# PowerShell snippet for system info (opt-in via --sysinfo).
_PS_SYSINFO = (
    "$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1;"
    "Write-Output \"SYSINFO_CPU=$($cpu.Name)\";"
    "Write-Output \"SYSINFO_CORES=$($cpu.NumberOfLogicalProcessors)\";"
    "$mem = Get-CimInstance Win32_OperatingSystem;"
    "$totalMB = [math]::Round($mem.TotalVisibleMemorySize / 1024);"
    "$freeMB = [math]::Round($mem.FreePhysicalMemory / 1024);"
    "$usedMB = $totalMB - $freeMB;"
    "Write-Output \"SYSINFO_MEM_TOTAL_MB=$totalMB\";"
    "Write-Output \"SYSINFO_MEM_USED_MB=$usedMB\";"
    "$disk = Get-CimInstance Win32_LogicalDisk -Filter \"DeviceID='C:'\";"
    "$dtMB = [math]::Round($disk.Size / 1MB);"
    "$duMB = [math]::Round(($disk.Size - $disk.FreeSpace) / 1MB);"
    "Write-Output \"SYSINFO_DISK_TOTAL_MB=$dtMB\";"
    "Write-Output \"SYSINFO_DISK_USED_MB=$duMB\";"
    "$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime;"
    "$up = (Get-Date) - $boot;"
    "Write-Output \"SYSINFO_UPTIME_SECS=$([math]::Floor($up.TotalSeconds))\""
)


# ---------------------------------------------------------------------------
# WinRM / SSH helpers
# ---------------------------------------------------------------------------

def _make_winrm_session(host, username, password, timeout, use_https=False, use_ntlm=False):
    """Create a WinRM session."""
    scheme = "https" if use_https else "http"
    port = "5986" if use_https else "5985"
    return winrm.Session(
        f"{scheme}://{host}:{port}/wsman",
        auth=(username, password),
        transport="ntlm" if use_ntlm else "basic",
        server_cert_validation="ignore",
        operation_timeout_sec=timeout,
        read_timeout_sec=timeout + 10,
    )


def _run_ps_winrm(session, script):
    """Run a PowerShell script via WinRM and return stdout."""
    result = session.run_ps(script)
    if result.status_code != 0:
        stderr = result.std_err.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"WinRM PowerShell error: {stderr}")
    return result.std_out.decode("utf-8", errors="replace")


def _run_ps_ssh(client, script, timeout):
    """Run a PowerShell script via SSH and return stdout."""
    cmd = f"powershell -NoProfile -Command \"{script}\""
    _, stdout, _ = client.exec_command(cmd, timeout=timeout)
    return stdout.read().decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# WinRM Collection (default)
# ---------------------------------------------------------------------------

def winrm_collect(host, username, password, timeout, use_https=False,
                  use_ntlm=False, check_sysinfo=False):
    """Connect to a Windows host via WinRM and return parsed OS info."""
    session = _make_winrm_session(host, username, password, timeout,
                                  use_https=use_https, use_ntlm=use_ntlm)
    output = _run_ps_winrm(session, _PS_SCRIPT)
    if check_sysinfo:
        output += "\n" + _run_ps_winrm(session, _PS_SYSINFO)
    return parse_win_output(output)


# ---------------------------------------------------------------------------
# SSH Collection (--ssh fallback)
# ---------------------------------------------------------------------------

def ssh_collect(host, username, password, timeout, check_sysinfo=False):
    """SSH into a Windows host and return parsed OS info."""
    client = ssh_connect(host, username, password, timeout, use_keys=not password)
    try:
        output = _run_ps_ssh(client, _PS_SCRIPT, timeout)
        if check_sysinfo:
            output += "\n" + _run_ps_ssh(client, _PS_SYSINFO, timeout)
        return parse_win_output(output)
    finally:
        client.close()


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

# Edition → version slug suffix mapping.
# No suffix = consumer/default release (Pro, Home, etc.).
_EDITION_SUFFIX = {
    "enterprise":              "-e",
    "enterprise ltsc":         "-e",
    "enterprise ltsb":         "-e",
    "enterprise n":            "-e",
    "iot enterprise":          "-iot",
    "iot enterprise ltsc":     "-iot",
    "iot":                     "-iot",
}

# Server display versions that indicate SAC (Semi-Annual Channel).
_SERVER_SAC_VERSIONS = {"1709", "1803", "1809", "1903", "1909", "2004", "20h2"}

# Server display versions that indicate AC (Annual Channel).
_SERVER_AC_VERSIONS = {"23h2"}


def parse_win_output(output):
    """Parse PowerShell output → {product, version, build, pretty_name, edition,
    product_slug, version_slug}.

    Extracts the Windows product family and edition from Caption, the feature-update
    version from DisplayVersion, and computes API-compatible slugs.

    Slug examples:
        product_slug='windows',        version_slug='10-22h2'
        product_slug='windows',        version_slug='11-26h1-e'
        product_slug='windows-server', version_slug='2022-ltsc'
    """
    result = {
        "product": "Unknown", "version": "Unknown", "build": "",
        "pretty_name": "Unknown", "edition": "",
        "product_slug": "unknown", "version_slug": "unknown",
        "last_patch_kb": "", "last_patch_title": "", "last_patch_date": "",
        "sysinfo": None,
    }

    fields = {}
    for line in output.strip().splitlines():
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        fields[key.strip()] = val.strip()

    caption = fields.get("Caption", "")
    if caption:
        result["pretty_name"] = caption
        product, edition = _parse_caption(caption)
        result["product"] = product
        result["edition"] = edition

    display_ver = fields.get("DisplayVersion", "")
    if display_ver:
        result["version"] = display_ver
    elif fields.get("BuildNumber"):
        result["version"] = fields["BuildNumber"]

    result["build"] = fields.get("BuildNumber", "")
    result["last_patch_kb"] = fields.get("LastPatchKB", "")
    result["last_patch_title"] = fields.get("LastPatchTitle", "")
    result["last_patch_date"] = fields.get("LastPatchDate", "")

    # Build API slugs
    result["product_slug"] = _product_slug(result["product"])
    result["version_slug"] = _version_slug(
        result["product"], result["version"], result["edition"],
    )

    # Sysinfo (only present when --sysinfo was used)
    if "SYSINFO_CPU" in fields:
        uptime_secs = int(fields.get("SYSINFO_UPTIME_SECS", 0) or 0)
        result["sysinfo"] = {
            "cpu": fields.get("SYSINFO_CPU", ""),
            "cores": int(fields.get("SYSINFO_CORES", 0) or 0),
            "memory_total_mb": int(fields.get("SYSINFO_MEM_TOTAL_MB", 0) or 0),
            "memory_used_mb": int(fields.get("SYSINFO_MEM_USED_MB", 0) or 0),
            "disk_total_mb": int(fields.get("SYSINFO_DISK_TOTAL_MB", 0) or 0),
            "disk_used_mb": int(fields.get("SYSINFO_DISK_USED_MB", 0) or 0),
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


def _parse_caption(caption):
    """Parse Caption into (product, edition).

    Examples:
        'Microsoft Windows 10 Pro'                   → ('Windows 10', 'Pro')
        'Microsoft Windows 11 Enterprise'             → ('Windows 11', 'Enterprise')
        'Microsoft Windows Server 2022 Standard'      → ('Windows Server 2022', 'Standard')
        'Microsoft Windows Server 2019 Datacenter'    → ('Windows Server 2019', 'Datacenter')
    """
    name = caption.replace("Microsoft ", "").strip()

    if "Windows Server" in name:
        parts = name.split()
        for i, p in enumerate(parts):
            if p == "Server" and i + 1 < len(parts):
                year = parts[i + 1]
                product = f"Windows Server {year}"
                edition = " ".join(parts[i + 2:])
                return product, edition
        return name, ""

    if "Windows" in name:
        parts = name.split()
        for i, p in enumerate(parts):
            if p == "Windows" and i + 1 < len(parts):
                ver = parts[i + 1]
                if ver.isdigit() or ver in ("XP", "Vista"):
                    product = f"Windows {ver}"
                    edition = " ".join(parts[i + 2:])
                    return product, edition
        return "Windows", ""

    return name, ""


def _product_slug(product):
    """Map human-readable product name to API product slug.

    Examples:
        'Windows 10'          → 'windows'
        'Windows 11'          → 'windows'
        'Windows Server 2022' → 'windows-server'
    """
    if "Server" in product:
        return "windows-server"
    if "Windows" in product:
        return "windows"
    return "unknown"


def _version_slug(product, version, edition):
    """Build API version slug from product, display version, and edition.

    Desktop Windows (product_slug='windows'):
        ('Windows 10', '22H2', 'Pro')              → '10-22h2'
        ('Windows 11', '26H1', 'Enterprise')       → '11-26h1-e'
        ('Windows 10', '21H2', 'IoT Enterprise')   → '10-21h2-iot'

    Windows Server (product_slug='windows-server'):
        ('Windows Server 2022', '...', 'Standard')    → '2022-ltsc'
        ('Windows Server 2022', '23H2', 'Standard')   → '23h2-ac'
        ('Windows Server 2019', '1809', 'Datacenter') → '1809-sac'
    """
    ver_lower = version.lower()
    ed_lower = edition.lower().strip()

    if "Server" in product:
        if ver_lower in _SERVER_SAC_VERSIONS:
            return f"{ver_lower}-sac"
        if ver_lower in _SERVER_AC_VERSIONS:
            return f"{ver_lower}-ac"
        # Default: LTSC keyed by year from product name
        year = product.split()[-1]
        return f"{year}-ltsc"

    # Desktop: extract major version number (10 or 11)
    major = ""
    for p in product.split():
        if p.isdigit():
            major = p
            break

    if not major:
        return ver_lower

    # Look up edition suffix; no match = consumer/default (no suffix)
    suffix = _EDITION_SUFFIX.get(ed_lower, "")

    return f"{major}-{ver_lower}{suffix}"


# ---------------------------------------------------------------------------
# API Queries
# ---------------------------------------------------------------------------

def query_windows_eol(api_url, api_key, product_slug, version_slug):
    """GET /api/v1/windows/{product_slug}/{version_slug} → release detail or error string."""
    path = f"/api/v1/windows/{quote(product_slug, safe='')}/{quote(version_slug, safe='')}"
    return api_get(api_url, api_key, path)


def query_windows_product(api_url, api_key, product_slug):
    """GET /api/v1/windows/{product_slug} → product overview or error string."""
    path = f"/api/v1/windows/{quote(product_slug, safe='')}"
    return api_get(api_url, api_key, path)


# ---------------------------------------------------------------------------
# Per-device orchestration
# ---------------------------------------------------------------------------

def scan_device(device, username, password, timeout, api_url, api_key,
                use_ssh=False, use_https=False, use_ntlm=False,
                check_sysinfo=False, no_api=False, debug=False):
    """Scan a single Windows host: collect OS info → API lookup. Returns result dict."""
    result = {
        "name": device["name"],
        "host": device["host"],
        "product": "Unknown",
        "version": "Unknown",
        "edition": "",
        "build": "",
        "pretty_name": "Unknown",
        "product_slug": "unknown",
        "version_slug": "unknown",
        "last_patch_kb": "",
        "last_patch_title": "",
        "last_patch_date": "",
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
        if use_ssh:
            parsed = ssh_collect(device["host"], username, password, timeout,
                                 check_sysinfo=check_sysinfo)
        else:
            parsed = winrm_collect(device["host"], username, password, timeout,
                                   use_https=use_https, use_ntlm=use_ntlm,
                                   check_sysinfo=check_sysinfo)
        result["product"] = parsed["product"]
        result["version"] = parsed["version"]
        result["edition"] = parsed["edition"]
        result["build"] = parsed["build"]
        result["pretty_name"] = parsed["pretty_name"]
        result["product_slug"] = parsed["product_slug"]
        result["version_slug"] = parsed["version_slug"]
        result["last_patch_kb"] = parsed["last_patch_kb"]
        result["last_patch_title"] = parsed["last_patch_title"]
        result["last_patch_date"] = parsed["last_patch_date"]
        result["sysinfo"] = parsed["sysinfo"]
    except (OSError, paramiko.SSHException, RuntimeError, winrm.exceptions.WinRMError,
            winrm.exceptions.WinRMTransportError) as e:
        result["error"] = str(e)
        return result

    # API call
    if not no_api and result["product_slug"] != "unknown" and result["version_slug"] != "unknown":
        api_data = query_windows_eol(api_url, api_key, result["product_slug"], result["version_slug"])
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
        elif isinstance(api_data, str):
            result["eol_status"] = api_data

    return result


# ---------------------------------------------------------------------------
# CSV Export
# ---------------------------------------------------------------------------

FIELDNAMES = ["name", "host", "product", "version", "edition", "build",
              "product_slug", "version_slug", "last_patch_kb", "last_patch_date",
              "eol_status", "eol_date", "days_until_eol", "error"]


def _build_csv_rows(results):
    rows = []
    for r in results:
        rows.append({
            "name": r["name"],
            "host": r["host"],
            "product": r["product"],
            "version": r["version"],
            "edition": r["edition"] or "",
            "build": r["build"],
            "product_slug": r["product_slug"],
            "version_slug": r["version_slug"],
            "last_patch_kb": r["last_patch_kb"] or "",
            "last_patch_date": r["last_patch_date"] or "",
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
    table = Table(title="Windows Audit Results", show_lines=False)
    table.add_column("Name", style="cyan")
    table.add_column("Host", style="dim")
    table.add_column("Product", style="magenta")
    table.add_column("Version", style="blue")
    table.add_column("Build", style="dim")
    table.add_column("Last Patch")
    table.add_column("Patch Date", style="dim")
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

        if r["error"]:
            errors += 1

        table.add_row(
            r["name"], r["host"], r["product"], r["version"],
            r["build"], r["last_patch_kb"] or "", r["last_patch_date"] or "",
            eol_display, eol_date, days_display, r["error"] or "",
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
            "product": r["product"],
            "version": r["version"],
            "edition": r["edition"],
            "build": r["build"],
            "pretty_name": r["pretty_name"],
            "product_slug": r["product_slug"],
            "version_slug": r["version_slug"],
            "last_patch_kb": r["last_patch_kb"],
            "last_patch_title": r["last_patch_title"],
            "last_patch_date": r["last_patch_date"],
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
    """Run the windows collector subcommand."""
    if args.no_rich:
        from ..display import quiet_console
        quiet_console()
    elif args.json:
        from ..display import redirect_console_to_stderr
        redirect_console_to_stderr()

    transport = "SSH" if args.ssh else "WinRM"
    _display.console.print(Panel(
        f"[bold cyan]Windows Audit Scan[/] [dim]({transport})[/]\n[dim]Powered by network-audit.io[/]",
        expand=False))

    if args.no_api:
        api_url, api_key = "", ""
    else:
        api_url, api_key = load_config()
    inventory = load_inventory(args.inventory)

    password = None
    if args.ask_pass:
        import getpass
        password = getpass.getpass(f"{transport} password for {args.username}: ")

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
                                   use_ssh=args.ssh, use_https=args.https,
                                   use_ntlm=args.ntlm, check_sysinfo=args.sysinfo,
                                   no_api=args.no_api, debug=args.debug)

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
        csv_file = args.output or default_csv_path("windows")
        export_csv(_build_csv_rows(results), FIELDNAMES, csv_file)
    else:
        csv_file = None

    if args.json:
        json.dump(_build_json_results(results, include_sysinfo=args.sysinfo),
                  sys.stdout, indent=2)
        print()

    if not args.no_rich and not args.json:
        display_summary(results, csv_file)
