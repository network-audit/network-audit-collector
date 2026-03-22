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

def ssh_collect(host, username, password, timeout, check_patched=False,
                check_sysinfo=False):
    """SSH into a Linux host and return /etc/os-release content.

    Also checks for Proxmox VE by running pveversion, appending the result
    as a synthetic PVE_VERSION line so the parser can detect it.
    When check_patched is True, appends LAST_PATCHED with the date of the
    most recent package operation.
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

        # Last patched date (opt-in via --patched)
        if check_patched:
            _, patch_stdout, _ = client.exec_command(
                _LAST_PATCHED_CMD, timeout=timeout,
            )
            patch_date = patch_stdout.read().decode("utf-8", errors="replace").strip()
            if patch_date:
                os_release += f"\nLAST_PATCHED={patch_date}\n"

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


# Shell snippet that outputs the last package operation date as YYYY-MM-DD.
# Tries apt (Debian/Ubuntu), dnf/yum (RHEL/Fedora/Rocky), pacman (Arch),
# zypper (SUSE), and apk (Alpine) in order.
_LAST_PATCHED_CMD = (
    "("
    # apt: newest .list file timestamp in dpkg info
    "  if [ -d /var/lib/dpkg/info ]; then"
    "    find /var/lib/dpkg/info -name '*.list' -printf '%T@\\n' 2>/dev/null"
    "    | sort -rn | head -1 | xargs -I{} date -d @{} +%Y-%m-%d 2>/dev/null && exit;"
    "  fi;"
    # dnf/yum: most recent history entry (date is the first YYYY-MM-DD pattern on line 2)
    "  if command -v dnf >/dev/null 2>&1; then"
    "    dnf history list -q 2>/dev/null | awk 'NR==2{for(i=1;i<=NF;i++) if($i~/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/){print $i;exit}}' && exit;"
    "  fi;"
    # pacman: last installed/upgraded line in pacman.log
    "  if [ -f /var/log/pacman.log ]; then"
    "    grep -E '\\[ALPM\\] (installed|upgraded)' /var/log/pacman.log"
    "    | tail -1 | grep -oP '\\d{4}-\\d{2}-\\d{2}' && exit;"
    "  fi;"
    # zypper: last entry in zypper history
    "  if [ -f /var/log/zypp/history ]; then"
    "    tail -1 /var/log/zypp/history | cut -d'|' -f1 | cut -d' ' -f1 && exit;"
    "  fi;"
    # apk: modification time of the installed db
    "  if [ -f /lib/apk/db/installed ]; then"
    "    date -r /lib/apk/db/installed +%Y-%m-%d 2>/dev/null && exit;"
    "  fi"
    ") 2>/dev/null"
)

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
    "echo \"SYSINFO_UPTIME_SECS=$(cut -d. -f1 /proc/uptime 2>/dev/null)\";"
    # --- Package versions (for CVE lookups) ---
    "echo \"SYSINFO_KERNEL=$(uname -r 2>/dev/null | cut -d'-' -f1 | cut -d'+' -f1)\";"
    # ssh -V writes to stderr; extract just the version (e.g. 10.2p1)
    "echo \"SYSINFO_SSH=$(ssh -V 2>&1 | grep -oP 'OpenSSH_\\K[^ ,]+')\";"
    "echo \"SYSINFO_OPENSSL=$(openssl version 2>/dev/null | awk '{print $2}')\";"
    # glibc: ldd --version first line contains version
    "echo \"SYSINFO_GLIBC=$(ldd --version 2>&1 | head -1 | grep -oP '[0-9]+\\.[0-9]+')\";"
    "echo \"SYSINFO_SUDO=$(sudo --version 2>/dev/null | head -1 | grep -oP '[0-9]+\\.[0-9]+[.p0-9]*')\";"
    "echo \"SYSINFO_CURL=$(curl --version 2>/dev/null | head -1 | awk '{print $2}')\";"
    "echo \"SYSINFO_SYSTEMD=$(systemctl --version 2>/dev/null | head -1 | awk '{print $2}')\";"
    # Optional: only if installed
    "echo \"SYSINFO_PYTHON=$(python3 --version 2>/dev/null | awk '{print $2}')\";"
    "echo \"SYSINFO_NODE=$(node --version 2>/dev/null | tr -d v)\";"
    "echo \"SYSINFO_DOCKER=$(docker --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+')\";"
    # --- Distro package versions (includes backport/patch suffixes) ---
    "if command -v dpkg-query >/dev/null 2>&1; then"
    "  for p in curl openssh-server openssh-client openssl libssl3t64 libgnutls30t64 sudo systemd python3 nodejs docker-ce; do"
    "    v=$(dpkg-query -W -f '${Version}' \"$p\" 2>/dev/null) && echo \"SYSINFO_DEB_${p}=${v}\";"
    "  done;"
    "elif command -v rpm >/dev/null 2>&1; then"
    "  for p in curl openssh-server openssl sudo systemd python3 nodejs docker-ce; do"
    "    v=$(rpm -q --qf '%{VERSION}-%{RELEASE}' \"$p\" 2>/dev/null) && echo \"SYSINFO_RPM_${p}=${v}\";"
    "  done;"
    "elif command -v pacman >/dev/null 2>&1; then"
    "  for p in curl openssh openssl sudo systemd python nodejs docker; do"
    "    v=$(pacman -Q \"$p\" 2>/dev/null | awk '{print $2}') && echo \"SYSINFO_PAC_${p}=${v}\";"
    "  done;"
    "fi"
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
              "release": "", "last_patched": "", "sysinfo": None}

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
        if "VERSION_CODENAME" in fields:
            result["release"] = fields["VERSION_CODENAME"]

    if "LAST_PATCHED" in fields:
        result["last_patched"] = fields["LAST_PATCHED"]

    if "SYSINFO_CPU" in fields:
        total_mb = int(fields.get("SYSINFO_MEM_TOTAL_MB", 0) or 0)
        used_mb = int(fields.get("SYSINFO_MEM_USED_MB", 0) or 0)
        disk_total_mb = int(fields.get("SYSINFO_DISK_TOTAL_MB", 0) or 0)
        disk_used_mb = int(fields.get("SYSINFO_DISK_USED_MB", 0) or 0)
        uptime_secs = int(fields.get("SYSINFO_UPTIME_SECS", 0) or 0)

        # Package versions — only include if non-empty
        packages = {}
        for key, pkg in (
            ("SYSINFO_KERNEL", "kernel"),
            ("SYSINFO_SSH", "openssh"),
            ("SYSINFO_OPENSSL", "openssl"),
            ("SYSINFO_GLIBC", "glibc"),
            ("SYSINFO_SUDO", "sudo"),
            ("SYSINFO_CURL", "curl"),
            ("SYSINFO_SYSTEMD", "systemd"),
            ("SYSINFO_PYTHON", "python"),
            ("SYSINFO_NODE", "node"),
            ("SYSINFO_DOCKER", "docker"),
        ):
            val = fields.get(key, "").strip()
            if val:
                packages[pkg] = val

        # Distro package versions (dpkg/rpm/pacman — includes backport suffixes)
        distro_packages = {}
        for key, val in fields.items():
            if val and (key.startswith("SYSINFO_DEB_") or
                        key.startswith("SYSINFO_RPM_") or
                        key.startswith("SYSINFO_PAC_")):
                # Strip prefix to get package name
                pkg_name = key.split("_", 2)[2]
                distro_packages[pkg_name] = val

        result["sysinfo"] = {
            "cpu": fields.get("SYSINFO_CPU", ""),
            "cores": int(fields.get("SYSINFO_CORES", 0) or 0),
            "memory_total_mb": total_mb,
            "memory_used_mb": used_mb,
            "disk_total_mb": disk_total_mb,
            "disk_used_mb": disk_used_mb,
            "uptime": _format_uptime(uptime_secs),
            "uptime_secs": uptime_secs,
            "packages": packages,
            "distro_packages": distro_packages,
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
# CVE Queries
# ---------------------------------------------------------------------------

# Map collector package names → API cpe_product names.
_PACKAGE_TO_CPE = {
    "kernel": "linux_kernel",
    "openssh": "openssh",
    "openssl": "openssl",
    "glibc": "glibc",
    "sudo": "sudo",
    "curl": "curl",
    "systemd": "systemd",
    "python": "python",
    "node": "node.js",
    "docker": "docker",
}

# Distro security tracker URL patterns. {cve_id} is replaced at runtime.
_DISTRO_CVE_URL = {
    "debian": "https://security-tracker.debian.org/tracker/{cve_id}",
    "ubuntu": "https://ubuntu.com/security/{cve_id}",
    "rhel": "https://access.redhat.com/security/cve/{cve_id}",
    "fedora": "https://bodhi.fedoraproject.org/updates/?search={cve_id}",
    "suse": "https://www.suse.com/security/cve/{cve_id}",
    "rocky": "https://errata.rockylinux.org/?search={cve_id}",
    "almalinux": "https://errata.almalinux.org/?search={cve_id}",
}


def query_software_cves(api_url, api_key, packages, distro="", release=""):
    """Query the software CVE endpoint for each package version.

    Args:
        api_url: Base API URL.
        api_key: API key.
        packages: Dict of {package_name: version_string}.
        distro: Distro ID (e.g. 'debian', 'ubuntu') for backport-aware filtering.
        release: Distro release codename (e.g. 'trixie', 'bookworm').

    Returns:
        Dict of {package_name: {total, cves, ...}} for packages with CVEs,
        or {package_name: error_string} on failure.
    """
    results = {}
    for pkg, version in packages.items():
        cpe_product = _PACKAGE_TO_CPE.get(pkg)
        if not cpe_product or not version:
            continue
        params = {"version": version}
        if distro:
            params["distro"] = distro
        if release:
            params["release"] = release
        data = api_get(api_url, api_key,
                       f"/api/v1/software/cve/{quote(cpe_product, safe='')}",
                       params=params)
        if isinstance(data, dict):
            cve_data = data.get("data", data)
            total = cve_data.get("total", 0)
            if total > 0:
                cves = cve_data.get("cves", [])
                url_tpl = _DISTRO_CVE_URL.get(distro)
                if url_tpl:
                    for cve in cves:
                        cve["distro_url"] = url_tpl.format(cve_id=cve.get("cve_id", ""))
                results[pkg] = {
                    "total": total,
                    "cves": cves,
                }
        elif isinstance(data, str):
            results[pkg] = {"total": 0, "error": data}
    return results


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
                check_patched=False, check_sysinfo=False, check_cve=False,
                no_api=False, debug=False):
    """Scan a single Linux host: SSH → parse → API. Returns result dict."""
    result = {
        "name": device["name"],
        "host": device["host"],
        "distro": "Unknown",
        "version": "Unknown",
        "release": "",
        "pretty_name": "Unknown",
        "codename": "",
        "lts": False,
        "last_patched": "",
        "sysinfo": None,
        "software_cves": None,
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
                                 check_patched=check_patched,
                                 check_sysinfo=check_sysinfo)
        parsed = parse_os_release(os_release)
        result["distro"] = parsed["distro"]
        result["version"] = parsed["version"]
        result["pretty_name"] = parsed["pretty_name"]
        result["release"] = parsed["release"]
        result["last_patched"] = parsed["last_patched"]
        result["sysinfo"] = parsed["sysinfo"]
    except (OSError, paramiko.SSHException) as e:
        result["error"] = str(e)
        return result

    # Software CVE check
    if check_cve and not no_api and result["sysinfo"] and result["sysinfo"].get("packages"):
        cve_results = query_software_cves(api_url, api_key, result["sysinfo"]["packages"],
                                          distro=result["distro"], release=result["release"])
        if cve_results:
            result["software_cves"] = cve_results
            if debug:
                _display.console.print(Panel(
                    json.dumps(cve_results, indent=2),
                    title=f"[dim]DEBUG CVE results for {device['name']}[/dim]",
                ))

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

_FIELDNAMES_BASE = ["name", "host", "distro", "version", "codename", "lts",
                    "eol_status", "eol_date", "days_until_eol", "error"]

_FIELDNAMES_PATCHED = ["name", "host", "distro", "version", "codename", "lts",
                       "last_patched", "eol_status", "eol_date", "days_until_eol", "error"]


def _build_csv_rows(results, include_patched=False):
    rows = []
    for r in results:
        row = {
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
        }
        if include_patched:
            row["last_patched"] = r["last_patched"] or ""
        rows.append(row)
    return rows


# ---------------------------------------------------------------------------
# Rich Display
# ---------------------------------------------------------------------------

def display_summary(results, csv_file, show_patched=False):
    table = Table(title="Linux Audit Results", show_lines=False)
    table.add_column("Name", style="cyan")
    table.add_column("Host", style="dim")
    table.add_column("Distro", style="magenta")
    table.add_column("Version", style="blue")
    table.add_column("Codename", style="white")
    table.add_column("LTS", justify="center")
    if show_patched:
        table.add_column("Last Patched", style="dim")
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

        row = [r["name"], r["host"], r["distro"], r["version"],
               r["codename"], lts_display]
        if show_patched:
            row.append(r["last_patched"] or "")
        row.extend([eol_display, eol_date, days_display, r["error"] or ""])
        table.add_row(*row)

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

def _build_json_results(results, include_patched=False, include_sysinfo=False,
                        include_cve=False):
    """Build a JSON-serializable list from scan results."""
    output = []
    for r in results:
        entry = {
            "name": r["name"],
            "host": r["host"],
            "distro": r["distro"],
            "version": r["version"],
            "release": r["release"],
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
        if include_patched:
            entry["last_patched"] = r["last_patched"]
        if include_sysinfo or include_cve:
            entry["sysinfo"] = r["sysinfo"]
        if include_cve:
            entry["software_cves"] = r["software_cves"]
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
                                   check_patched=args.patched,
                                   check_sysinfo=args.sysinfo or args.cve,
                                   check_cve=args.cve, no_api=args.no_api,
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
        fieldnames = _FIELDNAMES_PATCHED if args.patched else _FIELDNAMES_BASE
        export_csv(_build_csv_rows(results, include_patched=args.patched), fieldnames, csv_file)
    else:
        csv_file = None

    if args.json:
        json.dump(_build_json_results(results, include_patched=args.patched,
                                     include_sysinfo=args.sysinfo or args.cve,
                                     include_cve=args.cve), sys.stdout, indent=2)
        print()

    if not args.no_rich and not args.json:
        display_summary(results, csv_file, show_patched=args.patched)
