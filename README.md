# network-audit-collector

> If you run into any issues, please [open an issue](https://github.com/network-audit/network-audit-collector/issues), submit a PR, or send an email. The goal of this project is to help you get your time back.

A CLI tool that scans your Cisco network devices and Linux hosts, then checks their EOL (End-of-Life) and CVE status against the [network-audit.io](https://network-audit.io) API.

Point it at an inventory file, give it credentials, and it will connect to each device, pull version info, and tell you what's end-of-life, what has known vulnerabilities, and what's approaching EOL. Optionally collect system info (CPU, memory, disk, uptime) and installed package versions for CVE scanning. Results are displayed in a table, exported to CSV, or output as JSON.

## Why uv?

We recommend [uv](https://docs.astral.sh/uv/) to run this tool. With uv there's no virtual environment to manage, no pip install shenanigans. No `error: externally-managed-environment` on fresh hosts. Just clone and run:

```bash
uv run main.py linux -i linux-inv.json
```

That's it. uv reads `pyproject.toml`, installs what's needed in an isolated cache, and runs the script. No `pip install -r requirements.txt`, no `python -m venv`, no activating anything. It just works.

If you prefer traditional pip, that works too. uv is just faster and avoids the "it works on my machine" dependency headaches.

## Quick Start

```bash
git clone https://github.com/network-audit/network-audit-collector.git
cd network-audit-collector

# Import your API key (get one at https://network-audit.io)
uv run main.py account --import-key

# Create your inventory file
cp examples/linux-inv.json linux-inv.json
# Edit with your actual hosts

# Run it
uv run main.py linux -i linux-inv.json
```

## Usage

### Linux

```bash
# Basic scan (defaults to current user + key auth)
uv run main.py linux -i linux-inv.json

# With password auth
uv run main.py linux -u admin --ask-pass -i linux-inv.json

# Sysinfo only, no API calls (offline mode)
uv run main.py linux --sysinfo --no-api -c 10

# Parallel scan with delay between connections
uv run main.py linux -c 5 --delay 1
```

#### Linux flags

| Flag | Description |
|---|---|
| `--sysinfo` | Collect CPU, memory, disk, and uptime |
| `--no-api` | Skip all API calls (useful with `--sysinfo` for offline collection) |
| `--json` | Output results as JSON to stdout |
| `--no-csv` | Skip CSV file export |
| `--no-rich` | Suppress Rich console output |
| `--debug` | Print raw API responses |
| `-c N` | Max concurrent SSH connections (default: 1) |
| `--delay N` | Seconds between launching connections |

### Network (Cisco)

```bash
# Scan Cisco devices via SSH
uv run main.py network -u admin --ask-pass -i inv.json

# Scan Cisco devices via Telnet
uv run main.py network -u admin --ask-pass --telnet -i inv.json
```

### Account and Status

```bash
# Check your API account status
uv run main.py account

# Check API health
uv run main.py status

# JSON output for scripting
uv run main.py status --json
```

Run `uv run main.py <command> --help` for full flag details.

## API Status

Before running a scan you can check if the API is up:

```bash
uv run main.py status
```

```
╭────────────────────────────── network-audit.io ──────────────────────────────╮
│ Status: Operational                                                          │
│ API Key: Valid                                                               │
│ Updated: 2026-03-17T19:15:00Z                                                │
╰──────────────────────────────────────────────────────────────────────────────╯
```

### JSON output for scripting

Use `--json` to get machine-readable output with a `should_backoff` boolean that accounts for both platform health and active maintenance windows:

```bash
uv run main.py status --json
```

```json
{
  "healthy": true,
  "should_backoff": false,
  "status": "operational",
  "updated_at": "2026-03-17T19:15:00Z",
  "api_key_valid": true,
  "maintenance_active": false,
  "maintenance_starts_in_minutes": 5140,
  "planned_maintenance": [...]
}
```

### Cron examples

Simple pre-flight check — skip the scan if the API is down:

```bash
# /etc/cron.d/network-audit
0 6 * * 1  admin  cd /opt/network-audit-collector && uv run main.py status && uv run main.py linux -i hosts.json
```

With `--json` for more control — back off during maintenance or if the key is invalid:

```bash
#!/usr/bin/env bash
# /opt/network-audit-collector/scan.sh
set -euo pipefail
cd /opt/network-audit-collector

if uv run main.py status --json | jq -e '.should_backoff' > /dev/null; then
    echo "API unavailable or maintenance active — skipping scan"
    exit 0
fi

uv run main.py linux -i hosts.json
```

### Mid-scan maintenance awareness

Long-running scans automatically pause if a maintenance window starts during execution. In-flight device scans finish cleanly, then the tool waits until maintenance ends before resuming:

```
Scanning host-01... ✔
Scanning host-02... ✔
⏸  Maintenance in progress: Scheduled system patching and package updates
   Pausing scan — will resume automatically when maintenance ends (checking every 60s)...
▶  Maintenance ended — resuming scan
Scanning host-03... ✔
```

No flags needed — this behavior is built in to the `linux` and `network` commands.

## Configuration

### API Credentials

The recommended way to configure your API key:

```bash
uv run main.py account --import-key
```

This saves your credentials to `~/.config/network-audit-collector/.env` with `600` permissions, keeping them out of your project directory and version control.

The tool also supports a local `.env` file as a fallback:

```
api_url=https://api.network-audit.io
api_key=your_api_key_here
```

### Inventory Files

Inventory files can be JSON or CSV. Just use the right file extension and the tool figures it out.

**CSV** (probably what you already have from a spreadsheet export):

```csv
host,name
192.168.1.1,core-switch
192.168.1.2,edge-router
```

**JSON**:

```json
[
  {"host": "192.168.1.1", "name": "core-switch"},
  {"host": "192.168.1.2", "name": "edge-router"}
]
```

The `host` column/key is required. `name` is optional and defaults to the host value if not provided. Per-device username overrides are supported via the `username` key.

See `examples/` for sample inventory files in both formats.

## Example Output

These examples use real data from the network-audit.io API.

### Linux Scan

```
$ uv run main.py linux -i linux-inv.json
╭─────────────────────────────╮
│ Linux Audit Scan            │
│ Powered by network-audit.io │
╰─────────────────────────────╯

                                            Linux Audit Results
┏━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━┓
┃ Name       ┃ Host         ┃ Distro ┃ Version ┃ Codename     ┃ LTS ┃ EOL Status ┃ EOL Date   ┃ Days Left ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━┩
│ web-server │ 192.168.1.10 │ ubuntu │ 24.04   │ Noble Numbat │ Yes │ Current    │ 2029-05-31 │      1177 │
│ db-server  │ 192.168.1.11 │ debian │ 12      │ Bookworm     │ No  │ Warning    │ 2026-06-10 │        91 │
│ legacy-app │ 192.168.1.12 │ centos │ 7       │              │ No  │ EOL        │ 2020-08-06 │   EXPIRED │
└────────────┴──────────────┴────────┴─────────┴──────────────┴─────┴────────────┴────────────┴───────────┘

╭──────────────────────────────── Summary ─────────────────────────────────╮
│ Total hosts: 3  |  Errors: 0  |  EOL: 1  |  Warning: 1                  │
╰──────────────────────────────────────────────────────────────────────────╯
```

### Network Scan (Cisco)

```
$ uv run main.py network -u admin --ask-pass -i inv.json
╭─────────────────────────────╮
│ Network Audit Scan          │
│ Powered by network-audit.io │
╰─────────────────────────────╯

                                    Network Audit Results
┏━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━┓
┃ Name        ┃ Host        ┃ Hostname ┃ Model             ┃ OS Version ┃ EOL Status ┃ CVEs ┃
┡━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━┩
│ core-switch │ 192.168.1.1 │ CORE-SW  │ WS-C3750X-48T-S   │ 15.2(4)E10 │ EOL        │ 20   │
│ dist-switch │ 192.168.1.2 │ DIST-SW  │ WS-C2960X-48FPS-L │ 15.2(7)E7  │ Current    │ 24   │
│ edge-router │ 192.168.1.3 │ EDGE-RTR │ CISCO1921/K9      │ 15.7(3)M6  │ EOL        │ 21   │
└─────────────┴─────────────┴──────────┴───────────────────┴────────────┴────────────┴──────┘

╭──────────────────────────────── Summary ─────────────────────────────────╮
│ Total devices: 3  |  Errors: 0  |  EOL flagged: 2                        │
╰──────────────────────────────────────────────────────────────────────────╯
```

### CSV Output

Results are automatically exported to timestamped CSV files in `data/`:

```csv
name,host,distro,version,codename,lts,eol_status,eol_date,days_until_eol,error
web-server,192.168.1.10,ubuntu,24.04,Noble Numbat,True,current,2029-05-31,1177,
db-server,192.168.1.11,debian,12,Bookworm,False,warning,2026-06-10,91,
legacy-app,192.168.1.12,centos,7,,False,eol,2020-08-06,-2043,
```

## Grafana Dashboard

A sample Grafana dashboard is included in `examples/grafana-dashboard.json`. It visualizes fleet EOL status, CVE counts, memory/disk usage, and uptime from scan data.

To try it out:

1. Run a scan and save as JSON:
   ```bash
   uv run main.py linux --sysinfo --json --no-csv -c 5 > scan.json
   ```

2. Import `examples/grafana-dashboard.json` into Grafana with a TestData datasource using CSV content from `examples/grafana-sample-data.csv`.

Sample data is included in `examples/grafana-sample-data.json` and `examples/grafana-sample-data.csv`.

## Installing with pip

If you'd rather not use uv, traditional pip works fine:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py linux -i linux-inv.json
```

## API

This tool is a client for the [network-audit.io](https://network-audit.io) API. You'll need an API key to use it. Sign up at [network-audit.io](https://network-audit.io) to get one.

The API provides:
- EOL lifecycle data for Cisco hardware and Linux distributions
- CVE lookups for Cisco devices by model and IOS version

## Coming Soon

- Webhook management
- Windows Server and Desktop scanning
