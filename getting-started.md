# Getting Started

The network-audit collector is a purpose-built wrapper around several standard Python libraries to make connecting to Linux hosts and network appliances seamless — without requiring you to send confidential company information such as config files or network inventories. The only data sent to the API are the OS version (Linux/Network) and the chassis/model for network gear.

After installation, you can run `--help` at any time for all available options. The CLI is designed to be flexible for cronjobs and automation while still being easy to use interactively.

## Installation

```bash
git clone https://github.com/network-audit/network-audit-collector.git
cd network-audit-collector
```

We recommend [uv](https://docs.astral.sh/uv/) — no virtual environment to manage, no pip shenanigans:

```bash
uv run main.py --help
```

If you prefer pip:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py --help
```

## Import Your API Key

Sign up at [network-audit.io](https://network-audit.io) to get an API key, then import it:

```bash
uv run main.py account --import-key
```

Credentials are saved to `~/.config/network-audit-collector/.env` with `600` permissions — out of your project directory and version control.

## CLI Overview

```
$ uv run main.py --help
usage: main.py [-h] [--version] {network,linux,account,status} ...

Network Audit Collector - unified CLI for network-audit.io

positional arguments:
  {network,linux,account,status}
    network             Scan Cisco network devices (SSH/Telnet)
    linux               Scan Linux hosts (SSH)
    account             Check network-audit.io account status
    status              Check network-audit.io API status (for scripting/cron)

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
```

## Interactive Mode

Run the collector with no arguments for a guided menu — no flags to remember:

```
$ uv run main.py
╭─────────────────────────────╮
│ Network Audit Collector     │
│ Powered by network-audit.io │
╰─────────────────────────────╯
Scan type (network/linux): linux
Inventory file or IP (linux-inv.json):
Username (bl):
Auth (key/password) [key]:
Collect sysinfo? [y/n] (n):
Concurrent connections (1): 5
Timeout (seconds) (10):
Output (rich/json) [rich]:
```

You can also pass a single IP instead of an inventory file — the collector handles it automatically.

## Inventory Files

Inventory files can be JSON or CSV. The `host` field is required; `name` is optional.

**JSON:**

```json
[
  {"host": "192.168.1.10", "name": "web-server"},
  {"host": "192.168.1.11", "name": "db-server"}
]
```

**CSV:**

```csv
host,name
192.168.1.10,web-server
192.168.1.11,db-server
```

See the `examples/` directory for sample inventory files.

## Running Scans

### Linux

```bash
# Interactive defaults: current user, SSH key auth
uv run main.py linux -i linux-inv.json

# Password auth, 5 concurrent connections
uv run main.py linux -u admin --ask-pass -i linux-inv.json -c 5

# Collect sysinfo (CPU, memory, disk, uptime)
uv run main.py linux --sysinfo -i linux-inv.json

# JSON output for scripting (no CSV, no Rich)
uv run main.py linux -i linux-inv.json --json
```

### Network (Cisco)

```bash
# SSH (default)
uv run main.py network -u admin --ask-pass -i inv.json

# Telnet
uv run main.py network -u admin --ask-pass --telnet -i inv.json
```

## Output Modes

By default, scans display a Rich table in the terminal and export a CSV to `data/`. For larger fleets (>10 devices), the display automatically switches to a condensed summary grouped by status — full details are still in the CSV.

| Flag | Behavior |
|------|----------|
| *(none)* | Rich table + CSV export |
| `--json` | JSON to stdout (no CSV, no Rich) |
| `--no-csv` | Rich table only, skip CSV |

`--json` is self-contained — you never need `--json --no-csv --no-rich`.

## Account Management

```
$ uv run main.py account --help
usage: main.py account [-h] [--account] [--import-key] [--api-key [KEY]]
                       [--json] [--rich]

options:
  -h, --help       show this help message and exit
  --account        Show account number
  --import-key     Import API credentials to ~/.config
  --api-key [KEY]  Show current API key, or set a new one
  --json           Output as JSON (default)
  --rich           Show Rich table instead of JSON
```

Check your credit balance:

```bash
$ uv run main.py account | jq .credits_remaining
876
```

## Platform Status

The `status` command returns JSON by default so it can be fed into your scripts. Use it to check platform health and whether a maintenance window is active (typically Saturday morning US Eastern).

```json
$ uv run main.py status
{
  "healthy": true,
  "should_backoff": false,
  "status": "operational",
  "updated_at": "2026-03-29T15:09:31Z",
  "api_key_valid": true,
  "maintenance_active": false,
  "maintenance_starts_in_minutes": null,
  "planned_maintenance": []
}
```

For a human-readable view: `uv run main.py status --rich`

## Automation and Cron

### Pre-flight check

Skip the scan if the API is down or in maintenance:

```bash
#!/usr/bin/env bash
set -euo pipefail
cd /opt/network-audit-collector

if uv run main.py status | jq -e '.should_backoff' > /dev/null; then
    echo "API unavailable or maintenance active — skipping scan"
    exit 0
fi

uv run main.py linux -i hosts.json --json > /var/log/network-audit/weekly.json
```

### Credit balance alerting

Using your internal email or alerting (webhook, etc.), ping your team when the balance gets low:

```bash
balance=$(uv run main.py account | jq .credits_remaining)
if [ "$balance" -lt 100 ]; then
  echo "Low credits: $balance" | mail -s "network-audit alert" ops@company.com
  exit 1
fi
uv run main.py linux -i fleet.json --json > /var/log/network-audit/weekly.json
```

Alternatively, check the size of your fleet and alert if you don't have enough credits for the next few runs:

```bash
devices=$(jq length fleet.json)
cost_per_run=$((devices * 2))
balance=$(uv run main.py account | jq .credits_remaining)
runs_remaining=$((balance / cost_per_run))

if [ "$runs_remaining" -lt 5 ]; then
  echo "Only $runs_remaining scans left ($balance credits, $cost_per_run per run)" \
    | mail -s "network-audit: reload soon" ops@company.com
fi
```

### Mid-scan maintenance awareness

Long-running scans automatically pause if a maintenance window starts during execution. In-flight device connections finish cleanly, then the tool waits until maintenance ends before resuming. No flags needed — this is built in.

```
Scanning host-01... ✔
Scanning host-02... ✔
⏸  Maintenance in progress: Scheduled system patching and package updates
   Pausing scan — will resume automatically when maintenance ends (checking every 60s)...
▶  Maintenance ended — resuming scan
Scanning host-03... ✔
```

## Coming Soon

- Webhook management
- Windows Server and Desktop scanning
