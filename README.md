# network-audit-collector

A CLI tool that scans your Cisco network devices and Linux hosts, then checks their EOL (End-of-Life) and CVE status against the [network-audit.io](https://network-audit.io) API.

Point it at an inventory file, give it credentials, and it will SSH (or Telnet) into each device, pull version info, and tell you what's end-of-life, what has known vulnerabilities, and what's approaching EOL. Results are displayed in a table and exported to CSV.

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

# Configure your API key (get one at https://network-audit.io)
cp .env.example .env
# Edit .env with your API key

# Create your inventory file
cp examples/linux-inv.json linux-inv.json
# Edit with your actual hosts

# Run it
uv run main.py linux -i linux-inv.json
```

## Usage

```bash
# Scan Cisco devices via SSH
uv run main.py network -u admin --ask-pass -i inv.json

# Scan Cisco devices via Telnet
uv run main.py network -u admin --ask-pass --telnet -i inv.json

# Scan Linux hosts (defaults to current user + key auth)
uv run main.py linux -i linux-inv.json

# Scan Linux hosts with password auth
uv run main.py linux -u admin --ask-pass -i linux-inv.json

# Check your API account status
uv run main.py account
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
│ Updated: 2026-03-11T01:18:13Z                                                │
╰──────────────────────────────────────────────────────────────────────────────╯
                          Planned Maintenance
┏━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Start                ┃ End                  ┃ Description            ┃
┡━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 2026-03-14T10:00:00Z │ 2026-03-14T11:00:00Z │ OS patching and reboot │
└──────────────────────┴──────────────────────┴────────────────────────┘
```

The exit code is 0 when operational and 1 for anything else, so you can gate your scans on it in scripts or cron:

```bash
uv run main.py status && uv run main.py linux -i hosts.csv
```

## Configuration

### API Credentials

Create a `.env` file with your [network-audit.io](https://network-audit.io) API key:

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

The `host` column/key is required. `name` is optional and defaults to the host value if not provided.

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
├────────────┼──────────────┼────────┼─────────┼──────────────┼─────┼────────────┼────────────┼───────────┤
│ db-server  │ 192.168.1.11 │ debian │ 12      │ Bookworm     │ No  │ Warning    │ 2026-06-10 │        91 │
├────────────┼──────────────┼────────┼─────────┼──────────────┼─────┼────────────┼────────────┼───────────┤
│ legacy-app │ 192.168.1.12 │ centos │ 7       │              │ No  │ EOL        │ 2020-08-06 │   EXPIRED │
└────────────┴──────────────┴────────┴─────────┴──────────────┴─────┴────────────┴────────────┴───────────┘

╭────────────────────────────────────────────────────── Summary ───────────────────────────────────────────────────────╮
│ Total hosts: 3  |  Errors: 0  |  EOL: 1  |  Warning: 1  |  CSV: data/2026-03-10_linux.csv                            │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
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
├─────────────┼─────────────┼──────────┼───────────────────┼────────────┼────────────┼──────┤
│ dist-switch │ 192.168.1.2 │ DIST-SW  │ WS-C2960X-48FPS-L │ 15.2(7)E7  │ Current    │ 24   │
├─────────────┼─────────────┼──────────┼───────────────────┼────────────┼────────────┼──────┤
│ edge-router │ 192.168.1.3 │ EDGE-RTR │ CISCO1921/K9      │ 15.7(3)M6  │ EOL        │ 21   │
└─────────────┴─────────────┴──────────┴───────────────────┴────────────┴────────────┴──────┘

╭────────────────────────────────────────────────────── Summary ───────────────────────────────────────────────────────╮
│ Total devices: 3  |  Errors: 0  |  EOL flagged: 2  |  CSV: data/2026-03-10_network.csv                               │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

### CSV Output

Results are automatically exported to timestamped CSV files in `data/`:

```csv
name,host,distro,version,codename,lts,eol_status,eol_date,days_until_eol,error
web-server,192.168.1.10,ubuntu,24.04,Noble Numbat,True,current,2029-05-31,1177,
db-server,192.168.1.11,debian,12,Bookworm,False,warning,2026-06-10,91,
legacy-app,192.168.1.12,centos,7,,False,eol,2020-08-06,-2043,
```

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

The API provides EOL lifecycle data for Cisco hardware and Linux distributions, plus CVE lookups for Cisco devices by model and IOS version.
