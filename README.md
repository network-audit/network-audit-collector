# network-audit

CLI tool for collecting device info across your network and checking EOL/CVE status via [network-audit.io](https://network-audit.io).

## Install

Requires [uv](https://docs.astral.sh/uv/).

```bash
git clone <repo-url> && cd network-collector
cp inv.json.example inv.json   # add your devices
cp .env.example .env           # add your API credentials
```

## Usage (unified CLI)

```bash
# Cisco devices — SSH
python main.py network -u admin --ask-pass -i inv.json

# Cisco devices — Telnet
python main.py network -u admin --ask-pass --telnet -i inv.json

# Linux hosts — key auth
python main.py linux -u bl -i linux-inv.json

# Linux hosts — password auth
python main.py linux -u bl --ask-pass -i linux-inv.json

# Check API account status
python main.py account
```

Or with uv:

```bash
uv run python main.py network -u admin --ask-pass -i inv.json
uv run python main.py linux -u bl -i linux-inv.json
uv run python main.py account
```

### Subcommands

| Command   | Description                          |
|-----------|--------------------------------------|
| `network` | Scan Cisco devices (SSH/Telnet)      |
| `linux`   | Scan Linux hosts (SSH)               |
| `account` | Check network-audit.io account info  |

Run `python main.py <command> --help` for full flag details.

## Configuration

### `.env`

```
api_url=https://api.network-audit.io
api_key=your_api_key_here
```

### Inventory files

JSON arrays of objects with a `host` key and optional `name`:

```json
[
  {"host": "192.168.1.1", "name": "core-switch"},
  {"host": "192.168.1.2", "name": "edge-router"}
]
```

## Example Output

```
$ python main.py linux -u bl -i linux-inv.json
╭─────────────────────────────╮
│ Linux Audit Scan            │
│ Powered by network-audit.io │
╰─────────────────────────────╯
  Scanning hosts... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 12/12
✔ dns: Debian GNU/Linux 13 (trixie)
✔ vpn: Debian GNU/Linux 13 (trixie)
...

╭────────────────────────────────── Summary ───────────────────────────────────╮
│ Total hosts: 12  |  Errors: 0  |  EOL: 0  |  CSV: data/2026-03-02_linux.csv │
╰──────────────────────────────────────────────────────────────────────────────╯
```

Results are exported to CSV in the `data/` directory:

```csv
name,host,distro,version,codename,lts,eol_status,eol_date,days_until_eol,error
dns,10.6.6.100,debian,13,Trixie,False,current,2028-08-09,895,
vpn,10.6.6.101,debian,13,Trixie,False,current,2028-08-09,895,
monitoring,10.6.6.102,debian,13,Trixie,False,current,2028-08-09,895,
...
```

## Backward Compatibility

The standalone collector scripts still work:

```bash
python collector-network.py -u admin --ask-pass -i inv.json
python collector-linux.py -i linux-inv.json -u bl
python collector-account.py
```
