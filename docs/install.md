# Install

One command. No Python required — the installer handles everything.

## Linux / macOS

```bash
curl -LsSf https://network-audit.io/install.sh | sh
```

## Windows

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://network-audit.io/install.ps1 | iex"
```

## What the installer does

1. Installs [uv](https://docs.astral.sh/uv/) if not present (uv manages Python for you — no system Python needed)
2. Clones the collector to `~/.local/share/network-audit` (Linux/macOS) or `%LOCALAPPDATA%\network-audit` (Windows)
3. Installs dependencies via `uv sync`
4. Creates a `network-audit` command in your PATH
5. Prompts you to import your API key

Re-running the installer updates to the latest version.

## Custom install locations

Override defaults with environment variables:

| Variable | Default (Linux/macOS) | Default (Windows) |
|---|---|---|
| `NETWORK_AUDIT_REPO` | GitHub repo URL | GitHub repo URL |
| `NETWORK_AUDIT_DIR` | `~/.local/share/network-audit` | `%LOCALAPPDATA%\network-audit` |
| `NETWORK_AUDIT_BIN` | `~/.local/bin` | `%LOCALAPPDATA%\network-audit\bin` |

Example — install to `/opt` for a shared server:

```bash
NETWORK_AUDIT_DIR=/opt/network-audit NETWORK_AUDIT_BIN=/usr/local/bin \
  curl -LsSf https://network-audit.io/install.sh | sh
```

## Self-hosted git server

If you host the collector on your own Gitea/GitLab instance:

```bash
NETWORK_AUDIT_REPO=https://git.company.com/infra/network-audit-collector.git \
  curl -LsSf https://network-audit.io/install.sh | sh
```

Or for Windows:

```powershell
$env:NETWORK_AUDIT_REPO = "https://git.company.com/infra/network-audit-collector.git"
irm https://network-audit.io/install.ps1 | iex
```

---

# First Run

## 1. Get an API key

Sign up at [network-audit.io](https://network-audit.io) and grab your API key.

## 2. Import your key

```bash
network-audit account --import-key
```

```
API URL [https://api.network-audit.io]:
API Key: ************************************

Credentials saved to ~/.config/network-audit-collector/.env (mode 600)
```

If you skipped this during install, run it now. Credentials are stored in `~/.config/network-audit-collector/.env` with restricted permissions, outside your project directory and version control.

## 3. Check the API

```bash
network-audit status
```

```json
{
  "healthy": true,
  "should_backoff": false,
  "status": "operational",
  "api_key_valid": true,
  ...
}
```

If `api_key_valid` is `true`, you're good.

## 4. Create an inventory file

Create a JSON or CSV file with your hosts:

```json
[
  {"host": "192.168.1.10", "name": "web-server"},
  {"host": "192.168.1.11", "name": "db-server"}
]
```

Or scan a single host without an inventory file — use interactive mode:

```bash
network-audit
```

```
Scan type (network/linux): linux
Inventory file or IP (linux-inv.json): 192.168.1.10
Username (bl):
Auth (key/password) [key]:
...
```

## 5. Run your first scan

```bash
# Linux — defaults to current user + SSH key auth
network-audit linux -i hosts.json

# Cisco network devices
network-audit network -u admin --ask-pass -i switches.json
```

You'll see a progress bar, then results in a Rich table with a CSV exported to `data/`.

## 6. Check your balance

```bash
network-audit account | jq .credits_remaining
```

---

# Updating

Re-run the install command — it pulls the latest changes:

```bash
curl -LsSf https://network-audit.io/install.sh | sh
```

Or manually:

```bash
cd ~/.local/share/network-audit
git pull
uv sync
```

# Uninstall

```bash
rm -rf ~/.local/share/network-audit
rm ~/.local/bin/network-audit
# Optionally remove config:
rm -rf ~/.config/network-audit-collector
```

Windows:

```powershell
Remove-Item -Recurse "$env:LOCALAPPDATA\network-audit"
# Optionally remove config:
Remove-Item -Recurse "$env:USERPROFILE\.config\network-audit-collector"
```
