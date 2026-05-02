#!/usr/bin/env bash
# network-audit collector installer for Linux and macOS
# Usage: curl -LsSf https://network-audit.io/install.sh | sh
set -euo pipefail

REPO_URL="${NETWORK_AUDIT_REPO:-https://github.com/network-audit/network-audit-collector.git}"
INSTALL_DIR="${NETWORK_AUDIT_DIR:-$HOME/.local/share/network-audit}"
BIN_DIR="${NETWORK_AUDIT_BIN:-$HOME/.local/bin}"

info()  { printf '\033[1;34m==> %s\033[0m\n' "$*"; }
ok()    { printf '\033[1;32m==> %s\033[0m\n' "$*"; }
warn()  { printf '\033[1;33m==> %s\033[0m\n' "$*"; }
err()   { printf '\033[1;31m==> %s\033[0m\n' "$*" >&2; exit 1; }

# --- Check prerequisites ---
command -v git >/dev/null 2>&1 || err "git is required but not found. Install it first."

# --- Install uv if not present ---
if ! command -v uv >/dev/null 2>&1; then
    info "Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    # Source the env so uv is available in this session
    export PATH="$HOME/.local/bin:$PATH"
    if ! command -v uv >/dev/null 2>&1; then
        err "uv install succeeded but 'uv' not found in PATH. Restart your shell and re-run."
    fi
    ok "uv installed"
else
    ok "uv found at $(command -v uv)"
fi

# --- Download or update the collector ---
if [ -d "$INSTALL_DIR/.git" ]; then
    info "Updating existing installation..."
    git -C "$INSTALL_DIR" pull --ff-only
    ok "Updated to latest"
else
    if [ -d "$INSTALL_DIR" ]; then
        warn "$INSTALL_DIR exists but is not a git repo — backing up"
        mv "$INSTALL_DIR" "${INSTALL_DIR}.bak.$(date +%s)"
    fi
    info "Cloning collector to $INSTALL_DIR..."
    git clone "$REPO_URL" "$INSTALL_DIR"
    ok "Cloned"
fi

# --- Sync dependencies (uv downloads Python if needed) ---
info "Installing dependencies..."
cd "$INSTALL_DIR"
uv sync --quiet
ok "Dependencies installed"

# --- Create wrapper script ---
mkdir -p "$BIN_DIR"
cat > "$BIN_DIR/network-audit" << 'WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
INSTALL_DIR="${NETWORK_AUDIT_DIR:-$HOME/.local/share/network-audit}"
exec uv run --project "$INSTALL_DIR" python "$INSTALL_DIR/main.py" "$@"
WRAPPER
chmod +x "$BIN_DIR/network-audit"
ok "Installed 'network-audit' to $BIN_DIR/network-audit"

# --- Check PATH ---
case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *)
        warn "$BIN_DIR is not in your PATH."
        echo "    Add this to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
        echo ""
        echo "    export PATH=\"$BIN_DIR:\$PATH\""
        echo ""
        ;;
esac

# --- API key setup ---
echo ""
info "API Key Setup"
if [ -f "$HOME/.config/network-audit-collector/.env" ]; then
    ok "Existing API key found in ~/.config/network-audit-collector/.env"
elif [ -t 0 ]; then
    # Interactive terminal — offer to import now
    echo "    You need an API key from https://network-audit.io"
    echo ""
    printf "    Import now? [y/N]: "
    read -r answer
    if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
        cd "$INSTALL_DIR"
        uv run python main.py account --import-key
    else
        echo "    Run 'network-audit account --import-key' later to configure."
    fi
else
    # Non-interactive (piped install) — skip prompt
    echo "    Run 'network-audit account --import-key' to configure your API key."
fi

# --- Done ---
echo ""
ok "Installation complete!"
echo ""
echo "    Quick start:"
echo "      network-audit                          # interactive mode"
echo "      network-audit linux -i hosts.json      # scan Linux hosts"
echo "      network-audit status                   # check API health"
echo "      network-audit account                  # check credit balance"
echo "      network-audit --help                   # all options"
echo ""
echo "    Manage your account at https://network-audit.io"
echo ""
