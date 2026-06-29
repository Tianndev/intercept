#!/usr/bin/env bash
set -euo pipefail

CERT_PATH="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
MITMPROXY_DIR="$HOME/.mitmproxy"
ZSHRC="$HOME/.zshrc"
MARKER="# >>> intercept-proxy >>>"
END_MARKER="# <<< intercept-proxy <<<"

echo ""
echo "  INTERCEPT - Uninstall Script"
echo "  Developed by Tianndev"
echo ""
echo "  This will remove:"
echo "    • CA certificate from macOS System Keychain"
echo "    • ~/.mitmproxy directory and all certificate files"
echo "    • proxy-on / proxy-off aliases from ~/.zshrc"
echo "    • System proxy settings (Wi-Fi / Ethernet)"
echo ""

read -r -p "  Are you sure you want to uninstall everything? [y/N] " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo ""
    echo "  Cancelled."
    echo ""
    exit 0
fi

echo ""

# ─── Step 1: Remove CA Certificate from Keychain ────────────────────────────

remove_cert_keychain() {
    echo "[1/4] Removing CA certificate from macOS Keychain..."

    local removed=0

    # Remove from System keychain
    if security find-certificate -c "mitmproxy" /Library/Keychains/System.keychain &>/dev/null; then
        sudo security delete-certificate -c "mitmproxy" /Library/Keychains/System.keychain 2>/dev/null && removed=1
    fi

    # Remove from login keychain too (in case user installed manually there)
    if security find-certificate -c "mitmproxy" &>/dev/null; then
        security delete-certificate -c "mitmproxy" 2>/dev/null && removed=1
    fi

    if [ "$removed" -eq 1 ]; then
        echo "      Certificate removed from Keychain."
    else
        echo "      No mitmproxy certificate found in Keychain. Skipping."
    fi
}

# ─── Step 2: Remove ~/.mitmproxy directory ───────────────────────────────────

remove_mitmproxy_dir() {
    echo "[2/4] Removing ~/.mitmproxy directory..."

    if [ -d "$MITMPROXY_DIR" ]; then
        rm -rf "$MITMPROXY_DIR"
        echo "      Removed $MITMPROXY_DIR"
    else
        echo "      Directory $MITMPROXY_DIR not found. Skipping."
    fi
}

# ─── Step 3: Remove Shell Aliases ───────────────────────────────────────────

remove_shell_config() {
    echo "[3/4] Removing proxy aliases from $ZSHRC..."

    if grep -q "$MARKER" "$ZSHRC" 2>/dev/null; then
        sed -i '' "/$MARKER/,/$END_MARKER/d" "$ZSHRC"
        # Remove any leftover blank lines at end of file
        sed -i '' -e '${/^$/d;}' "$ZSHRC"
        echo "      Aliases removed from $ZSHRC"
    else
        echo "      No intercept aliases found in $ZSHRC. Skipping."
    fi
}

# ─── Step 4: Disable System Proxy ───────────────────────────────────────────

disable_system_proxy() {
    echo "[4/4] Disabling macOS system proxy settings..."

    # Try common network service names
    local services=("Wi-Fi" "Ethernet" "USB 10/100/1000 LAN")

    for service in "${services[@]}"; do
        if networksetup -listallnetworkservices 2>/dev/null | grep -qF "$service"; then
            networksetup -setwebproxystate "$service" off 2>/dev/null || true
            networksetup -setsecurewebproxystate "$service" off 2>/dev/null || true
            echo "      Proxy disabled for: $service"
        fi
    done

    # Also unset env vars in current session
    unset http_proxy https_proxy SSL_CERT_FILE REQUESTS_CA_BUNDLE 2>/dev/null || true

    echo "      System proxy settings cleared."
}

# ─── Main ────────────────────────────────────────────────────────────────────

main() {
    remove_cert_keychain
    remove_mitmproxy_dir
    remove_shell_config
    disable_system_proxy

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Uninstall complete. All intercept-related data removed."
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "  Reload your shell to apply alias removal:"
    echo "    source ~/.zshrc"
    echo ""
    echo "  To fully remove the tool itself:"
    echo "    pip uninstall tian-intercept"
    echo ""
}

main
