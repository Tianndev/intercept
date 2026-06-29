#!/usr/bin/env bash
set -euo pipefail

CERT_PATH="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
ZSHRC="$HOME/.zshrc"
PROXY_HOST="127.0.0.1"
PROXY_PORT="8080"
MARKER="# >>> intercept-proxy >>>"
END_MARKER="# <<< intercept-proxy <<<"

echo ""
echo "  INTERCEPT - Setup Script"
echo "  Developed by Tianndev"
echo ""

# ─── Step 1: Generate Certificate ───────────────────────────────────────────

generate_cert() {
    echo "[1/3] Generating CA certificate..."

    if [ -f "$CERT_PATH" ]; then
        echo "      Certificate already exists at $CERT_PATH"
        return
    fi

    echo "      Starting proxy briefly to generate certificate..."

    if ! command -v intercept &> /dev/null; then
        echo "      Error: intercept not found in PATH."
        echo "      Run: source .venv/bin/activate first."
        exit 1
    fi

    tian-intercept start --quiet &
    PROXY_PID=$!
    sleep 4
    kill "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true

    if [ ! -f "$CERT_PATH" ]; then
        echo "      Error: certificate was not generated at $CERT_PATH"
        exit 1
    fi

    echo "      Certificate generated at $CERT_PATH"
}

# ─── Step 2: Install Certificate to macOS Keychain ──────────────────────────

install_cert() {
    echo "[2/3] Installing CA certificate to macOS System Keychain..."

    if security find-certificate -c "mitmproxy" /Library/Keychains/System.keychain &>/dev/null; then
        echo "      Certificate already installed in Keychain."
        return
    fi

    sudo security add-trusted-cert \
        -d \
        -r trustRoot \
        -k /Library/Keychains/System.keychain \
        "$CERT_PATH"

    echo "      Certificate installed and trusted."
}

# ─── Step 3: Configure Shell Aliases ────────────────────────────────────────

configure_shell() {
    echo "[3/3] Configuring shell aliases in $ZSHRC..."

    # Detect active network service (Wi-Fi or Ethernet)
    NETWORK_SERVICE=$(networksetup -listallnetworkservices 2>/dev/null \
        | grep -v "An asterisk" \
        | grep -E "^(Wi-Fi|Ethernet|USB 10/100/1000 LAN)$" \
        | head -n 1)

    if [ -z "$NETWORK_SERVICE" ]; then
        # Fallback: grab first non-disabled service
        NETWORK_SERVICE=$(networksetup -listallnetworkservices 2>/dev/null \
            | grep -v "An asterisk" \
            | grep -v "^\*" \
            | sed -n '2p')
    fi

    echo "      Detected network service: $NETWORK_SERVICE"

    # Remove old block if it exists
    if grep -q "$MARKER" "$ZSHRC" 2>/dev/null; then
        # Remove the old block
        sed -i '' "/$MARKER/,/$END_MARKER/d" "$ZSHRC"
        echo "      Updated existing shell configuration."
    fi

    cat >> "$ZSHRC" << EOF

$MARKER
# Intercept Proxy Shortcuts
_INTERCEPT_SERVICE="${NETWORK_SERVICE}"

proxy-on() {
    export http_proxy="http://${PROXY_HOST}:${PROXY_PORT}"
    export https_proxy="http://${PROXY_HOST}:${PROXY_PORT}"
    export SSL_CERT_FILE="${CERT_PATH}"
    export REQUESTS_CA_BUNDLE="${CERT_PATH}"
    networksetup -setwebproxy "\$_INTERCEPT_SERVICE" ${PROXY_HOST} ${PROXY_PORT} 2>/dev/null
    networksetup -setsecurewebproxy "\$_INTERCEPT_SERVICE" ${PROXY_HOST} ${PROXY_PORT} 2>/dev/null
    networksetup -setwebproxystate "\$_INTERCEPT_SERVICE" on 2>/dev/null
    networksetup -setsecurewebproxystate "\$_INTERCEPT_SERVICE" on 2>/dev/null
    echo "Proxy enabled on ${PROXY_HOST}:${PROXY_PORT} (terminal + system)"
}

proxy-off() {
    unset http_proxy https_proxy SSL_CERT_FILE REQUESTS_CA_BUNDLE
    networksetup -setwebproxystate "\$_INTERCEPT_SERVICE" off 2>/dev/null
    networksetup -setsecurewebproxystate "\$_INTERCEPT_SERVICE" off 2>/dev/null
    echo "Proxy disabled"
}
$END_MARKER
EOF

    echo "      Shell aliases configured."
}

# ─── Main ────────────────────────────────────────────────────────────────────

main() {
    generate_cert
    install_cert
    configure_shell

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Setup complete."
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "  Reload your shell first:"
    echo "    source ~/.zshrc"
    echo ""
    echo "  Then:"
    echo "    1. Start proxy:     tian-intercept start"
    echo "    2. Enable routing:  proxy-on   (covers browser + terminal)"
    echo "    3. Disable routing: proxy-off"
    echo ""
    echo "  proxy-on sets BOTH system proxy (browser/apps)"
    echo "  AND terminal env vars (curl/python/etc.)"
    echo ""
}

main