# Intercept

> HTTP/HTTPS Traffic Inspector for the terminal — developed by **[Tianndev](https://github.com/Tianndev)**

Intercept runs as a transparent local proxy that captures all traffic passing through it, displaying full request and response details in real-time directly in your terminal.

---

## Features

- Captures method, URL, host, headers, request body, response body, cookies, tokens, and status codes
- Syntax highlighting for JSON, XML, HTML, and form-encoded bodies
- Automatic detection and highlighting of `Authorization` headers and cookies
- Filter by URL pattern, HTTP method, status code, domain, and content-type
- Export to JSON or HAR format (HAR is compatible with Chrome DevTools)
- Session persistence and traffic history browsing
- Traffic search across URL, headers, and body content

---

## Requirements

- Python 3.10 or higher

---

## Installation

```bash
git clone https://github.com/Tianndev/intercept
cd intercept
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Verify the installation:

```bash
tian-intercept --version
```

---

## One-Time Setup

Run the setup script once to get everything ready automatically:

```bash
bash setup-intercept.sh
```

This script will:
1. Generate the CA certificate by starting the proxy briefly
2. Install and trust the certificate in the macOS System Keychain
3. Add permanent `proxy-on` and `proxy-off` aliases to your `~/.zshrc`

After the script finishes, reload your shell:

```bash
source ~/.zshrc
```

> **Note**: This only needs to be run **once**. The CA certificate will be permanently trusted by macOS for all HTTPS connections routed through the proxy.

---

## Usage

### 1. Start the Proxy

Open a terminal and run:

```bash
tian-intercept start
```

The proxy will listen on `http://127.0.0.1:8080` by default.

### 2. Enable Routing

Open a **new terminal tab** and run:

```bash
proxy-on
```

All traffic from that terminal session will now be routed through Intercept.

### 3. Make Requests

```bash
curl https://httpbin.org/get
curl https://api.example.com/v1/users
```

Request and response details will appear in real-time in the proxy terminal.

### 4. Disable Routing

When you're done:

```bash
proxy-off
```

---

## Shell Aliases

The `setup-intercept.sh` script automatically adds the following aliases to `~/.zshrc`:

| Alias | Action |
|---|---|
| `proxy-on` | Routes terminal traffic through `127.0.0.1:8080` |
| `proxy-off` | Disables proxy routing |

> **Tip**: `proxy-on` needs to be run once per terminal tab. To route all system traffic (browsers, apps, etc.), configure the proxy in macOS **System Settings → Network → Proxies**.

---

## Filtering Traffic

Use filter flags to capture only the traffic you care about:

```bash
# Filter by domain
tian-intercept start --domain api.example.com

# Filter by HTTP method
tian-intercept start --method POST --method PUT

# Filter by status code
tian-intercept start --status 400 --status 500

# Filter by URL pattern
tian-intercept start --url "*/api/v1/*"

# Exclude specific domains
tian-intercept start --exclude analytics.google.com --exclude doubleclick.net

# Combine multiple filters
tian-intercept start --domain api.example.com --method POST --url "*/auth/*"
```

---

## Display Options

```bash
# Hide request/response headers
tian-intercept start --no-req-headers --no-resp-headers

# Show full body without truncation
tian-intercept start --full

# Compact mode
tian-intercept start --compact

# Silent mode — save without displaying
tian-intercept start --quiet --save

# Use a different port
tian-intercept start --port 9090
```

---

## Sessions & History

```bash
# Save traffic to the default session
tian-intercept start --save

# Save to a named session
tian-intercept start --session api-test --save

# View captured traffic history
tian-intercept show
tian-intercept show --limit 100
tian-intercept show --id <entry-id>
tian-intercept show --search "authorization"
```

---

## Exporting Traffic

```bash
# Export to JSON
tian-intercept export --format json --output traffic.json

# Export to HAR (importable in Chrome DevTools → Network → Import HAR)
tian-intercept export --format har --output traffic.har
```

---

## Statistics

```bash
tian-intercept stats
```

---

## Session Management

```bash
# List all saved sessions
tian-intercept sessions

# Clear traffic from the active session
tian-intercept clear

# Clear a specific session without confirmation
tian-intercept clear --session old-session --yes
```

---

## Command Reference

| Command | Description |
|---|---|
| `tian-intercept start` | Start the proxy server |
| `tian-intercept show` | Display captured traffic history |
| `tian-intercept export` | Export traffic to JSON or HAR |
| `tian-intercept stats` | Display traffic statistics |
| `tian-intercept sessions` | List all saved sessions |
| `tian-intercept clear` | Delete traffic history |
| `tian-intercept cert` | Display or install the CA certificate |

---

## Project Structure

```
intercept/
├── intercept/
│   ├── __init__.py     # Package version
│   ├── cli.py          # CLI entry point (Typer)
│   ├── proxy.py        # mitmproxy addon — core interceptor
│   ├── display.py      # Terminal renderer (Rich)
│   ├── storage.py      # Thread-safe traffic storage
│   ├── filters.py      # Filter engine
│   ├── exporter.py     # JSON and HAR exporter
│   └── config.py       # Configuration dataclasses
├── setup-intercept.sh  # One-time automated setup script
└── pyproject.toml
```

---

## Security Notice

This tool is intended for **development, debugging, and authorized security testing** on systems you own or have explicit permission to test. Do not use it to intercept traffic on networks or systems without proper authorization.

---

## License

MIT — see [LICENSE](LICENSE)

---

<p align="center">Developed with ❤️ by <a href="https://github.com/Tianndev">Tianndev</a></p>
