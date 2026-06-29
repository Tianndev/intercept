from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

from mitmproxy import http

from .config import InterceptConfig, PARSEABLE_CONTENT_TYPES
from .display import console, print_traffic_entry
from .filters import TrafficFilter
from .storage import TrafficStorage

_BODY_SIZE_LIMIT = 10240


def _safe_decode(data: bytes) -> str:
    if not data:
        return ""
    for encoding in ("utf-8", "latin-1", "ascii"):
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, Exception):
            continue
    return f"[binary data, {len(data)} bytes]" if len(data) > 512 else data.hex()


def _extract_content_type(raw: str) -> str:
    if not raw:
        return ""
    return raw.split(";")[0].strip().lower()


def _is_parseable(content_type: str) -> bool:
    return any(ct in content_type for ct in PARSEABLE_CONTENT_TYPES)


def _decode_body(content: Optional[bytes], content_type: str) -> str:
    if not content:
        return ""
    if _is_parseable(content_type) or len(content) <= _BODY_SIZE_LIMIT:
        return _safe_decode(content)
    return ""


def _headers_to_dict(headers) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in headers.items():
        key_lower = key.lower()
        if key_lower in result:
            result[key_lower] += f", {value}"
        else:
            result[key_lower] = value
    return result


def _get_onboarding_html(host: str, port: int) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Intercept - Proxy Console</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@500;700;800&family=Space+Grotesk:wght@500;700&display=swap" rel="stylesheet">
    <style>
        *, *::before, *::after {{
            box-sizing: border-box;
        }}

        :root {{
            --bg-base: #f0f2f5;
            --bg-card: #ffffff;
            --text-primary: #000000;
            --text-secondary: #374151;
            --accent-primary: #facc15;
            --accent-secondary: #a78bfa;
            --success-color: #4ade80;
            --border-width: 4px;
            --shadow-offset: 8px;
            --mono-font: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
        }}

        body {{
            font-family: 'Space Grotesk', -apple-system, BlinkMacSystemFont, sans-serif;
            background-color: var(--bg-base);
            color: var(--text-primary);
            margin: 0;
            padding: 24px 16px;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }}

        .dashboard {{
            width: 100%;
            max-width: 850px;
            background-color: var(--bg-card);
            border: var(--border-width) solid #000000;
            box-shadow: var(--shadow-offset) var(--shadow-offset) 0px #000000;
            display: flex;
            flex-direction: column;
        }}

        .header {{
            padding: 32px;
            border-bottom: var(--border-width) solid #000000;
            background-color: var(--accent-primary);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
        }}

        .logo-section {{
            display: flex;
            flex-direction: column;
            gap: 4px;
        }}

        .logo {{
            font-size: 32px;
            font-weight: 800;
            letter-spacing: -1px;
            text-transform: uppercase;
        }}

        .sub-logo {{
            font-size: 13px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #000000;
        }}

        .status-badge {{
            display: flex;
            align-items: center;
            gap: 8px;
            background-color: var(--success-color);
            border: var(--border-width) solid #000000;
            padding: 8px 16px;
            font-size: 13px;
            font-weight: 700;
            box-shadow: 4px 4px 0px #000000;
        }}

        .status-dot {{
            width: 8px;
            height: 8px;
            background-color: #000000;
            border-radius: 50%;
        }}

        .grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            background-color: #000000;
            gap: var(--border-width);
        }}

        @media (max-width: 768px) {{
            .grid {{
                grid-template-columns: 1fr;
            }}
            .grid-col {{
                padding: 24px !important;
            }}
            .header {{
                padding: 24px !important;
            }}
            .footer {{
                flex-direction: column;
                gap: 12px;
                align-items: flex-start !important;
                padding: 24px !important;
            }}
        }}

        .grid-col {{
            background-color: var(--bg-card);
            padding: 36px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            min-width: 0;
            overflow: hidden;
        }}

        h2 {{
            font-size: 22px;
            font-weight: 800;
            margin-top: 0;
            margin-bottom: 16px;
            text-transform: uppercase;
        }}

        p {{
            font-size: 15px;
            line-height: 1.6;
            color: var(--text-secondary);
            margin-bottom: 24px;
            font-family: 'Plus Jakarta Sans', sans-serif;
            font-weight: 500;
        }}

        .action-card {{
            background-color: var(--bg-base);
            border: var(--border-width) solid #000000;
            padding: 24px;
            box-shadow: 6px 6px 0px #000000;
            display: flex;
            flex-direction: column;
            gap: 20px;
            width: 100%;
        }}

        .btn {{
            display: block;
            background-color: var(--accent-secondary);
            color: #000000;
            font-size: 15px;
            font-weight: 700;
            text-align: center;
            text-decoration: none;
            padding: 14px 20px;
            border: var(--border-width) solid #000000;
            box-shadow: 4px 4px 0px #000000;
            transition: all 0.15s ease;
        }}

        .btn:hover {{
            transform: translate(2px, 2px);
            box-shadow: 2px 2px 0px #000000;
        }}

        .btn:active {{
            transform: translate(4px, 4px);
            box-shadow: 0px 0px 0px #000000;
        }}

        .code-container {{
            position: relative;
            background-color: #000000;
            border: 2px solid #000000;
            padding: 16px;
            font-family: var(--mono-font);
            font-size: 13px;
            color: #22c55e;
            overflow-x: auto;
            white-space: nowrap;
            width: 100%;
            max-width: 100%;
        }}

        .code-container::-webkit-scrollbar {{
            height: 6px;
        }}
        .code-container::-webkit-scrollbar-track {{
            background: #000000;
        }}
        .code-container::-webkit-scrollbar-thumb {{
            background: #374151;
            border-radius: 3px;
        }}

        .code-container pre {{
            margin: 0;
            overflow-x: auto;
            white-space: pre;
        }}

        .copy-btn {{
            position: absolute;
            top: 8px;
            right: 8px;
            background-color: var(--accent-primary);
            border: 2px solid #000000;
            color: #000000;
            padding: 6px 12px;
            font-size: 11px;
            font-weight: 700;
            cursor: pointer;
            box-shadow: 2px 2px 0px #000000;
            transition: all 0.1s;
            z-index: 10;
        }}

        .copy-btn:hover {{
            transform: translate(1px, 1px);
            box-shadow: 1px 1px 0px #000000;
        }}

        .copy-btn:active {{
            transform: translate(2px, 2px);
            box-shadow: 0px 0px 0px #000000;
        }}

        .footer {{
            padding: 24px 32px;
            background-color: var(--accent-primary);
            border-top: var(--border-width) solid #000000;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 13px;
            font-weight: 700;
        }}

        .footer a {{
            color: #000000;
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="dashboard">
        <div class="header">
            <div class="logo-section">
                <div class="logo">INTERCEPT</div>
                <div class="sub-logo">Traffic Inspection Console</div>
            </div>
            <div class="status-badge">
                <div class="status-dot"></div>
                PROXY ACTIVE
            </div>
        </div>
        
        <div class="grid">
            <div class="grid-col">
                <div>
                    <h2>Security & Credentials</h2>
                    <p>Decrypt TLS/HTTPS connections by installing the trusted local CA Certificate on your target device or browser environment.</p>
                </div>
                
                <div class="action-card">
                    <a href="/cert" class="btn">Download CA Certificate</a>
                    <div style="font-size: 13px; font-weight: 700;">
                        macOS Keychain installation command:
                        <div class="code-container" style="margin-top: 10px; color: #ef4444;">
                            <pre>sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/Downloads/mitmproxy-ca-cert.pem</pre>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="grid-col">
                <div>
                    <h2>Network Routing</h2>
                    <p>Route outbound network traffic through the local proxy server using standard environment variables.</p>
                </div>
                
                <div style="display: flex; flex-direction: column; gap: 24px; width: 100%;">
                    <div style="position: relative; width: 100%;">
                        <button class="copy-btn" onclick="copyConfig()">Copy</button>
                        <div class="code-container" id="config-text" style="padding-top: 24px; padding-bottom: 24px; width: 100%;">
                            <pre>export http_proxy=http://{host}:{port}<br>export https_proxy=http://{host}:{port}</pre>
                        </div>
                    </div>
                    <p style="font-size: 13px; margin: 0;">
                        Verify that target client applications respect global shell proxy settings.
                    </p>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <span>Server Instance: {host}:{port}</span>
            <span>Developed by <a href="https://github.com/Tianndev" target="_blank">Tianndev</a></span>
        </div>
    </div>

    <script>
        function copyConfig() {{
            const text = "export http_proxy=http://{host}:{port}\\nexport https_proxy=http://{host}:{port}";
            navigator.clipboard.writeText(text).then(() => {{
                const btn = document.querySelector('.copy-btn');
                btn.textContent = 'Copied';
                setTimeout(() => btn.textContent = 'Copy', 2000);
            }});
        }}
    </script>
</body>
</html>
"""


class InterceptAddon:
    def __init__(self, config: InterceptConfig, storage: TrafficStorage) -> None:
        self.config = config
        self.storage = storage
        self._filter = TrafficFilter(config.filters)
        self._flow_to_entry: dict[str, str] = {}
        self._flow_start: dict[str, float] = {}

    def request(self, flow: http.HTTPFlow) -> None:
        req = flow.request
        url = req.pretty_url
        host = req.pretty_host
        method = req.method
        content_type = _extract_content_type(req.headers.get("content-type", ""))

        if req.host in ("127.0.0.1", "localhost", self.config.proxy.host) and req.port == self.config.proxy.port:
            if req.path == "/cert":
                cert_path = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
                if cert_path.exists():
                    with open(cert_path, "rb") as f:
                        cert_bytes = f.read()
                    flow.response = http.Response.make(
                        200,
                        cert_bytes,
                        {
                            "Content-Type": "application/x-x509-ca-cert",
                            "Content-Disposition": 'attachment; filename="mitmproxy-ca-cert.pem"',
                        }
                    )
                else:
                    flow.response = http.Response.make(
                        404,
                        b"CA certificate file not found. Please start the proxy to generate it.",
                        {"Content-Type": "text/plain"}
                    )
            elif req.path in ("/", "/index.html"):
                html = _get_onboarding_html(self.config.proxy.host, self.config.proxy.port)
                flow.response = http.Response.make(
                    200,
                    html.encode("utf-8"),
                    {"Content-Type": "text/html"}
                )
            else:
                flow.response = http.Response.make(
                    404,
                    b"Not Found",
                    {"Content-Type": "text/plain"}
                )
            flow.metadata["intercept_skip"] = True
            return

        if not self._filter.should_capture(url, method, host, content_type):
            flow.metadata["intercept_skip"] = True
            return

        self._flow_start[flow.id] = time.time()

        request_data = {
            "method": method,
            "url": url,
            "host": host,
            "path": req.path,
            "scheme": req.scheme,
            "http_version": req.http_version,
            "headers": _headers_to_dict(req.headers),
            "content_type": content_type,
            "body": _decode_body(req.content, content_type),
            "content_length": len(req.content) if req.content else 0,
            "timestamp": time.time(),
        }

        entry_id = self.storage.add_request(request_data)
        self._flow_to_entry[flow.id] = entry_id
        flow.metadata["intercept_entry_id"] = entry_id

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.metadata.get("intercept_skip"):
            return

        entry_id = self._flow_to_entry.get(flow.id)
        if not entry_id:
            return

        resp = flow.response
        content_type = _extract_content_type(resp.headers.get("content-type", ""))

        if self.config.filters.exclude_html and "text/html" in content_type.lower():
            self.storage.remove_entry(entry_id)
            self._cleanup_flow(flow.id)
            return

        duration_ms = (time.time() - self._flow_start.get(flow.id, time.time())) * 1000

        response_data = {
            "status_code": resp.status_code,
            "status_text": resp.reason or "",
            "http_version": resp.http_version,
            "headers": _headers_to_dict(resp.headers),
            "content_type": content_type,
            "body": _decode_body(resp.content, content_type),
            "content_length": len(resp.content) if resp.content else 0,
        }

        if self.config.filters.status_codes:
            if resp.status_code not in self.config.filters.status_codes:
                self._cleanup_flow(flow.id)
                return

        self.storage.update_response(entry_id, response_data, duration_ms)

        if not self.config.quiet:
            entry = self.storage.get_entry(entry_id)
            if entry:
                try:
                    print_traffic_entry(
                        seq=entry.request.get("_seq", 0),
                        entry_id=entry_id,
                        request=entry.request,
                        response=entry.response,
                        duration_ms=duration_ms,
                        config=self.config.display,
                    )
                except Exception as exc:
                    console.print(f"[red]display error: {exc}[/red]")

        self._cleanup_flow(flow.id)

    def error(self, flow: http.HTTPFlow) -> None:
        if flow.metadata.get("intercept_skip"):
            return

        entry_id = self._flow_to_entry.get(flow.id)
        if entry_id and not self.config.quiet:
            error_msg = str(flow.error) if flow.error else "unknown error"
            console.print(f"[dim red]flow error: {flow.request.pretty_url}: {error_msg}[/dim red]")

        self._cleanup_flow(flow.id)

    def _cleanup_flow(self, flow_id: str) -> None:
        self._flow_to_entry.pop(flow_id, None)
        self._flow_start.pop(flow_id, None)
