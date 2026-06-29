from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from .config import DisplayConfig, SENSITIVE_HEADERS

STATUS_COLORS: dict[str, str] = {
    "1": "bright_cyan",
    "2": "bright_green",
    "3": "bright_blue",
    "4": "bright_yellow",
    "5": "bright_red",
}

METHOD_COLORS: dict[str, str] = {
    "GET": "bright_green",
    "POST": "bright_blue",
    "PUT": "bright_yellow",
    "PATCH": "bright_magenta",
    "DELETE": "bright_red",
    "HEAD": "bright_cyan",
    "OPTIONS": "bright_white",
}

console = Console(highlight=False)


def _status_color(status_code: int) -> str:
    return STATUS_COLORS.get(str(status_code)[0], "bright_white")


def format_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes / (1024 * 1024):.1f} MB"


def format_duration(ms: Optional[float]) -> str:
    if ms is None:
        return "—"
    return f"{ms:.0f}ms" if ms < 1000 else f"{ms / 1000:.2f}s"


def _looks_like_json(body: str) -> bool:
    s = body.strip()
    return (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]"))


def _format_body(
    body: str,
    content_type: str,
    max_size: int,
    full: bool,
) -> tuple[Any, str]:
    if not body:
        return Text("(empty)", style="bright_white italic"), ""

    truncation_msg = ""
    display = body
    if not full and len(body) > max_size:
        display = body[:max_size]
        truncation_msg = f"body truncated at {max_size} bytes — pass --full to display complete content"

    lexer = "text"
    if "json" in content_type or _looks_like_json(display):
        lexer = "json"
        try:
            display = json.dumps(json.loads(display), indent=2, ensure_ascii=False)
        except Exception:
            pass
    elif "html" in content_type:
        lexer = "html"
    elif "xml" in content_type:
        lexer = "xml"
    elif "x-www-form-urlencoded" in content_type:
        try:
            display = "\n".join(f"  {p}" for p in display.split("&"))
        except Exception:
            pass
    elif "graphql" in content_type:
        lexer = "graphql"

    syntax = Syntax(display, lexer, theme="monokai", word_wrap=True, background_color="default")
    return syntax, truncation_msg


def _format_token_value(value: str) -> Text:
    text = Text()
    lower = value.lower()
    if lower.startswith("bearer "):
        token = value[7:]
        visible = token[:16]
        text.append("Bearer ", style="bright_yellow")
        text.append(visible, style="bold bright_yellow")
        if len(token) > 16:
            text.append("*" * min(32, len(token) - 16), style="bright_yellow")
    elif lower.startswith("basic "):
        text.append("Basic ", style="bright_yellow")
        text.append("[base64-encoded credentials]", style="bold bright_yellow")
    else:
        visible = value[:16]
        text.append(visible, style="bold bright_yellow")
        if len(value) > 16:
            text.append("*" * min(32, len(value) - 16), style="bright_yellow")
    return text


def _render_headers(headers: dict[str, str], config: DisplayConfig) -> Table:
    table = Table(box=None, padding=(0, 1), show_header=False, expand=True)
    table.add_column("Key", style="bright_cyan", no_wrap=True, min_width=26)
    table.add_column("Value", style="bright_white", overflow="fold")

    for key, value in headers.items():
        key_lower = key.lower()
        is_sensitive = key_lower in SENSITIVE_HEADERS
        is_cookie = key_lower in ("cookie", "set-cookie")

        if is_sensitive and config.highlight_tokens:
            table.add_row(
                Text(key, style="bold bright_yellow"),
                _format_token_value(value),
            )
        elif is_cookie and config.highlight_cookies:
            table.add_row(
                Text(key, style="bold bright_magenta"),
                Text(value, style="bright_magenta"),
            )
        else:
            table.add_row(Text(key, style="bright_cyan"), Text(value, style="bright_white"))

    return table


def _build_panel(parts: list, title: Text, border_style: str) -> Panel:
    return Panel(Group(*parts), title=title, title_align="left", border_style=border_style, expand=True)


def _render_section(
    label: str,
    headers: dict,
    body: str,
    content_type: str,
    show_headers: bool,
    show_body: bool,
    config: DisplayConfig,
) -> list:
    parts = []
    if show_headers and headers:
        parts.append(Text("  Headers:", style="bold bright_white"))
        parts.append(_render_headers(headers, config))
    if show_body and body:
        syntax, truncation_msg = _format_body(body, content_type, config.max_body_size, config.full_output)
        parts.append(Text("\n  Body:", style="bold bright_white"))
        parts.append(syntax)
        if truncation_msg:
            parts.append(Text(f"  [{truncation_msg}]", style="bright_yellow"))
    return parts


def print_banner() -> None:
    banner = (
        "  _____ _                  _              \n"
        " |_   _(_)                | |             \n"
        "   | |  _  __ _ _ __  __ _| | _____   __  \n"
        "   | | | |/ _` | '_ \\/ _` | |/ _ \\ \\ / /  \n"
        "   | | | | (_| | | | | (_| | |  __/\\ V /   \n"
        "   |_| |_|\\__,_|_| |_|\\__,_|_|\\___| \\_/    \n"
    )
    console.print()
    console.print(Text(banner, style="bright_cyan"))
    console.print(Text("  TIAN-INTERCEPT - HTTP/HTTPS Traffic Inspector", style="bold bright_white"))
    console.print(Text("  Developed by Tianndev\n", style="bright_yellow"))


def print_proxy_info(host: str, port: int) -> None:
    info = Table(box=None, show_header=False, padding=(0, 2))
    info.add_column("Key", style="bright_cyan")
    info.add_column("Value", style="bold bright_white")
    info.add_row("Proxy Address", f"http://{host}:{port}")
    info.add_row("CA Certificate", "~/.mitmproxy/mitmproxy-ca-cert.pem")
    info.add_row("Stop", "Ctrl+C")

    console.print(Panel(info, title="Proxy Running", border_style="bright_green", expand=False))
    console.print(
        Panel(
            Text.assemble(
                ("http_proxy=", "bright_cyan"),
                (f"http://{host}:{port}", "bold bright_yellow"),
                ("\nhttps_proxy=", "bright_cyan"),
                (f"http://{host}:{port}", "bold bright_yellow"),
            ),
            title="Environment Variables",
            border_style="bright_cyan",
            expand=False,
        )
    )
    console.print()


def print_traffic_entry(
    seq: int,
    entry_id: str,
    request: dict,
    response: Optional[dict],
    duration_ms: Optional[float],
    config: DisplayConfig,
) -> None:
    method = request.get("method", "?")
    url = request.get("url", "")
    parsed_url = urlparse(url)
    method_color = METHOD_COLORS.get(method.upper(), "bright_white")

    url_text = Text()
    url_text.append(f"{parsed_url.scheme}://", style="bright_white")
    url_text.append(parsed_url.netloc, style="bold bright_white")
    url_text.append(parsed_url.path or "/", style="bright_white")
    if parsed_url.query:
        url_text.append("?", style="bright_yellow")
        url_text.append(parsed_url.query, style="bright_yellow")

    ts = datetime.fromtimestamp(
        request.get("timestamp", 0), tz=timezone.utc
    ).strftime("%H:%M:%S")

    console.print()
    console.rule(
        Text.assemble(
            (f" #{seq:04d}  ", "bright_white"),
            (f" {method} ", f"bold white on {method_color}"),
            ("  ", ""),
            url_text,
            (f"  [{ts}] ", "bright_cyan"),
        ),
        style="bright_white",
    )

    if not config.compact:
        req_parts = _render_section(
            "REQUEST",
            request.get("headers", {}),
            request.get("body", ""),
            request.get("content_type", ""),
            config.show_request_headers,
            config.show_request_body,
            config,
        )
        if req_parts:
            console.print(_build_panel(
                req_parts,
                Text("REQUEST", style="bold white on blue"),
                "bright_blue",
            ))

    if response:
        status_code = response.get("status_code", 0)
        status_text = response.get("status_text", "")
        sc = _status_color(status_code)
        content_length = response.get("content_length", 0)

        resp_title = Text.assemble(
            ("RESPONSE", "bold white on magenta"),
            ("  ", ""),
            (f" {status_code} {status_text} ", f"bold white on {sc}"),
            (f"  {format_duration(duration_ms)}", "bright_white"),
            (f"  {format_size(content_length)}", "bright_white"),
        )

        resp_parts = _render_section(
            "RESPONSE",
            response.get("headers", {}),
            response.get("body", ""),
            response.get("content_type", ""),
            config.show_response_headers,
            config.show_response_body,
            config,
        )

        if resp_parts:
            console.print(_build_panel(resp_parts, resp_title, sc))
        else:
            console.print(Panel(
                Text(
                    f"  {status_code} {status_text}  {format_duration(duration_ms)}"
                    f"  {format_size(content_length)}",
                    style=f"bold {sc}",
                ),
                border_style=sc,
                expand=False,
            ))


def print_stats(stats: dict) -> None:
    if not stats:
        console.print("[bright_white]No traffic captured.[/bright_white]")
        return

    console.print()
    console.print(Panel("Traffic Statistics", style="bright_cyan"))

    summary = Table(box=box.ROUNDED, show_header=False, padding=(0, 2))
    summary.add_column("Metric", style="bright_cyan")
    summary.add_column("Value", style="bold bright_white")
    summary.add_row("Total Requests", str(stats["total_requests"]))
    summary.add_row("Total Responses", str(stats["total_responses"]))
    summary.add_row("Total Data Transferred", format_size(stats["total_bytes"]))
    summary.add_row("Avg Response Time", format_duration(stats["avg_duration_ms"]))
    console.print(summary)
    console.print()

    if stats.get("method_counts"):
        table = Table(title="HTTP Methods", box=box.ROUNDED, title_style="bold bright_white")
        table.add_column("Method", style="bold")
        table.add_column("Count", style="bold bright_white", justify="right")
        for method, count in sorted(stats["method_counts"].items(), key=lambda x: -x[1]):
            color = METHOD_COLORS.get(method.upper(), "bright_white")
            table.add_row(Text(method, style=f"bold {color}"), str(count))
        console.print(table)
        console.print()

    if stats.get("status_counts"):
        table = Table(title="Status Codes", box=box.ROUNDED, title_style="bold bright_white")
        table.add_column("Status", style="bold")
        table.add_column("Count", style="bold bright_white", justify="right")
        for status, count in sorted(stats["status_counts"].items()):
            color = _status_color(int(status))
            table.add_row(Text(status, style=f"bold {color}"), str(count))
        console.print(table)
        console.print()

    if stats.get("domain_stats"):
        table = Table(title="Top Domains", box=box.ROUNDED, title_style="bold bright_white")
        table.add_column("Domain", style="bold bright_cyan")
        table.add_column("Requests", justify="right", style="bright_white")
        table.add_column("Methods", style="bright_green")
        table.add_column("Statuses", style="bright_yellow")
        for host, data in sorted(stats["domain_stats"].items(), key=lambda x: -x[1]["count"])[:20]:
            table.add_row(
                host,
                str(data["count"]),
                ", ".join(sorted(data.get("methods", []))),
                ", ".join(str(s) for s in sorted(data.get("statuses", []))),
            )
        console.print(table)


def print_history_table(entries: list) -> None:
    if not entries:
        console.print("[bright_white]No traffic stored.[/bright_white]")
        return

    table = Table(title="Traffic History", box=box.ROUNDED, title_style="bold bright_cyan", show_lines=False)
    table.add_column("#", style="bright_white", justify="right", width=5)
    table.add_column("ID", style="bright_cyan", width=10)
    table.add_column("Time", style="bright_white", width=10)
    table.add_column("Method", width=8)
    table.add_column("Status", width=8, justify="center")
    table.add_column("Duration", width=10, justify="right", style="bright_white")
    table.add_column("Size", width=8, justify="right", style="bright_white")
    table.add_column("URL", min_width=40, overflow="fold", style="bright_white")

    for entry in entries:
        req = entry.request
        resp = entry.response or {}
        ts = datetime.fromtimestamp(entry.timestamp, tz=timezone.utc).strftime("%H:%M:%S")

        method = req.get("method", "?")
        method_text = Text(method, style=f"bold {METHOD_COLORS.get(method.upper(), 'bright_white')}")

        status = resp.get("status_code")
        status_text = (
            Text(str(status), style=f"bold {_status_color(status)}")
            if status
            else Text("—", style="bright_white")
        )

        url = req.get("url", "")
        if len(url) > 80:
            url = url[:77] + "..."

        table.add_row(
            str(req.get("_seq", "?")),
            entry.id,
            ts,
            method_text,
            status_text,
            format_duration(entry.duration_ms),
            format_size(resp.get("content_length", 0)),
            url,
        )

    console.print(table)
