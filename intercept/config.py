from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


INTERCEPT_DIR = Path.home() / ".intercept"
SESSIONS_DIR = INTERCEPT_DIR / "sessions"
CERTS_DIR = INTERCEPT_DIR / "certs"

INTERCEPT_DIR.mkdir(exist_ok=True)
SESSIONS_DIR.mkdir(exist_ok=True)
CERTS_DIR.mkdir(exist_ok=True)


@dataclass
class ProxyConfig:
    host: str = "127.0.0.1"
    port: int = 8080
    upstream_proxy: Optional[str] = None

    @property
    def listen_addr(self) -> str:
        return f"{self.host}:{self.port}"


@dataclass
class FilterConfig:
    url_pattern: Optional[str] = None
    methods: list[str] = field(default_factory=list)
    status_codes: list[int] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    content_types: list[str] = field(default_factory=list)
    exclude_static: bool = True
    exclude_hosts: list[str] = field(default_factory=list)
    exclude_html: bool = False
    exclude_cgi: bool = True


@dataclass
class DisplayConfig:
    show_request_headers: bool = True
    show_response_headers: bool = True
    show_request_body: bool = True
    show_response_body: bool = True
    max_body_size: int = 5120
    full_output: bool = False
    compact: bool = False
    highlight_tokens: bool = True
    highlight_cookies: bool = True


@dataclass
class InterceptConfig:
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    filters: FilterConfig = field(default_factory=FilterConfig)
    display: DisplayConfig = field(default_factory=DisplayConfig)
    session_name: Optional[str] = None
    auto_save: bool = False
    quiet: bool = False


STATIC_EXTENSIONS: frozenset[str] = frozenset({
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm",
    ".map", ".zip", ".gz", ".pdf",
})

SENSITIVE_HEADERS: frozenset[str] = frozenset({
    "authorization",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
    "api-key",
    "token",
    "x-token",
    "x-csrf-token",
    "x-session-token",
})

PARSEABLE_CONTENT_TYPES: frozenset[str] = frozenset({
    "application/json",
    "application/x-www-form-urlencoded",
    "text/html",
    "text/xml",
    "application/xml",
    "text/plain",
    "application/graphql",
})
