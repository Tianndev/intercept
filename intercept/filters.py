from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from .config import FilterConfig, STATIC_EXTENSIONS


class TrafficFilter:
    def __init__(self, config: FilterConfig) -> None:
        self.config = config
        self._url_regex: Optional[re.Pattern] = None

        if config.url_pattern:
            try:
                self._url_regex = re.compile(config.url_pattern, re.IGNORECASE)
            except re.error:
                self._url_regex = re.compile(
                    fnmatch.translate(config.url_pattern), re.IGNORECASE
                )

    def should_capture(
        self,
        url: str,
        method: str,
        host: str,
        content_type: str = "",
        status_code: Optional[int] = None,
    ) -> bool:
        path = urlparse(url).path

        path_lower = path.lower()

        if any(ex.lower() in host.lower() for ex in self.config.exclude_hosts):
            return False

        if self.config.exclude_cgi and (path_lower.startswith("/cdn-cgi/") or "/cgi-bin/" in path_lower):
            return False

        if self.config.exclude_static and Path(path).suffix.lower() in STATIC_EXTENSIONS:
            return False

        if self.config.exclude_html and Path(path).suffix.lower() in {".html", ".htm"}:
            return False

        if self._url_regex and not self._url_regex.search(url):
            return False

        if self.config.methods:
            if method.upper() not in {m.upper() for m in self.config.methods}:
                return False

        if self.config.hosts:
            if not any(h.lower() in host.lower() for h in self.config.hosts):
                return False

        if self.config.content_types:
            if not any(ct.lower() in content_type.lower() for ct in self.config.content_types):
                return False

        if status_code is not None and self.config.status_codes:
            if status_code not in self.config.status_codes:
                return False

        return True

    def match_url(self, url: str) -> bool:
        if not self._url_regex:
            return True
        return bool(self._url_regex.search(url))
