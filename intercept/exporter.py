from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from .storage import TrafficEntry


def export_json(entries: list[TrafficEntry], output: Path) -> int:
    data = {
        "format": "intercept-json",
        "version": "1.0",
        "exported_at": datetime.now(tz=timezone.utc).isoformat(),
        "entry_count": len(entries),
        "entries": [e.to_dict() for e in entries],
    }
    with open(output, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    return len(entries)


def export_har(entries: list[TrafficEntry], output: Path, creator_name: str = "intercept") -> int:
    har_entries = [
        entry
        for e in entries
        if e.response and (entry := _build_har_entry(e, e.request, e.response)) is not None
    ]

    har = {
        "log": {
            "version": "1.2",
            "creator": {"name": creator_name, "version": "1.0.0"},
            "browser": {"name": creator_name, "version": "1.0.0"},
            "pages": [
                {
                    "startedDateTime": datetime.now(tz=timezone.utc).isoformat(),
                    "id": "page_1",
                    "title": "Intercept Capture",
                    "pageTimings": {"onContentLoad": -1, "onLoad": -1},
                }
            ],
            "entries": har_entries,
        }
    }

    with open(output, "w", encoding="utf-8") as f:
        json.dump(har, f, indent=2, ensure_ascii=False)

    return len(har_entries)


def _build_har_entry(
    entry: TrafficEntry,
    req: dict,
    resp: dict,
) -> Optional[dict[str, Any]]:
    try:
        url = req.get("url", "")
        parsed = urlparse(url)
        started_datetime = datetime.fromtimestamp(entry.timestamp, tz=timezone.utc).isoformat()

        req_headers = [{"name": k, "value": v} for k, v in req.get("headers", {}).items()]
        req_body_str = req.get("body", "")
        req_body_size = len(req_body_str.encode("utf-8")) if req_body_str else 0
        req_content_type = req.get("content_type", "")

        har_post_data: Optional[dict] = None
        if req_body_str:
            if "x-www-form-urlencoded" in req_content_type:
                params = [
                    {"name": k, "value": v}
                    for part in req_body_str.split("&")
                    if "=" in part
                    for k, v in [part.split("=", 1)]
                ]
                har_post_data = {
                    "mimeType": req_content_type,
                    "params": params,
                    "text": req_body_str,
                }
            else:
                har_post_data = {
                    "mimeType": req_content_type or "text/plain",
                    "text": req_body_str,
                }

        query_string = [
            {"name": k, "value": v}
            for part in parsed.query.split("&")
            if "=" in part
            for k, v in [part.split("=", 1)]
        ] if parsed.query else []

        har_request: dict[str, Any] = {
            "method": req.get("method", "GET"),
            "url": url,
            "httpVersion": req.get("http_version", "HTTP/1.1"),
            "headers": req_headers,
            "queryString": query_string,
            "cookies": _parse_cookie_string(req.get("headers", {}).get("cookie", "")),
            "headersSize": -1,
            "bodySize": req_body_size,
        }
        if har_post_data:
            har_request["postData"] = har_post_data

        resp_headers = [{"name": k, "value": v} for k, v in resp.get("headers", {}).items()]
        resp_body_str = resp.get("body", "")
        resp_content_type = resp.get("content_type", "text/plain")
        resp_body_size = resp.get("content_length", 0)

        set_cookie = next(
            (v for k, v in resp.get("headers", {}).items() if k.lower() == "set-cookie"), ""
        )

        har_response: dict[str, Any] = {
            "status": resp.get("status_code", 0),
            "statusText": resp.get("status_text", ""),
            "httpVersion": resp.get("http_version", "HTTP/1.1"),
            "headers": resp_headers,
            "cookies": _parse_cookie_string(set_cookie),
            "content": {
                "size": resp_body_size,
                "mimeType": resp_content_type,
                "text": resp_body_str,
            },
            "redirectURL": resp.get("headers", {}).get("location", ""),
            "headersSize": -1,
            "bodySize": resp_body_size,
        }

        return {
            "startedDateTime": started_datetime,
            "time": entry.duration_ms or 0,
            "request": har_request,
            "response": har_response,
            "cache": {},
            "timings": {"send": 0, "wait": entry.duration_ms or 0, "receive": 0},
            "pageref": "page_1",
            "_id": entry.id,
        }

    except Exception:
        return None


def _parse_cookie_string(cookie_str: str) -> list[dict]:
    if not cookie_str:
        return []
    return [
        {"name": k.strip(), "value": v.strip()}
        for part in cookie_str.split(";")
        if "=" in part
        for k, v in [part.split("=", 1)]
    ]
