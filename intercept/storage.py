from __future__ import annotations

import json
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .config import SESSIONS_DIR


class TrafficEntry:
    def __init__(
        self,
        entry_id: str,
        timestamp: float,
        request: dict,
        response: Optional[dict] = None,
    ) -> None:
        self.id = entry_id
        self.timestamp = timestamp
        self.request = request
        self.response = response
        self.duration_ms: Optional[float] = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "timestamp_iso": datetime.fromtimestamp(self.timestamp, tz=timezone.utc).isoformat(),
            "duration_ms": self.duration_ms,
            "request": self.request,
            "response": self.response,
        }

    @classmethod
    def from_dict(cls, data: dict) -> TrafficEntry:
        entry = cls(
            entry_id=data["id"],
            timestamp=data["timestamp"],
            request=data["request"],
            response=data.get("response"),
        )
        entry.duration_ms = data.get("duration_ms")
        return entry


class TrafficStorage:
    def __init__(self, session_name: Optional[str] = None, auto_save: bool = False) -> None:
        self._entries: list[TrafficEntry] = []
        self._lock = threading.Lock()
        self._counter = 0
        self.session_name = session_name or datetime.now().strftime("session_%Y%m%d_%H%M%S")
        self.auto_save = auto_save
        self.session_file = SESSIONS_DIR / f"{self.session_name}.json"

        if self.session_file.exists():
            self._load_from_file()

    def add_request(self, request_data: dict) -> str:
        entry_id = str(uuid.uuid4())[:8]
        with self._lock:
            self._counter += 1
            request_data["_seq"] = self._counter
            entry = TrafficEntry(
                entry_id=entry_id,
                timestamp=time.time(),
                request=request_data,
            )
            self._entries.append(entry)

        if self.auto_save:
            self._save_to_file()

        return entry_id

    def update_response(self, entry_id: str, response_data: dict, duration_ms: float) -> None:
        with self._lock:
            for entry in self._entries:
                if entry.id == entry_id:
                    entry.response = response_data
                    entry.duration_ms = duration_ms
                    break

        if self.auto_save:
            self._save_to_file()

    def remove_entry(self, entry_id: str) -> None:
        with self._lock:
            self._entries = [e for e in self._entries if e.id != entry_id]
        if self.auto_save:
            self._save_to_file()

    def get_entry(self, entry_id: str) -> Optional[TrafficEntry]:
        with self._lock:
            for entry in self._entries:
                if entry.id == entry_id:
                    return entry
        return None

    def get_all(self, limit: Optional[int] = None) -> list[TrafficEntry]:
        with self._lock:
            entries = list(self._entries)
        return entries[-limit:] if limit else entries

    def search(self, query: str, field: str = "all") -> list[TrafficEntry]:
        query = query.lower()
        results: list[TrafficEntry] = []
        with self._lock:
            for entry in self._entries:
                matched = False
                if field in ("all", "url"):
                    matched = matched or query in entry.request.get("url", "").lower()
                if field in ("all", "body"):
                    req_body = str(entry.request.get("body", "")).lower()
                    resp_body = str((entry.response or {}).get("body", "")).lower()
                    matched = matched or query in req_body or query in resp_body
                if field in ("all", "headers"):
                    req_h = str(entry.request.get("headers", {})).lower()
                    resp_h = str((entry.response or {}).get("headers", {})).lower()
                    matched = matched or query in req_h or query in resp_h
                if matched:
                    results.append(entry)
        return results

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            entries = list(self._entries)

        if not entries:
            return {}

        domain_stats: dict[str, dict] = {}
        method_counts: dict[str, int] = {}
        status_counts: dict[str, int] = {}
        total_bytes = 0
        total_duration = 0.0
        count_with_response = 0

        for entry in entries:
            host = entry.request.get("host", "unknown")
            if host not in domain_stats:
                domain_stats[host] = {"count": 0, "methods": set(), "statuses": set()}
            domain_stats[host]["count"] += 1
            domain_stats[host]["methods"].add(entry.request.get("method", ""))

            method = entry.request.get("method", "UNKNOWN")
            method_counts[method] = method_counts.get(method, 0) + 1

            if entry.response:
                count_with_response += 1
                status = str(entry.response.get("status_code", 0))
                status_counts[status] = status_counts.get(status, 0) + 1
                total_bytes += entry.response.get("content_length", 0)
                domain_stats[host]["statuses"].add(entry.response.get("status_code", 0))

            if entry.duration_ms:
                total_duration += entry.duration_ms

        for d in domain_stats.values():
            d["methods"] = sorted(d["methods"])
            d["statuses"] = sorted(d["statuses"])

        avg_duration = total_duration / count_with_response if count_with_response else 0.0

        return {
            "total_requests": len(entries),
            "total_responses": count_with_response,
            "total_bytes": total_bytes,
            "avg_duration_ms": round(avg_duration, 2),
            "method_counts": method_counts,
            "status_counts": status_counts,
            "domain_stats": domain_stats,
        }

    def clear(self) -> int:
        with self._lock:
            count = len(self._entries)
            self._entries.clear()
            self._counter = 0
        return count

    def save(self, path: Optional[Path] = None) -> Path:
        target = path or self.session_file
        self._save_to_file(target)
        return target

    def _save_to_file(self, path: Optional[Path] = None) -> None:
        target = path or self.session_file
        with self._lock:
            data = [e.to_dict() for e in self._entries]
        with open(target, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "session": self.session_name,
                    "created_at": datetime.now(tz=timezone.utc).isoformat(),
                    "entry_count": len(data),
                    "entries": data,
                },
                f,
                indent=2,
                ensure_ascii=False,
            )

    def _load_from_file(self) -> None:
        try:
            with open(self.session_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            with self._lock:
                for entry_data in data.get("entries", []):
                    self._entries.append(TrafficEntry.from_dict(entry_data))
                if self._entries:
                    self._counter = max(e.request.get("_seq", 0) for e in self._entries)
        except (json.JSONDecodeError, KeyError, ValueError):
            pass

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._entries)
