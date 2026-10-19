"""Structured audit logging for agent runs.

Logs hashes and metadata, never prompts or secrets. Every tool call and output
is recorded so an analyst can reconstruct what the agent did.
"""

from __future__ import annotations

import json
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.security.artifacts import sha256_file, sha256_text

_SENSITIVE_KEY = re.compile(r"(api[_-]?key|secret|token|password|authorization)", re.I)
_MAX_STRING = 2_000


def hash_text(value: str) -> str:
    return sha256_text(value)


def hash_file(path: Path | str) -> str | None:
    candidate = Path(path)
    if not candidate.is_file():
        return None
    return sha256_file(candidate)


def redact(value: Any) -> Any:
    """Recursively redact sensitive keys and cap long strings."""

    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            if _SENSITIVE_KEY.search(str(key)):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = redact(item)
        return redacted
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str) and len(value) > _MAX_STRING:
        return value[:_MAX_STRING] + "...[truncated]"
    return value


class AuditLogger:
    """Append-only JSONL audit logger."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def log(self, event: dict[str, Any]) -> dict[str, Any]:
        record = dict(event)
        record.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        record = redact(record)
        line = json.dumps(record, ensure_ascii=True, sort_keys=True, default=str)
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
                handle.flush()
        return record
