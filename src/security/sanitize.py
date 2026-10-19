"""Prompt-input sanitisation and untrusted-data delimiting.

The LLM is never a trust boundary. Everything that comes from an alert or a
retrieved document is delimited as data and stripped of control characters, and
any markup that could close a delimiter is escaped. Tests and the red-team suite
verify the delimiters cannot be broken out of.
"""

from __future__ import annotations

import json
import re
from typing import Any

MAX_PROMPT_CHARS = 20_000
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_TAG_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")

# Heuristic detection only. These patterns flag text that *looks* like an
# instruction; they are not a prompt-injection prevention mechanism.
_INSTRUCTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("ignore_previous", re.compile(r"ignore\s+(all\s+)?(previous|prior)", re.I)),
    (
        "disregard",
        re.compile(r"disregard\s+(the\s+)?(above|previous|instructions)", re.I),
    ),
    ("system_tag", re.compile(r"</?\s*system\s*>", re.I)),
    ("role_override", re.compile(r"you\s+are\s+now\s+", re.I)),
    ("new_instructions", re.compile(r"new\s+instructions?\s*:", re.I)),
    (
        "execute",
        re.compile(r"\b(execute|run)\s+(the\s+)?(command|shell|script)\b", re.I),
    ),
    (
        "credential_request",
        re.compile(r"\b(api[_ -]?key|secret|password|token)\b", re.I),
    ),
    ("rule_override", re.compile(r"\b(write|generate)\s+(a\s+)?(drop|reject)\b", re.I)),
    ("exfiltration", re.compile(r"\b(exfiltrat|send\s+the\s+data|curl\s+http)", re.I)),
)


def strip_control_chars(value: str, max_chars: int | None = None) -> str:
    """Remove control characters (except newlines/tabs) and optionally cap size."""

    if not isinstance(value, str):
        value = str(value)
    cleaned = _CONTROL_CHARS.sub("", value)
    if max_chars is not None and len(cleaned) > max_chars:
        cleaned = cleaned[:max_chars] + "\n...[truncated]"
    return cleaned


def escape_prompt_markup(value: str) -> str:
    """Escape angle brackets so untrusted text cannot close a delimiting tag."""

    return value.replace("<", "\\u003c").replace(">", "\\u003e")


def clean_context(value: str, max_chars: int = MAX_PROMPT_CHARS) -> str:
    return escape_prompt_markup(strip_control_chars(value, max_chars=max_chars))


def json_for_prompt(obj: Any, max_chars: int = MAX_PROMPT_CHARS) -> str:
    """Serialise untrusted data as safe JSON for a prompt."""

    serialised = json.dumps(obj, ensure_ascii=True, sort_keys=True, default=str)
    if len(serialised) > max_chars:
        raise ValueError(f"prompt payload exceeds {max_chars} characters")
    return escape_prompt_markup(serialised)


def wrap_untrusted(tag: str, content: str) -> str:
    """Wrap content in an explicit untrusted-data delimiter."""

    if not _TAG_RE.match(tag):
        raise ValueError(f"invalid delimiter tag: {tag!r}")
    safe_content = escape_prompt_markup(strip_control_chars(content))
    return f"<{tag}>\n{safe_content}\n</{tag}>"


def alert_for_llm(alert: dict) -> dict:
    """Return the minimum alert fields the agent needs.

    Raw telemetry rows are dropped: the agent only uses the window summary, and
    keeping six raw rows per alert needlessly sends process data to the LLM.
    """

    allowed = {
        "alert_id",
        "timestamp",
        "plc_id",
        "plc_ip",
        "anomaly_score",
        "window_start",
        "window_end",
        "window_summary",
    }
    return {key: alert[key] for key in allowed if key in alert}


def detect_instruction_patterns(text: str) -> list[str]:
    """Return labels for instruction-like patterns found in untrusted text."""

    return [label for label, pattern in _INSTRUCTION_PATTERNS if pattern.search(text)]
