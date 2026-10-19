"""Validation and hardening helpers for untrusted model/tool inputs."""

from __future__ import annotations

import ipaddress
import re
import uuid

from src.security.schemas import ALLOWED_FUNCTION_CODES

_FORBIDDEN_ACTIONS = re.compile(r"\b(drop|reject|pass|bypass)\b", re.IGNORECASE)
_SID_RE = re.compile(r"sid\s*:\s*(\d+)\s*;")
_MSG_RE = re.compile(r'msg\s*:\s*"([^"\n]{1,512})"\s*;')
_MODBUS_HEADER_RE = re.compile(r"^alert\s+modbus\s+\S+\s+")
_LOCAL_SID_MIN = 1_000_000
_LOCAL_SID_MAX = 9_999_999


def canonical_uuid(value: str) -> str:
    """Canonicalise a UUID string, rejecting paths and other malformed input."""

    try:
        return str(uuid.UUID(value))
    except (ValueError, AttributeError, TypeError) as exc:
        raise ValueError("alert_id must be a canonical UUID") from exc


def validate_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except (ValueError, TypeError) as exc:
        raise ValueError(f"invalid IP address: {value!r}") from exc


def validate_function_code(value: int) -> int:
    if value not in ALLOWED_FUNCTION_CODES:
        raise ValueError(f"unsupported Modbus function code: {value}")
    return int(value)


def validate_rule(rule: str) -> str:
    """Structurally validate a generated Suricata rule.

    This is defence in depth, not a replacement for ``suricata -T``. It rejects
    non-Modbus and non-alert actions (a generated drop rule is never acceptable
    in OT), checks the required keywords, and confines SIDs to the local range.
    """

    if not isinstance(rule, str) or not rule.strip():
        return "FAILED: rule must be a non-empty string"
    if len(rule) > 4096:
        return "FAILED: rule exceeds 4096 characters"
    if "\x00" in rule:
        return "FAILED: rule contains a NUL byte"

    stripped = rule.lstrip()
    if not _MODBUS_HEADER_RE.match(stripped):
        return "FAILED: rule must use the 'alert modbus' protocol keyword"
    if stripped.count("(") != stripped.count(")"):
        return "FAILED: rule has unbalanced parentheses"
    if not stripped.rstrip().endswith(")"):
        return "FAILED: rule must end with ')'"

    for token in ("sid:", "classtype:", "msg:", "rev:"):
        if token not in rule:
            return f"FAILED: rule must contain {token}"

    if _FORBIDDEN_ACTIONS.search(rule):
        return "FAILED: generated rules must be alert-only (no drop/reject/pass/bypass)"

    sid_match = _SID_RE.search(rule)
    if not sid_match:
        return "FAILED: rule must contain a numeric sid:"
    sid = int(sid_match.group(1))
    if not (_LOCAL_SID_MIN <= sid <= _LOCAL_SID_MAX):
        return f"FAILED: sid must be in {_LOCAL_SID_MIN}-{_LOCAL_SID_MAX}"

    if not _MSG_RE.search(rule):
        return "FAILED: rule must contain a quoted, single-line msg:"

    return "PASSED"
