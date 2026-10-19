"""Strict schemas for untrusted alert data.

These models are the trust boundary for anything entering the pipeline from the
network or telemetry. They reject unknown fields, malformed identifiers, invalid
IP addresses and unexpected Modbus function codes.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import datetime
from typing import List

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

ALLOWED_FUNCTION_CODES = frozenset({3, 6, 16, 131})
WRITE_FUNCTION_CODES = frozenset({6, 16})

_PLC_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_FUNCTION_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,31}$")
_MAX_TIMESTAMP = 64


def _validate_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ValueError(f"invalid IP address: {value!r}") from exc


def _validate_timestamp(value: str | None) -> str | None:
    if value is None:
        return None
    if len(value) > _MAX_TIMESTAMP:
        raise ValueError("timestamp is too long")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid ISO-8601 timestamp: {value!r}") from exc
    return value


class RawRow(BaseModel):
    """One telemetry row inside an alert window (untrusted input)."""

    model_config = ConfigDict(extra="forbid")

    plc_id: str = Field(min_length=1, max_length=64)
    plc_ip: str
    reg_0_inlet_valve: float = Field(ge=0, le=100)
    reg_1: float = Field(default=0, ge=0, le=100)
    reg_2: float = Field(default=0, ge=0, le=100)
    reg_3: float = Field(default=0, ge=0, le=100)
    reg_4: float = Field(default=0, ge=0, le=100)
    reg_5_tank_level: float = Field(ge=0, le=100)
    source_ip: str
    function_code: int
    function_name: str = Field(min_length=1, max_length=32)

    @field_validator("plc_id")
    @classmethod
    def valid_plc_id(cls, value: str) -> str:
        if not _PLC_ID_RE.match(value):
            raise ValueError("plc_id contains unsupported characters")
        return value

    @field_validator("plc_ip", "source_ip")
    @classmethod
    def valid_ip(cls, value: str) -> str:
        return _validate_ip(value)

    @field_validator("function_code")
    @classmethod
    def valid_function_code(cls, value: int) -> int:
        if value not in ALLOWED_FUNCTION_CODES:
            raise ValueError(f"unsupported Modbus function code: {value}")
        return value

    @field_validator("function_name")
    @classmethod
    def valid_function_name(cls, value: str) -> str:
        if not _FUNCTION_NAME_RE.match(value):
            raise ValueError("function_name contains unsupported characters")
        return value


class WindowSummary(BaseModel):
    """Summary of the six-row window that triggered an alert."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    tank_level_mean: float = Field(ge=0, le=100)
    tank_level_max: float = Field(ge=0, le=100)
    has_write_fc: int = Field(ge=0, le=1)
    source_ips: List[str] = Field(default_factory=list, max_length=32)
    function_codes: List[int] = Field(min_length=1, max_length=8)

    @field_validator("source_ips")
    @classmethod
    def valid_source_ips(cls, values: List[str]) -> List[str]:
        return [_validate_ip(value) for value in values]

    @field_validator("function_codes")
    @classmethod
    def valid_function_codes(cls, values: List[int]) -> List[int]:
        for value in values:
            if value not in ALLOWED_FUNCTION_CODES:
                raise ValueError(f"unsupported Modbus function code: {value}")
        return sorted(set(values))

    @model_validator(mode="after")
    def consistent_levels(self) -> "WindowSummary":
        if self.tank_level_mean > self.tank_level_max:
            raise ValueError("tank_level_mean cannot exceed tank_level_max")
        return self


class AlertPayload(BaseModel):
    """Validated alert accepted by the webhook and the standalone agent."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    alert_id: str
    timestamp: str
    plc_id: str = Field(min_length=1, max_length=64)
    plc_ip: str
    anomaly_score: float = Field(ge=-1.0, le=1.0)
    window_summary: WindowSummary
    raw_data: List[RawRow] = Field(default_factory=list, max_length=100)
    window_start: str | None = None
    window_end: str | None = None

    @field_validator("alert_id")
    @classmethod
    def canonical_uuid(cls, value: str) -> str:
        try:
            return str(uuid.UUID(value))
        except (ValueError, AttributeError) as exc:
            raise ValueError("alert_id must be a canonical UUID") from exc

    @field_validator("plc_id")
    @classmethod
    def valid_plc_id(cls, value: str) -> str:
        if not _PLC_ID_RE.match(value):
            raise ValueError("plc_id contains unsupported characters")
        return value

    @field_validator("plc_ip")
    @classmethod
    def valid_plc_ip(cls, value: str) -> str:
        return _validate_ip(value)

    @field_validator("timestamp", "window_start", "window_end")
    @classmethod
    def valid_timestamps(cls, value: str | None) -> str | None:
        return _validate_timestamp(value)

    @model_validator(mode="after")
    def consistent_write_flag(self) -> "AlertPayload":
        function_codes = set(self.window_summary.function_codes)
        has_write = bool(self.window_summary.has_write_fc)
        if has_write and not (function_codes & WRITE_FUNCTION_CODES):
            raise ValueError("has_write_fc=1 requires FC 6 or FC 16")
        if not has_write and (function_codes & WRITE_FUNCTION_CODES):
            raise ValueError("FC 6/FC 16 requires has_write_fc=1")
        return self
