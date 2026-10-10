"""Validated normalized security-event schema.

Scenario labels are retained only as evaluation metadata. Detection code must not
use these fields as evidence when evaluating an event.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class EventType(StrEnum):
    """Supported normalized event families."""

    AUTHENTICATION = "authentication"
    PROCESS = "process"
    NETWORK = "network"


class EventAction(StrEnum):
    """Normalized action categories, not verdicts about maliciousness."""

    LOGIN = "login"
    LOGOUT = "logout"
    EXECUTE = "execute"
    CONNECT = "connect"
    DISCONNECT = "disconnect"
    OTHER = "other"


class EventOutcome(StrEnum):
    """Outcome of the reported action."""

    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class ProcessMetadata(BaseModel):
    """Optional process context for process or related telemetry."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    name: str | None = Field(default=None, min_length=1, max_length=255)
    executable: str | None = Field(default=None, min_length=1, max_length=2048)
    pid: int | None = Field(default=None, ge=0, le=2**32 - 1)
    parent_pid: int | None = Field(default=None, ge=0, le=2**32 - 1)
    command_line: str | None = Field(default=None, min_length=1, max_length=4096)
    hash_sha256: str | None = None

    @field_validator("hash_sha256")
    @classmethod
    def validate_sha256(cls, value: str | None) -> str | None:
        if value is not None and re.fullmatch(r"[A-Fa-f0-9]{64}", value) is None:
            raise ValueError("hash_sha256 must be exactly 64 hexadecimal characters")
        return value.lower() if value is not None else None


class ScenarioMetadata(BaseModel):
    """Evaluation labels; never treat this metadata as detection evidence."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    scenario_id: str | None = Field(default=None, min_length=1, max_length=128)
    label: str | None = Field(default=None, min_length=1, max_length=64)


class SecurityEvent(BaseModel):
    """A normalized event with a stable ID and retained source provenance."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    event_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    timestamp: datetime
    event_type: EventType
    host_id: str = Field(min_length=1, max_length=255)
    username: str | None = Field(default=None, min_length=1, max_length=255)
    source_ip: str | None = None
    destination_ip: str | None = None
    action: EventAction
    outcome: EventOutcome = EventOutcome.UNKNOWN
    process: ProcessMetadata | None = None
    source_id: str = Field(min_length=1, max_length=512)
    scenario: ScenarioMetadata | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include a timezone offset")
        return value.astimezone(UTC)

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def normalize_ip(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ValueError("must be a valid IPv4 or IPv6 address") from exc

    @model_validator(mode="after")
    def validate_event_shape(self) -> Self:
        if self.event_type == EventType.AUTHENTICATION:
            if self.action not in {EventAction.LOGIN, EventAction.LOGOUT, EventAction.OTHER}:
                raise ValueError("authentication events require login, logout, or other action")
            if not self.username:
                raise ValueError("authentication events require username")
        elif self.event_type == EventType.PROCESS:
            if self.action not in {EventAction.EXECUTE, EventAction.OTHER}:
                raise ValueError("process events require execute or other action")
            if self.process is None:
                raise ValueError("process events require process metadata")
        elif self.event_type == EventType.NETWORK:
            if self.action not in {EventAction.CONNECT, EventAction.DISCONNECT, EventAction.OTHER}:
                raise ValueError("network events require connect, disconnect, or other action")
            if self.source_ip is None and self.destination_ip is None:
                raise ValueError("network events require source_ip or destination_ip")
        return self
