"""Streaming JSONL parsing with line-oriented error reporting."""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import TextIO

from pydantic import ValidationError

from soc_sentinel.schemas import SecurityEvent


@dataclass(frozen=True, slots=True)
class IngestionIssue:
    """A rejected input line and a concise reason."""

    line_number: int
    message: str


@dataclass(slots=True)
class ParsedBatch:
    """Streaming parse summary; events are retained to allow transactional insert."""

    events: list[SecurityEvent] = field(default_factory=list)
    issues: list[IngestionIssue] = field(default_factory=list)
    records_read: int = 0
    records_rejected: int = 0

    @property
    def has_errors(self) -> bool:
        """Whether any input line was rejected."""
        return self.records_rejected > 0


def _iter_lines(stream: TextIO) -> Iterator[tuple[int, str]]:
    for line_number, raw_line in enumerate(stream, start=1):
        yield line_number, raw_line


def parse_jsonl_stream(stream: TextIO, *, strict: bool = False) -> ParsedBatch:
    """Parse a text stream one line at a time.

    Blank lines are ignored and do not count as records. In non-strict mode,
    malformed JSON/schema records are collected as issues and reading continues.
    In strict mode, the first invalid non-blank record raises ValueError with its
    line number. The caller decides whether to persist the parsed batch.
    """
    result = ParsedBatch()
    seen_ids: set[str] = set()
    for line_number, raw_line in _iter_lines(stream):
        if not raw_line.strip():
            continue
        result.records_read += 1
        try:
            decoded = json.loads(raw_line)
            if not isinstance(decoded, dict):
                raise ValueError("each JSONL record must be a JSON object")
            event = SecurityEvent.model_validate(decoded)
        except (json.JSONDecodeError, ValidationError, ValueError) as exc:
            message = _format_error(exc)
            if strict:
                raise ValueError(f"line {line_number}: {message}") from exc
            result.records_rejected += 1
            result.issues.append(IngestionIssue(line_number, message))
            continue

        if event.event_id in seen_ids:
            message = f"duplicate event_id '{event.event_id}' within input"
            if strict:
                raise ValueError(f"line {line_number}: {message}")
            result.records_rejected += 1
            result.issues.append(IngestionIssue(line_number, message))
            continue
        seen_ids.add(event.event_id)
        result.events.append(event)
    return result


def parse_jsonl_file(path: str | Path, *, strict: bool = False) -> ParsedBatch:
    """Open a UTF-8 JSONL file and parse it without reading the whole file at once."""
    with Path(path).open("r", encoding="utf-8") as stream:
        return parse_jsonl_stream(stream, strict=strict)


def _format_error(exc: Exception) -> str:
    if isinstance(exc, json.JSONDecodeError):
        return f"invalid JSON: {exc.msg} (column {exc.colno})"
    if isinstance(exc, ValidationError):
        first = exc.errors(include_url=False)[0]
        location = ".".join(str(part) for part in first["loc"])
        prefix = f"{location}: " if location else ""
        return f"schema validation failed: {prefix}{first['msg']}"
    return str(exc)
