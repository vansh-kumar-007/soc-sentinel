"""JSONL input parsing tests."""

from __future__ import annotations

import io
import json

import pytest

from soc_sentinel.ingestion.jsonl import MAX_LINE_BYTES, parse_jsonl_stream
from tests.test_schemas import authentication_event


def test_non_strict_parser_collects_errors_and_continues() -> None:
    valid = authentication_event()
    malformed = '{"event_id":'
    missing = {"event_id": "missing-timestamp"}
    text = "\n".join([json.dumps(valid), malformed, json.dumps(missing), json.dumps(valid)])
    result = parse_jsonl_stream(io.StringIO(text))

    assert result.records_read == 4
    assert len(result.events) == 1
    assert result.records_rejected == 3
    assert result.duplicate_records == 1
    assert [issue.line_number for issue in result.issues] == [2, 3, 4]
    assert "invalid JSON" in result.issues[0].message
    assert "schema validation failed" in result.issues[1].message
    assert "duplicate event_id" in result.issues[2].message


def test_strict_parser_aborts_on_first_bad_nonblank_line() -> None:
    text = json.dumps(authentication_event()) + "\n{broken-json}\n"
    with pytest.raises(ValueError, match="line 2"):
        parse_jsonl_stream(io.StringIO(text), strict=True)


def test_blank_and_empty_inputs_are_supported() -> None:
    assert parse_jsonl_stream(io.StringIO("")).records_read == 0
    result = parse_jsonl_stream(io.StringIO("\n  \n"))
    assert result.records_read == 0
    assert result.records_rejected == 0


def test_parser_rejects_non_object_json() -> None:
    result = parse_jsonl_stream(io.StringIO('[]\n"not an object"\n'))
    assert result.records_rejected == 2
    assert all("JSON object" in issue.message for issue in result.issues)


def test_oversized_line_is_rejected_without_json_parsing() -> None:
    result = parse_jsonl_stream(io.StringIO('{"padding":"' + "x" * MAX_LINE_BYTES + '"}'))
    assert result.records_read == 1
    assert result.records_rejected == 1
    assert "maximum allowed size" in result.issues[0].message


def test_strict_duplicate_aborts_with_line_number() -> None:
    row = json.dumps(authentication_event())
    with pytest.raises(ValueError, match="line 2: duplicate event_id"):
        parse_jsonl_stream(io.StringIO(row + "\n" + row), strict=True)
