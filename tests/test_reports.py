"""Presentation must not execute evidence text or destroy JSON fidelity."""

from __future__ import annotations

import csv
import io
import json
import struct
from pathlib import Path

import pytest

from rbinforensics.reports import render, safe_text
from rbinforensics.scanner import ScanOptions, scan


def report_for(tmp_path: Path, original: str = r"C:\資料\report.txt") -> dict:
    directory = tmp_path.resolve() / "evidence"
    directory.mkdir()
    source = directory / "$IABC.txt"
    encoded = (original + "\0").encode("utf-16-le")
    source.write_bytes(struct.pack("<QQQI", 2, 7, 133485408001234567, len(encoded) // 2) + encoded)
    (directory / "$RABC.txt").write_bytes(b"payload")
    return scan(directory, ScanOptions(hash_payload=True))


def test_json_roundtrip_is_authoritative_for_unicode_and_embedded_controls(tmp_path: Path) -> None:
    original = "C:\\資料\\line\n\x1b[31m.txt"
    report = report_for(tmp_path, original)
    rendered = render(report, "json")
    assert json.loads(rendered) == report
    assert json.loads(rendered)["records"][0]["metadata"]["original_path"] == original
    assert "\x1b" not in rendered
    assert "\\u001b" in rendered


@pytest.mark.parametrize("original", ['=HYPERLINK("evil")', "+1+1", "-1+2", "@SUM(1,2)", "  =1+1"])
def test_csv_blocks_formula_prefixes_without_changing_json(tmp_path: Path, original: str) -> None:
    report = report_for(tmp_path, original)
    row = next(csv.DictReader(io.StringIO(render(report, "csv"))))
    assert row["original_path"] == "'" + original
    assert json.loads(render(report, "json"))["records"][0]["metadata"]["original_path"] == original


@pytest.mark.parametrize(
    "original,expected",
    [
        (" \t=1+1", r" \u0009=1+1"),
        ("\tvalue", r"\u0009value"),
        ("\nvalue", r"\u000avalue"),
        ("\0=1+1", r"\u0000=1+1"),
    ],
)
def test_csv_control_prefixes_are_literal_text(
    tmp_path: Path, original: str, expected: str
) -> None:
    report = report_for(tmp_path, original)
    row = next(csv.DictReader(io.StringIO(render(report, "csv"))))
    assert row["original_path"] == expected
    assert json.loads(render(report, "json"))["records"][0]["metadata"]["original_path"] == original


def test_csv_roundtrip_columns_and_quoted_paths(tmp_path: Path) -> None:
    original = 'C:\\folder\\a,"b".txt'
    report = report_for(tmp_path, original)
    row = next(csv.DictReader(io.StringIO(render(report, "csv"))))
    assert row["original_path"] == original
    assert row["original_size"] == "7"
    assert row["source_sha256"] == report["records"][0]["source_sha256"]
    assert row["payload_hash_status"] == "computed"
    assert row["deleted_at_utc"] == "2024-01-01T00:00:00.1234567Z"


def test_table_escapes_terminal_controls_and_bidi_but_preserves_unicode(tmp_path: Path) -> None:
    report = report_for(tmp_path, "C:\\資料\\x\x1b[2J\n\u202ename.txt")
    table = render(report, "table")
    assert "\x1b" not in table
    assert "\u202e" not in table
    assert "\\u001b" in table
    assert "\\u202e" in table
    assert "資料" in table
    assert "Source SHA256" in table
    assert "Payload SHA256" in table
    assert "Summary:" in table


def test_error_records_render_in_all_formats(tmp_path: Path) -> None:
    directory = tmp_path.resolve() / "evidence"
    directory.mkdir()
    (directory / "$IBAD").write_bytes(b"bad")
    report = scan(directory)
    assert "[ERROR]" in render(report, "table")
    assert "Expected at least 24 header bytes" in render(report, "table")
    row = next(csv.DictReader(io.StringIO(render(report, "csv"))))
    assert row["original_path"] == ""
    assert row["issues"] == "truncated_header"
    assert json.loads(render(report, "json"))["summary"]["errors"] == 1


def test_empty_report_is_explicit(tmp_path: Path) -> None:
    report = scan(tmp_path.resolve())
    assert "No $I metadata candidates" in render(report, "table")
    assert len(list(csv.DictReader(io.StringIO(render(report, "csv"))))) == 0
    assert json.loads(render(report, "json"))["records"] == []


def test_unknown_timestamp_renders_unknown(tmp_path: Path) -> None:
    report = report_for(tmp_path)
    report["records"][0]["metadata"]["deleted_at_utc"] = None
    report["records"][0]["metadata"]["deleted_at_display"] = None
    assert "unknown" in render(report, "table")


def test_invalid_format_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Unknown report format"):
        render(scan(tmp_path.resolve()), "xml")


def test_safe_text_handles_non_string_and_surrogates() -> None:
    assert safe_text(42) == "42"
    assert safe_text("x\udcff") == "x\\udcff"
