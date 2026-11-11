"""End-to-end selected views keep the complete scan and its failures auditable."""

from __future__ import annotations

import csv
import io
import json
import struct
from pathlib import Path

import pytest

from rbinforensics.cli import main

BASE_TICKS = 133_485_408_001_234_560


def write_item(directory: Path, suffix: str, original: str, size: int, tick: int):
    encoded = (original + "\0").encode("utf-16-le")
    (directory / ("$I" + suffix)).write_bytes(
        struct.pack("<QQQI", 2, size, tick, len(encoded) // 2) + encoded
    )


@pytest.fixture
def evidence(tmp_path: Path) -> Path:
    directory = tmp_path.resolve() / "evidence"
    directory.mkdir()
    write_item(directory, "A.pdf", r"C:\Users\Analyst\budget.pdf", 10, BASE_TICKS + 1)
    write_item(directory, "B.txt", r"C:\Users\Analyst\notes.txt", 20, BASE_TICKS + 2)
    write_item(directory, "C.pdf", r"C:\Users\Analyst\meeting.pdf", 30, BASE_TICKS + 3)
    return directory


def test_cli_query_json_retains_scan_but_selects_one_record(evidence: Path, capsys):
    assert main(["scan", str(evidence), "--query", "BUDGET", "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["parsed"] == 3
    assert len(report["records"]) == 3
    assert report["selection"]["active"] is True
    assert report["selection"]["matched"] == 1
    assert report["selection"]["excluded"] == 2
    event = report["timeline"]["events"][0]
    assert event["original_path"].endswith("budget.pdf")
    assert report["timeline"]["daily_counts"] == [{"date_utc": "2024-01-01", "count": 1}]


def test_csv_exports_only_selected_records(evidence: Path, capsys):
    assert (
        main(["scan", str(evidence), "--extension", "PDF", "--max-size", "15", "--format", "csv"])
        == 0
    )
    rows = list(csv.DictReader(io.StringIO(capsys.readouterr().out)))
    assert len(rows) == 1
    assert rows[0]["original_path"].endswith("budget.pdf")


def test_repeatable_extensions_are_or_within_and_combined_filters(evidence: Path, capsys):
    assert (
        main(
            [
                "scan",
                str(evidence),
                "--extension",
                ".pdf",
                "--extension",
                "txt",
                "--min-size",
                "20",
                "--format",
                "json",
            ]
        )
        == 0
    )
    report = json.loads(capsys.readouterr().out)
    selected = [report["records"][index] for index in report["selection"]["record_indexes"]]
    assert {record["metadata"]["original_size"] for record in selected} == {20, 30}
    assert report["selection"]["filters"]["extensions"] == [".pdf", ".txt"]


def test_deletion_bounds_preserve_100ns_precision(evidence: Path, capsys):
    assert (
        main(
            [
                "scan",
                str(evidence),
                "--deleted-after",
                "2024-01-01T00:00:00.1234562Z",
                "--deleted-before",
                "2024-01-01T00:00:00.1234562Z",
                "--format",
                "json",
            ]
        )
        == 0
    )
    report = json.loads(capsys.readouterr().out)
    assert report["selection"]["matched"] == 1
    assert [event["deletion_filetime"] for event in report["timeline"]["events"]] == [
        BASE_TICKS + 2
    ]


def test_date_bounds_are_utc_even_when_display_zone_is_different(evidence: Path, capsys):
    assert (
        main(
            [
                "scan",
                str(evidence),
                "--timezone",
                "Asia/Jakarta",
                "--deleted-after",
                "2024-01-01",
                "--deleted-before",
                "2024-01-02",
                "--format",
                "json",
            ]
        )
        == 0
    )
    report = json.loads(capsys.readouterr().out)
    assert report["selection"]["matched"] == 3
    assert report["timeline"]["events"][0]["deleted_at_display"].endswith("+07:00")


def test_sid_filter_uses_acquired_context(evidence: Path, capsys):
    sid = "S-1-5-21-111-222-333-1001"
    nested = evidence / sid
    nested.mkdir()
    write_item(nested, "D.pdf", r"C:\Users\Other\document.pdf", 40, BASE_TICKS + 4)
    assert main(["scan", str(evidence), "--recursive", "--sid", sid, "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["parsed"] == 4
    assert report["selection"]["matched"] == 1
    assert report["timeline"]["by_sid"] == [{"sid": sid, "count": 1}]


def test_filters_cannot_turn_corrupt_evidence_into_success(evidence: Path, capsys):
    (evidence / "$IBROKEN.txt").write_bytes(b"broken")
    assert main(["scan", str(evidence), "--query", "budget", "--format", "json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["errors"] == 1
    assert len(report["records"]) == 4
    assert any(record["status"] == "error" for record in report["records"])
    assert report["selection"]["matched"] == 2
    selected = [report["records"][index] for index in report["selection"]["record_indexes"]]
    assert any(record["status"] == "error" for record in selected)


def test_empty_selection_is_a_successful_scan(evidence: Path, capsys):
    assert main(["scan", str(evidence), "--query", "nothing-matches", "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["selection"]["matched"] == 0
    assert report["summary"]["candidates"] == 3
    assert report["timeline"]["events"] == []


def test_orphan_only_inventory_is_successful(tmp_path: Path, capsys):
    evidence = tmp_path.resolve() / "evidence"
    evidence.mkdir()
    (evidence / "$RLONE.pdf").write_bytes(b"content")
    assert main(["scan", str(evidence), "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["candidates"] == 0
    assert report["summary"]["orphan_payloads"] == 1
    assert report["timeline"]["events"] == []


@pytest.mark.parametrize(
    "arguments",
    [
        ["--min-size", "-1"],
        ["--min-size", "20", "--max-size", "10"],
        ["--deleted-after", "2024-01-02", "--deleted-before", "2024-01-01"],
        ["--deleted-after", "2024-01-01T00:00:00"],
        ["--deleted-before", "2024-99-01"],
        ["--extension", "*.pdf"],
    ],
)
def test_invalid_filter_options_do_not_write_output(
    evidence: Path, tmp_path: Path, capsys, arguments
):
    output = tmp_path.resolve() / "report.json"
    assert main(["scan", str(evidence), "--output", str(output), *arguments]) == 2
    assert not output.exists()
    assert "rbf:" in capsys.readouterr().err


def test_html_report_is_written_as_utf8_outside_evidence(evidence: Path, tmp_path: Path, capsys):
    output = tmp_path.resolve() / "report.html"
    assert main(["scan", str(evidence), "--format", "html", "--output", str(output)]) == 0
    content = output.read_text(encoding="utf-8")
    assert "<!doctype html" in content.lower()
    assert "budget.pdf" in content
    assert "Content-Security-Policy" in content
    assert capsys.readouterr().out == ""
