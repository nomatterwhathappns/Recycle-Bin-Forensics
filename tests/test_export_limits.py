"""Rendering and exclusive exports enforce exact, bounded UTF-8 output."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from contextlib import contextmanager
from pathlib import Path

import pytest

from rbinforensics import limits as limit_module
from rbinforensics import output
from rbinforensics.html_report import render_html
from rbinforensics.limits import WorkLimitExceeded, WorkLimits, operation_budget
from rbinforensics.reports import iter_render, render, render_csv, render_table

FORMATS = ("json", "csv", "table", "html")


def make_report(input_path: str = "/evidence") -> dict:
    record = {
        "record_type": "metadata",
        "source_path": input_path + "/$Iunicode.txt",
        "source_name": "$Iunicode.txt",
        "source_size": 112,
        "source_sha256": "a" * 64,
        "sid": "S-1-5-21-1001",
        "status": "warning",
        "metadata": {
            "format_version": 2,
            "original_path": '=HYPERLINK("資料&<x>😀")\n\u202e.txt',
            "original_size": 9007199254740993,
            "deletion_filetime": 133485408001234567,
            "deleted_at_utc": "2024-01-01T00:00:00.1234567Z",
            "deleted_at_display": "2024-01-01T00:00:00.1234567+00:00",
        },
        "payload": {
            "status": "available_file",
            "path": input_path + "/$Runicode.txt",
            "size": 7,
            "sha256": "b" * 64,
            "hash_status": "computed",
            "size_matches_metadata": False,
        },
        "issues": [
            {"severity": "warning", "code": "size_mismatch", "message": "資料 <size> & mismatch"}
        ],
    }
    orphan = copy.deepcopy(record)
    orphan.update(
        record_type="orphan_payload",
        source_path=input_path + "/$Rorphan.bin",
        source_name="$Rorphan.bin",
        metadata=None,
        issues=[],
    )
    return {
        "schema_version": "2.0",
        "tool": {"name": "rbinforensics", "version": "1.4.0"},
        "input": input_path,
        "started_at_utc": "2024-02-01T00:00:00+00:00",
        "completed_at_utc": "2024-02-01T00:00:01+00:00",
        "options": {"case_id": "CASE & 資料", "examiner": "Analyst", "timezone": "UTC"},
        "summary": {
            "candidates": 1,
            "parsed": 1,
            "errors": 0,
            "warnings": 2,
            "skipped": 0,
            "orphan_payloads": 1,
        },
        "records": [record, orphan],
    }


@pytest.fixture
def report(tmp_path: Path) -> dict:
    source = tmp_path / "evidence"
    source.mkdir()
    return make_report(str(source))


@pytest.mark.parametrize("format_name", FORMATS)
def test_exact_utf8_boundary_and_one_byte_over(format_name: str) -> None:
    report = make_report()
    before = copy.deepcopy(report)
    expected = render(report, format_name)
    size = len(expected.encode("utf-8"))
    assert render(report, format_name, limits=WorkLimits(max_export_bytes=size)) == expected
    with pytest.raises(WorkLimitExceeded) as failure:
        render(report, format_name, limits=WorkLimits(max_export_bytes=size - 1))
    assert failure.value.resource == "max_export_bytes"
    assert failure.value.limit == size - 1
    assert failure.value.observed > failure.value.limit
    assert report == before
    if format_name != "json":
        assert size > len(expected), "The boundary fixture must contain UTF-8 multibyte text."


@pytest.mark.parametrize("format_name", FORMATS)
def test_iterator_checks_bytes_before_yielding_and_streams(format_name: str) -> None:
    report = make_report()
    expected = render(report, format_name)
    size = len(expected.encode("utf-8"))
    chunks = list(iter_render(report, format_name, limits=WorkLimits(max_export_bytes=size)))
    assert "".join(chunks) == expected
    assert len(chunks) > 1
    assert all(len(chunk.encode("utf-8")) < size for chunk in chunks)
    accepted = []
    with pytest.raises(WorkLimitExceeded, match="max_export_bytes"):
        for chunk in iter_render(report, format_name, limits=WorkLimits(max_export_bytes=size - 1)):
            accepted.append(chunk)
    assert sum(len(chunk.encode("utf-8")) for chunk in accepted) <= size - 1


@pytest.mark.parametrize("format_name", FORMATS)
def test_file_export_exact_boundary_is_not_double_charged(
    report: dict, tmp_path: Path, format_name: str
) -> None:
    expected = render(report, format_name).encode("utf-8")
    destination = tmp_path / ("report." + format_name)
    result = output.write_report(
        report, destination, format_name, limits=WorkLimits(max_export_bytes=len(expected))
    )
    assert result == destination
    assert result.read_bytes() == expected


@pytest.mark.parametrize("format_name", FORMATS)
def test_failed_size_limited_export_removes_its_partial_file(
    report: dict, tmp_path: Path, monkeypatch, format_name: str
) -> None:
    size = len(render(report, format_name).encode("utf-8"))
    destination = tmp_path / ("report." + format_name)
    original_open = Path.open
    written = []

    class TrackedStream:
        def __init__(self, stream):
            self.stream = stream

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def write(self, chunk):
            result = self.stream.write(chunk)
            written.append(chunk)
            return result

    @contextmanager
    def track_open(path, *args, **kwargs):
        with original_open(path, *args, **kwargs) as stream:
            yield TrackedStream(stream) if path == destination else stream

    monkeypatch.setattr(Path, "open", track_open)
    with pytest.raises(WorkLimitExceeded, match="max_export_bytes") as failure:
        output.write_report(
            report, destination, format_name, limits=WorkLimits(max_export_bytes=size - 1)
        )
    assert failure.value.operation == "export"
    assert written, "The limit must be exercised after a partial streamed write."
    assert not destination.exists()


@pytest.mark.parametrize("format_name", FORMATS)
def test_render_limits_include_full_scan_records_even_when_selection_is_empty(
    format_name: str,
) -> None:
    report = make_report()
    report["selection"] = {
        "active": True,
        "filters": {"query": "absent"},
        "record_indexes": [],
        "matched": 0,
        "excluded": 2,
    }
    with pytest.raises(WorkLimitExceeded, match="max_records"):
        render(report, format_name, limits=WorkLimits(max_records=1))


@pytest.mark.parametrize("format_name", FORMATS)
def test_iterator_rechecks_deadline_between_chunks(monkeypatch, format_name: str) -> None:
    clock = [0.0]
    monkeypatch.setattr(limit_module, "monotonic", lambda: clock[0])
    iterator = iter_render(make_report(), format_name, limits=WorkLimits(max_operation_seconds=1))
    assert next(iterator)
    clock[0] = 1.001
    with pytest.raises(WorkLimitExceeded, match="max_operation_seconds"):
        next(iterator)


@pytest.mark.parametrize(
    "replace",
    [
        False,
        pytest.param(
            True,
            marks=pytest.mark.skipif(
                os.name == "nt", reason="Windows prevents replacing an open output handle"
            ),
        ),
    ],
)
def test_deadline_failure_cleans_only_the_created_file(
    report: dict, tmp_path: Path, monkeypatch, replace: bool
) -> None:
    clock = [0.0]
    monkeypatch.setattr(limit_module, "monotonic", lambda: clock[0])
    destination = tmp_path / "report.json"
    original_open = Path.open
    wrote = []

    class SlowStream:
        def __init__(self, stream):
            self.stream = stream

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def write(self, chunk):
            result = self.stream.write(chunk)
            wrote.append(chunk)
            if replace and len(wrote) == 1:
                destination.unlink()
                with original_open(destination, "w", encoding="utf-8") as replacement:
                    replacement.write("another writer's output")
            clock[0] = 2.0
            return result

    @contextmanager
    def slow_open(path, *args, **kwargs):
        with original_open(path, *args, **kwargs) as stream:
            yield SlowStream(stream) if path == destination else stream

    monkeypatch.setattr(Path, "open", slow_open)
    with pytest.raises(WorkLimitExceeded, match="max_operation_seconds") as failure:
        output.write_report(report, destination, "json", limits=WorkLimits(max_operation_seconds=1))
    assert failure.value.operation == "export"
    assert wrote
    if replace:
        assert destination.read_text("utf-8") == "another writer's output"
    else:
        assert not destination.exists()


@pytest.mark.parametrize("stage", ["fsync", "close"])
def test_deadline_during_finalization_does_not_leave_a_successful_export(
    report: dict, tmp_path: Path, monkeypatch, stage: str
) -> None:
    clock = [0.0]
    monkeypatch.setattr(limit_module, "monotonic", lambda: clock[0])
    destination = tmp_path / "report.json"
    if stage == "fsync":
        original_fsync = output.os.fsync

        def expire_after_fsync(descriptor):
            original_fsync(descriptor)
            clock[0] = 2.0

        monkeypatch.setattr(output.os, "fsync", expire_after_fsync)
    else:
        original_open = Path.open

        @contextmanager
        def expire_after_close(path, *args, **kwargs):
            with original_open(path, *args, **kwargs) as stream:
                yield stream
            if path == destination:
                clock[0] = 2.0

        monkeypatch.setattr(Path, "open", expire_after_close)
    with pytest.raises(WorkLimitExceeded, match="max_operation_seconds"):
        output.write_report(report, destination, "json", limits=WorkLimits(max_operation_seconds=1))
    assert not destination.exists()


@pytest.mark.parametrize("format_name", FORMATS)
def test_outer_operation_budget_is_reused_without_double_charging(format_name: str) -> None:
    report = make_report()
    size = len(render(report, format_name).encode("utf-8"))
    with operation_budget(WorkLimits(max_export_bytes=size), operation="export") as budget:
        assert len(render(report, format_name).encode("utf-8")) == size
        assert budget.export_bytes == size


def test_json_stream_keeps_the_existing_indented_faithful_representation() -> None:
    report = make_report()
    assert (
        render(report, "json")
        == json.dumps(report, ensure_ascii=True, indent=2, allow_nan=False) + "\n"
    )


@pytest.mark.parametrize("renderer", [render_csv, render_table, render_html])
def test_legacy_renderer_entry_points_enforce_the_same_byte_limit(renderer) -> None:
    report = make_report()
    expected = renderer(report)
    size = len(expected.encode("utf-8"))
    assert renderer(report, limits=WorkLimits(max_export_bytes=size)) == expected
    with pytest.raises(WorkLimitExceeded, match="max_export_bytes"):
        renderer(report, limits=WorkLimits(max_export_bytes=size - 1))


@pytest.mark.parametrize(
    "format_name,expected_sha256",
    [
        ("csv", "0130c8d9eaef9c000785343d2b39004532f3729ab29b7cf78e6c816442431e5a"),
        ("table", "f461700110bcbe26cbe9d6a8bf46939db996c21cbb1fa4fd32796ffcf2026cd9"),
        ("html", "1addd9f3ff0ba903202584ed4eddb06993d1df77ce069f216c7a88f613cd62d8"),
    ],
)
def test_streaming_preserves_existing_presentation_bytes(
    format_name: str, expected_sha256: str
) -> None:
    # Captured from the version 1.4 renderers for this fixed Unicode/escaping fixture.
    content = render(make_report(), format_name).encode("utf-8")
    assert hashlib.sha256(content).hexdigest() == expected_sha256
