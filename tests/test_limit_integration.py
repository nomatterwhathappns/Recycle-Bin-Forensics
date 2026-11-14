"""Work limits preserve complete evidence reports across CLI and desktop phases."""

from __future__ import annotations

import json
import struct
from pathlib import Path
from queue import Empty

import pytest

from rbinforensics import cli
from rbinforensics import limits as limits_module
from rbinforensics.analysis import FilterOptions
from rbinforensics.desktop import DesktopSession
from rbinforensics.limits import WorkLimitExceeded, WorkLimits
from rbinforensics.reports import render
from rbinforensics.scanner import ScanOptions, scan


@pytest.fixture
def evidence(tmp_path: Path) -> Path:
    directory = tmp_path.resolve() / "evidence"
    directory.mkdir()
    for suffix, original, content in (
        ("ONE.pdf", r"C:\Case\report.pdf", b"report"),
        ("TWO.txt", r"C:\Case\notes.txt", b"notes"),
    ):
        encoded = (original + "\0").encode("utf-16-le")
        (directory / ("$I" + suffix)).write_bytes(
            struct.pack("<QQQI", 2, len(content), 133485408001234567, len(encoded) // 2) + encoded
        )
        (directory / ("$R" + suffix)).write_bytes(content)
    return directory


def _join(session: DesktopSession) -> None:
    assert session.worker is not None
    session.worker.join(timeout=5)
    assert not session.worker.is_alive(), "Desktop operation did not finish"


def _events(session: DesktopSession) -> list[tuple[str, object]]:
    result = []
    while True:
        try:
            result.append(session.events.get_nowait())
        except Empty:
            return result


def _complete(evidence: Path, limits: WorkLimits | None = None) -> DesktopSession:
    session = DesktopSession()
    session.start_scan(evidence, ScanOptions(hash_payload=True, limits=limits))
    _join(session)
    assert session.state == "complete", session.error
    return session


@pytest.mark.parametrize(
    ("flag", "resource"),
    [
        ("--max-records", "max_records"),
        ("--max-payload-hash-bytes", "max_payload_hash_bytes"),
        ("--max-metadata-bytes", "max_metadata_bytes"),
        ("--max-visited-entries", "max_visited_entries"),
    ],
)
@pytest.mark.parametrize("to_file", [False, True])
def test_cli_scan_limit_has_no_completed_json_or_source_changes(
    evidence: Path, capsys: pytest.CaptureFixture, flag: str, resource: str, to_file: bool
) -> None:
    before = {path.name: path.read_bytes() for path in evidence.iterdir()}
    target = evidence.parent / "incomplete.json"
    args = ["scan", str(evidence), "--hash-payload", "--format", "json", flag, "1"]
    if to_file:
        args += ["--output", str(target)]
    assert cli.main(args) == 3
    captured = capsys.readouterr()
    assert captured.out == ""
    assert resource in captured.err
    assert "incomplete" in captured.err
    assert "No completed output" in captured.err
    assert not target.exists()
    assert {path.name: path.read_bytes() for path in evidence.iterdir()} == before


def test_cli_depth_limit_does_not_turn_nested_scope_into_a_complete_report(
    evidence: Path, capsys: pytest.CaptureFixture
) -> None:
    nested = evidence / "SID"
    nested.mkdir()
    (nested / "$IDEEP.txt").write_bytes((evidence / "$ITWO.txt").read_bytes())
    assert (
        cli.main(["scan", str(evidence), "--recursive", "--format", "json", "--max-depth", "0"])
        == 3
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "max_depth" in captured.err


def test_cli_operation_deadline_returns_limit_exit_without_stdout(
    evidence: Path, capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    times = iter(range(100))
    monkeypatch.setattr(limits_module, "monotonic", lambda: next(times))
    assert (
        cli.main(["scan", str(evidence), "--format", "json", "--max-operation-seconds", "0.5"]) == 3
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "max_operation_seconds" in captured.err


@pytest.mark.parametrize("format_name", ["json", "csv", "html", "table"])
@pytest.mark.parametrize("to_file", [False, True])
def test_cli_export_limit_leaves_no_partial_stdout_or_file(
    evidence: Path, capsys: pytest.CaptureFixture, format_name: str, to_file: bool
) -> None:
    target = evidence.parent / ("incomplete." + format_name)
    args = [
        "scan",
        str(evidence),
        "--format",
        format_name,
        "--max-export-bytes",
        "512",
    ]
    if to_file:
        args += ["--output", str(target)]
    assert cli.main(args) == 3
    captured = capsys.readouterr()
    assert captured.out == ""
    assert ("export incomplete" if to_file else "render incomplete") in captured.err
    assert "max_export_bytes" in captured.err
    assert "Report saved" not in captured.err
    assert not target.exists()


@pytest.mark.parametrize(
    ("flag", "value"),
    [
        ("--max-records", "0"),
        ("--max-payload-hash-bytes", "-1"),
        ("--max-metadata-bytes", "0"),
        ("--max-depth", "-1"),
        ("--max-operation-seconds", "0"),
        ("--max-operation-seconds", "nan"),
        ("--max-operation-seconds", "inf"),
        ("--max-export-bytes", "0"),
        ("--max-visited-entries", "0"),
    ],
)
def test_cli_invalid_budget_values_remain_usage_errors(
    evidence: Path, capsys: pytest.CaptureFixture, flag: str, value: str
) -> None:
    target = evidence.parent / "invalid.json"
    assert cli.main(["scan", str(evidence), "--output", str(target), flag, value]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert flag[2:].replace("-", "_") in captured.err
    assert not target.exists()


@pytest.mark.parametrize(
    ("flag", "value"),
    [("--max-records", "1.5"), ("--max-depth", "true"), ("--max-operation-seconds", "soon")],
)
def test_cli_invalid_budget_types_exit_two_before_scanning(
    evidence: Path, capsys: pytest.CaptureFixture, flag: str, value: str
) -> None:
    with pytest.raises(SystemExit) as stopped:
        cli.main(["scan", str(evidence), flag, value])
    assert stopped.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "invalid" in captured.err


def test_cli_all_budget_overrides_accept_exact_workload_and_keep_report_options(
    evidence: Path, capsys: pytest.CaptureFixture
) -> None:
    metadata_bytes = sum(path.stat().st_size for path in evidence.glob("$I*"))
    assert (
        cli.main(
            [
                "scan",
                str(evidence),
                "--format",
                "json",
                "--hash-payload",
                "--case-id",
                "LIMIT-CASE",
                "--examiner",
                "Examiner",
                "--max-records",
                "2",
                "--max-payload-hash-bytes",
                "11",
                "--max-metadata-bytes",
                str(metadata_bytes),
                "--max-depth",
                "1",
                "--max-operation-seconds",
                "60",
                "--max-export-bytes",
                "1000000",
                "--max-visited-entries",
                "4",
            ]
        )
        == 0
    )
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert captured.err == ""
    assert report["schema_version"] == "2.0"
    assert report["summary"]["payloads_hashed"] == 2
    assert report["options"] == {
        "recursive": False,
        "hash_payload": True,
        "timezone": "UTC",
        "case_id": "LIMIT-CASE",
        "examiner": "Examiner",
    }


def test_original_five_positional_scan_options_keep_schema_two_contract(evidence: Path) -> None:
    options = ScanOptions(False, True, "UTC", "POSITIONAL", "Examiner")
    assert options.limits is None
    report = scan(evidence, options)
    assert report["options"] == {
        "recursive": False,
        "hash_payload": True,
        "timezone": "UTC",
        "case_id": "POSITIONAL",
        "examiner": "Examiner",
    }
    assert report["schema_version"] == "2.0"


def test_desktop_scan_limit_never_publishes_or_exports_a_complete_inventory(
    evidence: Path,
) -> None:
    session = _complete(evidence)
    limits = WorkLimits(max_records=1)
    session.start_scan(evidence, ScanOptions(limits=limits))
    _join(session)
    assert session.state == "limited"
    assert session.scan_limits == limits
    assert session.view_limits == limits
    assert session.report is None and session.view is None
    assert not session.has_unsaved_report
    assert "incomplete" in session.error
    emitted = _events(session)
    assert emitted[-1] == ("limited", session.error)
    assert not any(name == "complete" for name, _ in emitted)
    target = evidence.parent / "limited.json"
    with pytest.raises(RuntimeError, match="complete analysis"):
        session.start_export(target, "json")
    with pytest.raises(RuntimeError, match="complete analysis"):
        session.export(target, "json")
    assert not target.exists()
    session.start_scan(evidence, ScanOptions(limits=WorkLimits(max_records=2)))
    _join(session)
    assert session.state == "complete", session.error
    assert session.has_unsaved_report


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("saved_before", [False, True])
def test_desktop_filter_limit_preserves_baseline_previous_view_and_saved_state(
    evidence: Path, asynchronous: bool, saved_before: bool
) -> None:
    session = _complete(evidence, WorkLimits(max_records=2))
    baseline = session.report
    previous = session.apply_view(FilterOptions(extensions=("pdf",)))
    previous_limits = session.view_limits
    if saved_before:
        session.export(evidence.parent / "saved-before-filter.json", "json")
    _events(session)
    if asynchronous:
        session.start_filter(FilterOptions(extensions=("txt",)), limits=WorkLimits(max_records=1))
        _join(session)
        assert _events(session)[-1][0] == "filter_limited"
        assert "filter incomplete" in session.error
    else:
        with pytest.raises(WorkLimitExceeded, match="filter incomplete"):
            session.apply_view(FilterOptions(extensions=("txt",)), limits=WorkLimits(max_records=1))
    assert session.state == "complete"
    assert session.report is baseline
    assert session.view is previous
    assert session.view_limits is previous_limits
    assert session.has_unsaved_report is (not saved_before)
    assert previous["selection"]["matched"] == 1
    assert len(previous["records"]) == 2
    session.start_filter(FilterOptions(extensions=("txt",)))
    _join(session)
    assert session.state == "complete", session.error
    assert session.view is not previous
    assert session.view["timeline"]["events"][0]["original_path"].endswith("notes.txt")


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("saved_before", [False, True])
def test_desktop_limited_json_cleanup_keeps_inventory_unsaved_until_full_success(
    evidence: Path, asynchronous: bool, saved_before: bool
) -> None:
    session = _complete(evidence)
    baseline = session.report
    view = session.apply_view(FilterOptions(extensions=("pdf",)))
    if saved_before:
        session.export(evidence.parent / "earlier-save.json", "json")
    required_bytes = len(render(view, "json").encode("utf-8"))
    target = evidence.parent / "retry-save.json"
    limits = WorkLimits(max_export_bytes=required_bytes - 1)
    if asynchronous:
        session.start_export(target, "json", limits=limits)
        _join(session)
    else:
        with pytest.raises(WorkLimitExceeded, match="export incomplete"):
            session.export(target, "json", limits=limits)
    assert _events(session)[-1][0] == "export_limited"
    assert not target.exists()
    assert session.state == "complete"
    assert session.report is baseline and session.view is view
    assert session.has_unsaved_report is (not saved_before)
    session.export(target, "json", limits=WorkLimits(max_export_bytes=required_bytes))
    assert _events(session)[-1] == ("exported", target)
    assert not session.has_unsaved_report
    saved = json.loads(target.read_text("utf-8"))
    assert len(saved["records"]) == 2
    assert saved["selection"]["matched"] == 1


def test_desktop_default_phase_limits_follow_scan_and_overrides_do_not_leak(
    evidence: Path,
) -> None:
    scan_limits = WorkLimits(max_records=2, max_export_bytes=1)
    session = _complete(evidence, scan_limits)
    assert session.scan_limits is scan_limits and session.view_limits is scan_limits
    filter_limits = WorkLimits(max_records=2, max_export_bytes=1_000_000)
    session.start_filter(FilterOptions(extensions=("pdf",)), limits=filter_limits)
    _join(session)
    assert session.view_limits is filter_limits
    target = evidence.parent / "independent-export.json"
    with pytest.raises(WorkLimitExceeded, match="max_export_bytes"):
        session.export(target, "json")
    assert not target.exists()
    assert session.scan_limits is scan_limits
    session.export(target, "json", limits=filter_limits)
    assert target.is_file()
    assert not session.has_unsaved_report
    session.start_filter(FilterOptions())
    _join(session)
    assert session.state == "complete", session.error
    assert session.view_limits is scan_limits
    assert session.scan_limits is scan_limits


def test_desktop_scan_filter_and_export_each_start_a_fresh_deadline(
    evidence: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [0.0]
    monkeypatch.setattr(limits_module, "monotonic", lambda: clock[0])
    session = _complete(evidence, WorkLimits(max_operation_seconds=1))
    clock[0] = 100.0
    session.start_filter(FilterOptions(extensions=("txt",)))
    _join(session)
    assert session.state == "complete", session.error
    assert _events(session)[-1][0] == "filtered"
    clock[0] = 200.0
    target = evidence.parent / "fresh-operation.json"
    session.start_export(target, "json")
    _join(session)
    assert session.state == "complete", session.error
    assert _events(session)[-1] == ("exported", target)
    assert target.is_file() and not session.has_unsaved_report


@pytest.mark.parametrize("override", [False, 0, {}, ""])
@pytest.mark.parametrize("method", ["apply_view", "start_filter", "export", "start_export"])
def test_invalid_desktop_limit_overrides_do_not_silently_use_scan_defaults(
    evidence: Path, override, method: str
) -> None:
    session = _complete(evidence)
    baseline, view = session.report, session.view
    before_limits = session.view_limits
    _events(session)
    target = evidence.parent / "invalid-override.json"
    if method == "apply_view":
        with pytest.raises(TypeError, match="WorkLimits"):
            session.apply_view(FilterOptions(), limits=override)
    elif method == "export":
        with pytest.raises(TypeError, match="WorkLimits"):
            session.export(target, "json", limits=override)
        assert _events(session)[-1][0] == "export_error"
    elif method == "start_filter":
        session.start_filter(FilterOptions(), limits=override)
        _join(session)
        assert _events(session)[-1][0] == "filter_error"
        assert "WorkLimits" in session.error
    else:
        session.start_export(target, "json", limits=override)
        _join(session)
        assert _events(session)[-1][0] == "export_error"
        assert "WorkLimits" in session.error
    assert session.state == "complete"
    assert session.report is baseline and session.view is view
    assert session.view_limits is before_limits
    assert session.has_unsaved_report
    assert not target.exists()
