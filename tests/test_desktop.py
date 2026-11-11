"""Desktop coordination with real evidence, deterministic barriers, and exports."""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path
from queue import Empty
from threading import Event

import pytest

from rbinforensics import desktop
from rbinforensics.analysis import FilterOptions
from rbinforensics.desktop import DesktopSession
from rbinforensics.scan_control import ScanCancelled, ScanProgress
from rbinforensics.scanner import ScanOptions


@pytest.fixture
def evidence(tmp_path: Path) -> Path:
    directory = tmp_path.resolve() / "evidence"
    directory.mkdir()
    for suffix, path, content in (
        ("ABC.pdf", r"C:\Users\Analyst\report.pdf", b"report"),
        ("DEF.txt", r"C:\Users\Analyst\notes.txt", b"notes"),
    ):
        encoded = (path + "\0").encode("utf-16-le")
        (directory / ("$I" + suffix)).write_bytes(
            struct.pack("<QQQI", 2, len(content), 133485408001234567, len(encoded) // 2) + encoded
        )
        (directory / ("$R" + suffix)).write_bytes(content)
    return directory


def join_worker(session: DesktopSession) -> None:
    assert session.worker is not None
    session.worker.join(timeout=5)
    assert not session.worker.is_alive(), "Desktop job did not finish."


def events(session: DesktopSession) -> list[tuple[str, object]]:
    result = []
    while True:
        try:
            result.append(session.events.get_nowait())
        except Empty:
            return result


def completed(evidence: Path) -> DesktopSession:
    session = DesktopSession()
    session.start_scan(evidence, ScanOptions(hash_payload=True))
    join_worker(session)
    assert session.state == "complete", session.error
    return session


def test_idle_session_has_no_exportable_result(tmp_path: Path) -> None:
    session = DesktopSession()
    assert session.state == "idle"
    assert session.report is None
    assert session.view is None
    assert session.worker is None
    assert session.cancel() is False
    with pytest.raises(RuntimeError, match="complete analysis"):
        session.apply_view(FilterOptions())
    with pytest.raises(RuntimeError, match="complete analysis"):
        session.export(tmp_path / "report.json", "json")
    with pytest.raises(RuntimeError, match="complete analysis"):
        session.start_export(tmp_path / "report.json", "json")


def test_real_scan_publishes_complete_report_and_progress(evidence: Path) -> None:
    session = completed(evidence)
    assert session.error is None
    assert session.view is session.report
    assert session.report["summary"]["parsed"] == 2
    assert session.report["summary"]["payloads_hashed"] == 2
    emitted = events(session)
    assert emitted[-1] == ("complete", session.report)
    assert sum(name == "complete" for name, _ in emitted) == 1
    assert all(isinstance(value, ScanProgress) for name, value in emitted if name == "progress")
    assert any(name == "progress" for name, _ in emitted)
    assert session.cancel() is False


def test_scan_runs_in_worker_and_rejects_overlapping_jobs(
    evidence: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    entered = Event()
    release = Event()

    def blocked_scan(*args, control, **kwargs):
        entered.set()
        assert release.wait(5)
        control.check()
        return {"records": [], "summary": {}}

    monkeypatch.setattr(desktop, "scan", blocked_scan)
    session = DesktopSession()
    session.start_scan(evidence, ScanOptions())
    assert entered.wait(2), "Scan worker did not start."
    try:
        assert session.state == "scanning"
        assert session.worker.is_alive()
        assert session.report is None
        with pytest.raises(RuntimeError, match="already running"):
            session.start_scan(evidence, ScanOptions())
        with pytest.raises(RuntimeError, match="complete analysis"):
            session.start_export(evidence.parent / "report.json", "json")
        with pytest.raises(RuntimeError, match="complete analysis"):
            session.apply_view(FilterOptions())
    finally:
        release.set()
        join_worker(session)
    assert session.state == "complete"


def test_cancelled_scan_clears_old_report_and_never_exports_partial_results(
    evidence: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = completed(evidence)
    session.events.put(("complete", {"stale": True}))
    entered = Event()
    release = Event()

    def blocked_scan(*args, control, **kwargs):
        entered.set()
        assert release.wait(5)
        control.check()
        pytest.fail("A cancelled worker must not publish a report.")

    monkeypatch.setattr(desktop, "scan", blocked_scan)
    session.start_scan(evidence, ScanOptions())
    assert entered.wait(2)
    assert session.report is None
    assert session.view is None
    assert session.cancel() is True
    release.set()
    join_worker(session)
    assert session.state == "cancelled"
    assert session.error is None
    assert events(session) == [("cancelled", None)]
    with pytest.raises(RuntimeError, match="complete analysis"):
        session.export(evidence.parent / "cancelled.json", "json")
    assert not (evidence.parent / "cancelled.json").exists()


def test_late_cancel_before_publication_cannot_report_success(
    evidence: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def apparently_done_scan(*args, control, **kwargs):
        control.cancel()
        # A scanner could finish just as the operator presses cancel; the
        # coordinator independently checks cancellation before publishing.
        return {"records": [], "summary": {}}

    monkeypatch.setattr(desktop, "scan", apparently_done_scan)
    session = DesktopSession()
    session.start_scan(evidence, ScanOptions())
    join_worker(session)
    assert session.state == "cancelled"
    assert session.report is None
    assert events(session) == [("cancelled", None)]


def test_worker_error_is_visible_and_old_results_are_not_reused(
    evidence: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = completed(evidence)

    def failed_scan(*args, **kwargs):
        raise PermissionError("Unreadable source\x1b[2J")

    monkeypatch.setattr(desktop, "scan", failed_scan)
    session.start_scan(evidence, ScanOptions())
    join_worker(session)
    assert session.state == "error"
    assert session.error == r"Unreadable source\u001b[2J"
    assert session.report is None
    assert session.view is None
    assert events(session) == [("error", session.error)]
    with pytest.raises(RuntimeError):
        session.start_export(evidence.parent / "failed.json", "json")


def test_filters_always_reselect_from_full_scan_and_preserve_audit(evidence: Path) -> None:
    session = completed(evidence)
    baseline = json.dumps(session.report, sort_keys=True)
    view = session.apply_view(FilterOptions(extensions=(".pdf",)))
    assert view["selection"]["matched"] == 1
    assert len(view["records"]) == 2
    assert len(view["timeline"]["events"]) == 1
    view = session.apply_view(FilterOptions(extensions=(".txt",)))
    assert view["selection"]["matched"] == 1
    assert view["timeline"]["events"][0]["original_path"].endswith("notes.txt")
    assert json.dumps(session.report, sort_keys=True) == baseline
    assert session.apply_view(FilterOptions())["selection"]["matched"] == 2


def test_invalid_filters_keep_previous_view(evidence: Path) -> None:
    session = completed(evidence)
    before = session.view
    with pytest.raises(ValueError):
        session.apply_view(FilterOptions(min_size=10, max_size=1))
    assert session.view is before
    assert session.state == "complete"


def test_export_preserves_full_json_and_selected_view(evidence: Path) -> None:
    session = completed(evidence)
    session.apply_view(FilterOptions(extensions=(".pdf",)))
    target = evidence.parent / "selected.json"
    assert session.export(target, "json") == target
    report = json.loads(target.read_text("utf-8"))
    assert report["selection"]["matched"] == 1
    assert len(report["records"]) == 2
    assert report["summary"]["payloads_hashed"] == 2
    expected = hashlib.sha256(b"report").hexdigest()
    pdf = next(r for r in report["records"] if r["source_name"].endswith("ABC.pdf"))
    assert pdf["payload"]["sha256"] == expected
    assert session.state == "complete"
    assert events(session)[-1] == ("exported", target)


@pytest.mark.parametrize("format_name", ["json", "csv", "html"])
def test_async_export_creates_report_and_reports_completion(
    evidence: Path, format_name: str
) -> None:
    session = completed(evidence)
    target = evidence.parent / ("report." + format_name)
    session.start_export(target, format_name)
    join_worker(session)
    assert target.is_file()
    assert target.stat().st_size > 0
    assert session.state == "complete"
    assert session.error is None
    assert events(session)[-1] == ("exported", target)


def test_export_failure_retains_complete_analysis_and_never_overwrites(evidence: Path) -> None:
    session = completed(evidence)
    baseline = session.report
    view = session.view
    target = evidence.parent / "existing.json"
    target.write_text("previous report", encoding="utf-8")
    session.start_export(target, "json")
    join_worker(session)
    assert session.state == "complete"
    assert session.report is baseline
    assert session.view is view
    assert session.error
    assert events(session)[-1][0] == "export_error"
    assert target.read_text("utf-8") == "previous report"


def test_synchronous_export_propagates_failure_but_preserves_result(evidence: Path) -> None:
    session = completed(evidence)
    baseline = session.report
    target = evidence / "report.json"
    with pytest.raises(ValueError, match="outside"):
        session.export(target, "json")
    assert not target.exists()
    assert session.state == "complete"
    assert session.report is baseline
    assert events(session)[-1][0] == "export_error"


def test_background_export_does_not_block_and_guards_view(
    evidence: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = completed(evidence)
    entered = Event()
    release = Event()
    target = evidence.parent / "export.json"

    def blocked_write(report, destination, format_name):
        entered.set()
        assert release.wait(5)
        return destination

    monkeypatch.setattr(desktop, "write_report", blocked_write)
    session.start_export(target, "json")
    assert entered.wait(2)
    try:
        assert session.state == "exporting"
        assert session.worker.is_alive()
        assert session.cancel() is False
        with pytest.raises(RuntimeError, match="complete analysis"):
            session.apply_view(FilterOptions())
        with pytest.raises(RuntimeError, match="already running"):
            session.start_scan(evidence, ScanOptions())
        with pytest.raises(RuntimeError, match="complete analysis"):
            session.start_export(target, "json")
    finally:
        release.set()
        join_worker(session)
    assert session.state == "complete"


def test_cancelled_worker_can_be_followed_by_a_new_successful_scan(
    evidence: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_scan = desktop.scan

    def cancelled_scan(*args, **kwargs):
        raise ScanCancelled()

    monkeypatch.setattr(desktop, "scan", cancelled_scan)
    session = DesktopSession()
    session.start_scan(evidence, ScanOptions())
    join_worker(session)
    assert session.state == "cancelled"
    monkeypatch.setattr(desktop, "scan", original_scan)
    session.start_scan(evidence, ScanOptions())
    join_worker(session)
    assert session.state == "complete"
    assert session.report["summary"]["parsed"] == 2
    assert all(name != "cancelled" for name, _ in events(session))


def test_async_filter_computes_selected_view_without_mutating_full_scan(evidence: Path) -> None:
    session = completed(evidence)
    baseline = json.dumps(session.report, sort_keys=True)
    session.start_filter(FilterOptions(extensions=(".pdf",)))
    join_worker(session)
    assert session.state == "complete"
    assert session.view["selection"]["matched"] == 1
    assert len(session.view["records"]) == 2
    assert len(session.view["timeline"]["events"]) == 1
    assert json.dumps(session.report, sort_keys=True) == baseline
    assert events(session) == [("filtered", session.view)]
    session.start_filter(FilterOptions(extensions=(".txt",)))
    join_worker(session)
    assert session.view["timeline"]["events"][0]["original_path"].endswith("notes.txt")


def test_async_filter_failure_preserves_previous_complete_view(evidence: Path) -> None:
    session = completed(evidence)
    before_report, before_view = session.report, session.view
    session.start_filter(FilterOptions(min_size=10, max_size=1))
    join_worker(session)
    assert session.state == "complete"
    assert session.report is before_report
    assert session.view is before_view
    assert session.error
    assert events(session) == [("filter_error", session.error)]


def test_filter_runs_in_worker_and_rejects_overlapping_jobs(
    evidence: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = completed(evidence)
    entered = Event()
    release = Event()
    original = desktop.apply_filters

    def blocked_filter(report, filters):
        entered.set()
        assert release.wait(5)
        return original(report, filters)

    monkeypatch.setattr(desktop, "apply_filters", blocked_filter)
    session.start_filter(FilterOptions())
    assert entered.wait(2)
    try:
        assert session.state == "filtering"
        assert session.worker.is_alive()
        assert session.cancel() is False
        with pytest.raises(RuntimeError, match="already running"):
            session.start_scan(evidence, ScanOptions())
        with pytest.raises(RuntimeError, match="complete analysis"):
            session.start_filter(FilterOptions())
        with pytest.raises(RuntimeError, match="complete analysis"):
            session.start_export(evidence.parent / "report.json", "json")
        with pytest.raises(RuntimeError, match="complete analysis"):
            session.apply_view(FilterOptions())
    finally:
        release.set()
        join_worker(session)
    assert session.state == "complete"


@pytest.mark.parametrize("operation", ["scan", "filter", "export"])
def test_thread_start_failure_recovers_state_and_allows_retry(
    evidence: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    session = completed(evidence)
    old_report, old_view = session.report, session.view
    target = evidence.parent / "retry.json"

    def start_failure(_):
        raise RuntimeError("Cannot start thread\x1b[2J")

    def start_job():
        if operation == "scan":
            session.start_scan(evidence, ScanOptions())
        elif operation == "filter":
            session.start_filter(FilterOptions(extensions=(".pdf",)))
        else:
            session.start_export(target, "json")

    with monkeypatch.context() as context:
        context.setattr(desktop.Thread, "start", start_failure)
        start_job()
    assert session.worker is None
    assert session.error == r"Cannot start thread\u001b[2J"
    if operation == "scan":
        assert session.state == "error"
        assert session.report is None
        assert session.view is None
        assert events(session) == [("error", session.error)]
    else:
        assert session.state == "complete"
        assert session.report is old_report
        assert session.view is old_view
        assert events(session) == [(operation + "_error", session.error)]
    assert not target.exists()
    start_job()
    join_worker(session)
    assert session.state == "complete"
    assert session.error is None
    if operation == "export":
        assert json.loads(target.read_text("utf-8"))["summary"]["parsed"] == 2


def test_progress_is_rate_limited_even_when_phases_change_and_completion_survives(
    evidence: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ticks = iter(index / 1000 for index in range(10_002))
    monkeypatch.setattr(desktop, "monotonic", lambda: next(ticks))
    result = {"records": [], "summary": {}}

    def fast_scan(*args, control, **kwargs):
        for index in range(5000):
            control.emit(
                ScanProgress(
                    "processing" if index % 2 else "hashing",
                    index,
                    5000,
                    source_path=str(evidence / "$IABC.pdf"),
                )
            )
        control.emit(ScanProgress("complete", 5000, 5000))
        return result

    monkeypatch.setattr(desktop, "scan", fast_scan)
    session = DesktopSession()
    session.start_scan(evidence, ScanOptions())
    join_worker(session)
    emitted = events(session)
    progress = [value for name, value in emitted if name == "progress"]
    # Five thousand scanner callbacks represent five deterministic seconds.
    # Rounding at a 50 ms boundary can reduce the count, never increase it
    # beyond the first notification + 20 Hz + final complete notification.
    assert 2 < len(progress) <= 102
    assert progress[0].processed == 0  # Monotonic time 0.0 is not a false sentinel.
    assert progress[-1] == ScanProgress("complete", 5000, 5000)
    assert emitted[-1] == ("complete", result)
    assert sum(name == "complete" for name, _ in emitted) == 1
    assert session.state == "complete"


def test_new_scan_resets_progress_throttle_and_keeps_first_notification(
    evidence: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(desktop, "monotonic", lambda: 0.0)

    def single_instant_scan(*args, control, **kwargs):
        control.emit(ScanProgress("discovering", 0, None))
        control.emit(ScanProgress("processing", 0, 1))
        control.emit(ScanProgress("complete", 1, 1))
        return {"records": [], "summary": {}}

    monkeypatch.setattr(desktop, "scan", single_instant_scan)
    session = DesktopSession()
    for _ in range(2):
        session.start_scan(evidence, ScanOptions())
        join_worker(session)
        emitted = events(session)
        assert [value.phase for name, value in emitted if name == "progress"] == [
            "discovering",
            "complete",
        ]
        assert emitted[-1][0] == "complete"
