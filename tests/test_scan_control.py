"""Progress is observable work; cancellation never produces a complete report."""

from __future__ import annotations

import hashlib
import struct
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import FrozenInstanceError
from pathlib import Path
from threading import Barrier

import pytest

from rbinforensics import scanner
from rbinforensics.scan_control import (
    ProgressCallbackError,
    ScanCancelled,
    ScanControl,
    ScanProgress,
)
from rbinforensics.scanner import ScanOptions, scan


def write_item(directory: Path, suffix: str = "ABC.txt", content: bytes = b"payload") -> Path:
    encoded = (r"C:\Users\Analyst\report.txt" + "\0").encode("utf-16-le")
    path = directory / ("$I" + suffix)
    path.write_bytes(
        struct.pack("<QQQI", 2, len(content), 133485408001234567, len(encoded) // 2) + encoded
    )
    (directory / ("$R" + suffix)).write_bytes(content)
    return path


@pytest.fixture
def evidence(tmp_path: Path) -> Path:
    directory = tmp_path.resolve() / "evidence"
    directory.mkdir()
    return directory


def test_cancel_before_scan_never_reads_or_validates_source(tmp_path: Path) -> None:
    control = ScanControl()
    control.cancel()
    with pytest.raises(ScanCancelled, match="incomplete"):
        scan(tmp_path / "nonexistent", control=control)


def test_progress_events_are_immutable_and_cancellation_is_sticky() -> None:
    event = ScanProgress("discovering", 0, None)
    with pytest.raises(FrozenInstanceError):
        event.processed = 9
    control = ScanControl()
    control.emit(event)
    control.cancel()
    with pytest.raises(ScanCancelled):
        control.emit(event)
    with pytest.raises(ScanCancelled):
        control.check()


def test_discovery_cancel_stops_before_any_candidate_processing(evidence: Path) -> None:
    source = write_item(evidence)
    events = []

    def progress(event: ScanProgress) -> None:
        events.append(event)
        if event.phase == "discovering" and event.source_path == str(source):
            control.cancel()

    control = ScanControl(progress)
    with pytest.raises(ScanCancelled):
        scan(evidence, control=control)
    assert events
    assert all(event.phase == "discovering" for event in events)
    assert all(event.total is None for event in events)


def test_totals_count_metadata_and_orphans_once_and_finish_after_analysis(evidence: Path) -> None:
    write_item(evidence)
    (evidence / "$IBAD").write_bytes(b"broken")
    (evidence / "$RORPHAN.bin").write_bytes(b"orphan")
    directory_payload = evidence / "$RFOLDER"
    directory_payload.mkdir()
    write_item(directory_payload, "INSIDE.txt")
    events: list[ScanProgress] = []
    report = scan(evidence, ScanOptions(recursive=True), control=ScanControl(events.append))
    assert report["summary"]["candidates"] == 2
    assert report["summary"]["orphan_payloads"] == 2
    assert report["summary"]["errors"] == 1
    assert report["summary"]["parsed"] == 1
    discovery = [event for event in events if event.phase == "discovering"]
    assert discovery and all(event.total is None for event in discovery)
    processing = [event for event in events if event.phase == "processing"]
    assert processing and all(event.total == 4 for event in processing)
    assert {event.processed for event in processing} == {0, 1, 2, 3}
    assert events[-1] == ScanProgress("complete", 4, 4, str(evidence))
    assert all(event.processed < event.total for event in processing)
    assert "selection" in report and "timeline" in report


def test_single_file_progress_and_source_hash_match_uncontrolled_run(evidence: Path) -> None:
    source = write_item(evidence)
    events: list[ScanProgress] = []
    controlled = scan(source, ScanOptions(hash_payload=True), control=ScanControl(events.append))
    ordinary = scan(source, ScanOptions(hash_payload=True))
    for report in (controlled, ordinary):
        report.pop("started_at_utc")
        report.pop("completed_at_utc")
    assert controlled == ordinary
    assert events[-1].phase == "complete"
    assert events[-1].processed == events[-1].total == 1
    assert (
        controlled["records"][0]["source_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    )


def test_hashing_reports_real_chunk_bytes_and_preserves_digest(
    evidence: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    content = b"abcdefghijklmnopqrstuvwxyz"
    source = write_item(evidence, content=content)
    monkeypatch.setattr(scanner, "HASH_CHUNK_BYTES", 4)
    events: list[ScanProgress] = []
    report = scan(source, ScanOptions(hash_payload=True), control=ScanControl(events.append))
    hashing = [event for event in events if event.phase == "hashing"]
    assert [event.bytes_processed for event in hashing] == [0, 4, 8, 12, 16, 20, 24, 26]
    assert all(event.bytes_total == len(content) for event in hashing)
    assert all(event.processed == 0 and event.total == 1 for event in hashing)
    assert report["records"][0]["payload"]["sha256"] == hashlib.sha256(content).hexdigest()
    assert events[-1].phase == "complete"


def test_hash_cancel_is_not_a_per_file_error_and_no_partial_hash_is_returned(
    evidence: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    content = b"abcdefghijklmnopqrstuvwxyz"
    source = write_item(evidence, content=content)
    monkeypatch.setattr(scanner, "HASH_CHUNK_BYTES", 4)
    events: list[ScanProgress] = []

    def progress(event: ScanProgress) -> None:
        events.append(event)
        if event.phase == "hashing" and event.bytes_processed == 4:
            control.cancel()

    def unexpected_failure(*args, **kwargs):
        raise AssertionError("Cancellation must not become a payload failure record")

    monkeypatch.setattr(scanner, "_payload_failure", unexpected_failure)
    control = ScanControl(progress)
    with pytest.raises(ScanCancelled):
        scan(source, ScanOptions(hash_payload=True), control=control)
    assert events[-1].phase == "hashing"
    assert events[-1].bytes_processed == 4
    assert not any(event.phase == "complete" for event in events)
    # The cancelled scan's context cannot leak into later uncontrolled reads.
    digest, length = scanner._hash_payload(evidence / "$RABC.txt")
    assert digest == hashlib.sha256(content).hexdigest()
    assert length == len(content)
    assert (evidence / "$RABC.txt").read_bytes() == content


def test_cancel_checkpoint_after_analysis_prevents_completed_report(
    evidence: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = write_item(evidence)
    original = scanner.apply_filters
    events: list[ScanProgress] = []
    control = ScanControl(events.append)

    def cancel_after_selection(*args, **kwargs):
        result = original(*args, **kwargs)
        control.cancel()
        return result

    monkeypatch.setattr(scanner, "apply_filters", cancel_after_selection)
    with pytest.raises(ScanCancelled):
        scan(source, control=control)
    assert not any(event.phase == "complete" for event in events)


def test_callback_io_error_is_not_misreported_as_unreadable_evidence(evidence: Path) -> None:
    source = write_item(evidence)

    def progress(event: ScanProgress) -> None:
        if event.phase == "hashing":
            raise PermissionError("progress consumer failed")

    with pytest.raises(ProgressCallbackError) as stopped:
        scan(source, ScanOptions(hash_payload=True), control=ScanControl(progress))
    assert isinstance(stopped.value.__cause__, PermissionError)
    assert scan(source)["summary"]["errors"] == 0


def test_explicit_callback_cancellation_propagates(evidence: Path) -> None:
    source = write_item(evidence)

    def progress(_: ScanProgress) -> None:
        raise ScanCancelled("explicit callback stop")

    with pytest.raises(ScanCancelled, match="explicit callback stop"):
        scan(source, control=ScanControl(progress))


def test_empty_scan_has_no_invented_total_or_processing_percentage(evidence: Path) -> None:
    events: list[ScanProgress] = []
    report = scan(evidence, control=ScanControl(events.append))
    assert report["records"] == []
    assert events[-1] == ScanProgress("complete", 0, 0, str(evidence))


def test_empty_payload_can_complete_without_a_fabricated_byte_percentage(evidence: Path) -> None:
    source = write_item(evidence, content=b"")
    events: list[ScanProgress] = []
    report = scan(source, ScanOptions(hash_payload=True), control=ScanControl(events.append))
    hashing = [event for event in events if event.phase == "hashing"]
    assert len(hashing) == 1
    assert hashing[0].bytes_processed == hashing[0].bytes_total == 0
    assert report["records"][0]["payload"]["sha256"] == hashlib.sha256(b"").hexdigest()


def test_concurrent_runs_keep_cancellation_and_progress_isolated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = tmp_path.resolve() / "first"
    second = tmp_path.resolve() / "second"
    first.mkdir()
    second.mkdir()
    write_item(first, content=b"first payload")
    write_item(second, content=b"second payload")
    monkeypatch.setattr(scanner, "HASH_CHUNK_BYTES", 4)
    barrier = Barrier(2)
    first_events: list[ScanProgress] = []
    second_events: list[ScanProgress] = []

    def callback(events: list[ScanProgress], cancel: bool):
        synchronized = False

        def on_progress(event: ScanProgress) -> None:
            nonlocal synchronized
            events.append(event)
            if event.phase == "processing" and not synchronized:
                synchronized = True
                barrier.wait(timeout=5)
            if cancel and event.phase == "hashing" and event.bytes_processed > 0:
                first_control.cancel()

        return on_progress

    first_control = ScanControl(callback(first_events, True))
    second_control = ScanControl(callback(second_events, False))
    with ThreadPoolExecutor(max_workers=2) as pool:
        stopped = pool.submit(scan, first, ScanOptions(hash_payload=True), control=first_control)
        completed = pool.submit(
            scan, second, ScanOptions(hash_payload=True), control=second_control
        )
        with pytest.raises(ScanCancelled):
            stopped.result(timeout=10)
        report = completed.result(timeout=10)
    assert report["summary"]["errors"] == 0
    assert report["summary"]["payloads_hashed"] == 1
    assert second_events[-1].phase == "complete"
    assert not any(event.phase == "complete" for event in first_events)
    assert all(str(first) in event.source_path for event in first_events if event.source_path)
    assert all(str(second) in event.source_path for event in second_events if event.source_path)


def test_nested_uncontrolled_scan_restores_outer_progress_context(tmp_path: Path) -> None:
    outer = tmp_path.resolve() / "outer"
    inner = tmp_path.resolve() / "inner"
    outer.mkdir()
    inner.mkdir()
    write_item(outer)
    write_item(inner)
    events: list[ScanProgress] = []
    nested = False

    def progress(event: ScanProgress) -> None:
        nonlocal nested
        events.append(event)
        if event.phase == "processing" and not nested:
            nested = True
            assert scan(inner)["summary"]["parsed"] == 1

    report = scan(outer, control=ScanControl(progress))
    assert report["summary"]["parsed"] == 1
    assert nested
    assert all(str(outer) in event.source_path for event in events if event.source_path)
    assert events[-1].processed == events[-1].total == 1


def link_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"Creating test symlink unavailable: {exc}")


@pytest.mark.parametrize("controlled", [False, True])
def test_redirected_metadata_retains_safe_sibling_observations_without_reading_link(
    evidence: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, controlled: bool
) -> None:
    target = tmp_path.resolve() / "private-metadata-target"
    target.write_bytes(b"MUST NOT BE OPENED AS METADATA")
    source = evidence / "$IABC.txt"
    link_or_skip(source, target)
    content = b"safe acquired payload"
    payload = evidence / "$RABC.txt"
    payload.write_bytes(content)
    original_open = scanner._open_regular

    @contextmanager
    def open_safe_only(path: Path):
        assert path not in (source, target), "Metadata redirect target must never be read"
        with original_open(path) as opened:
            yield opened

    monkeypatch.setattr(scanner, "_open_regular", open_safe_only)
    events: list[ScanProgress] = []
    control = ScanControl(events.append) if controlled else None
    report = scan(evidence, ScanOptions(hash_payload=True), control=control)
    assert len(report["records"]) == 1
    record = report["records"][0]
    assert record["record_type"] == "discovery"
    assert record["source_path"] == str(source)
    assert record["source_sha256"] is None
    assert record["source_size"] is None
    assert record["metadata"] is None
    assert record["status"] == "skipped"
    assert record["payload"]["path"] == str(payload)
    assert record["payload"]["sha256"] == hashlib.sha256(content).hexdigest()
    assert record["payload"]["size_matches_metadata"] is None
    assert report["summary"]["orphan_payloads"] == 0
    assert report["summary"]["payloads_hashed"] == 1
    assert report["summary"]["skipped"] == 1
    assert target.read_bytes() == b"MUST NOT BE OPENED AS METADATA"
    if controlled:
        assert events[-1] == ScanProgress("complete", 1, 1, str(evidence))
        assert any(
            event.phase == "hashing" and event.source_path == str(payload) for event in events
        )


def test_cancellation_during_redirected_metadata_sibling_hash_produces_no_report(
    evidence: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path.resolve() / "private-link-target"
    target.write_bytes(b"private metadata target")
    link_or_skip(evidence / "$IABC.txt", target)
    (evidence / "$RABC.txt").write_bytes(b"safe payload bytes")
    monkeypatch.setattr(scanner, "HASH_CHUNK_BYTES", 4)
    events: list[ScanProgress] = []

    def progress(event: ScanProgress) -> None:
        events.append(event)
        if event.phase == "hashing" and event.bytes_processed >= 4:
            control.cancel()

    control = ScanControl(progress)
    with pytest.raises(ScanCancelled):
        scan(evidence, ScanOptions(hash_payload=True), control=control)
    assert events[-1].phase == "hashing"
    assert events[-1].processed == 0 and events[-1].total == 1
    assert not any(event.phase == "complete" for event in events)


def test_metadata_discovery_error_remains_error_after_safe_sibling_hash(
    evidence: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = write_item(evidence)
    original_scandir = scanner.os.scandir

    class DeniedEntry:
        def __init__(self, entry) -> None:
            self.name = entry.name
            self.path = entry.path

        def stat(self, *, follow_symlinks: bool):
            raise PermissionError("Cannot inspect metadata entry")

    @contextmanager
    def metadata_stat_denied(path):
        with original_scandir(path) as entries:
            yield iter(
                DeniedEntry(entry) if entry.name == source.name else entry for entry in entries
            )

    monkeypatch.setattr(scanner.os, "scandir", metadata_stat_denied)
    events: list[ScanProgress] = []
    report = scan(evidence, ScanOptions(hash_payload=True), control=ScanControl(events.append))
    record = report["records"][0]
    assert record["status"] == "error"
    assert record["metadata"] is None
    assert record["source_sha256"] is None
    assert record["payload"]["sha256"] == hashlib.sha256(b"payload").hexdigest()
    assert record["payload"]["size_matches_metadata"] is None
    assert report["summary"]["errors"] == 1
    assert report["summary"]["orphan_payloads"] == 0
    assert events[-1].processed == events[-1].total == 1


def test_payload_hash_failure_does_not_leave_redirected_metadata_as_only_skipped(
    evidence: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path.resolve() / "private-target"
    target.write_bytes(b"private metadata")
    link_or_skip(evidence / "$IABC.txt", target)
    (evidence / "$RABC.txt").write_bytes(b"payload")

    def unreadable_payload(_: Path):
        raise PermissionError("Payload cannot be read")

    monkeypatch.setattr(scanner, "_hash_payload", unreadable_payload)
    report = scan(evidence, ScanOptions(hash_payload=True), control=ScanControl())
    record = report["records"][0]
    assert record["status"] == "error"
    assert record["metadata"] is None
    assert record["payload"]["status"] == "unreadable"
    assert record["payload"]["sha256"] is None
    assert report["summary"]["errors"] == 1
    assert report["summary"]["skipped"] == 0


def test_generic_directory_redirect_keeps_payload_unassociated(
    evidence: Path, tmp_path: Path
) -> None:
    target = tmp_path.resolve() / "private-folder"
    target.mkdir()
    write_item(target, "SECRET.txt")
    redirect = evidence / "folder"
    link_or_skip(redirect, target)
    report = scan(evidence, ScanOptions(recursive=True, hash_payload=True), control=ScanControl())
    assert len(report["records"]) == 1
    assert report["records"][0]["source_path"] == str(redirect)
    assert report["records"][0]["payload"] is None
    assert report["summary"]["payloads_hashed"] == 0


def test_failed_i_named_input_directory_never_correlates_sibling_outside_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = tmp_path.resolve() / "$ISCOPE"
    directory.mkdir()
    (directory.parent / "$RSCOPE").write_bytes(b"outside scope")

    def denied(_: Path):
        raise PermissionError("Input directory cannot be listed")

    monkeypatch.setattr(scanner.os, "scandir", denied)
    events: list[ScanProgress] = []
    report = scan(directory, ScanOptions(hash_payload=True), control=ScanControl(events.append))
    record = report["records"][0]
    assert record["status"] == "error"
    assert record["source_path"] == str(directory)
    assert record["payload"] is None
    assert report["summary"]["payloads_hashed"] == 0
    assert events[-1].processed == events[-1].total == 0
