"""Workload ceilings abort scans without publishing a completed partial report."""

from __future__ import annotations

import hashlib
import io
import struct
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from threading import Barrier
from types import SimpleNamespace

import pytest

from rbinforensics import limits as work_limits
from rbinforensics import scanner
from rbinforensics.limits import WorkLimitExceeded, WorkLimits, current_budget, operation_budget
from rbinforensics.scan_control import ScanControl, ScanProgress
from rbinforensics.scanner import ScanOptions, scan


def write_item(directory: Path, suffix: str = "ABC.txt", content: bytes = b"data") -> Path:
    encoded = (r"C:\Users\Analyst\report.txt" + "\0").encode("utf-16-le")
    source = directory / ("$I" + suffix)
    source.write_bytes(
        struct.pack("<QQQI", 2, len(content), 133485408001234567, len(encoded) // 2) + encoded
    )
    (directory / ("$R" + suffix)).write_bytes(content)
    return source


@pytest.fixture
def evidence(tmp_path: Path) -> Path:
    directory = tmp_path.resolve() / "evidence"
    directory.mkdir()
    return directory


def assert_limit(stopped, resource: str, observed: int | float | None = None) -> None:
    assert stopped.value.operation == "scan"
    assert stopped.value.resource == resource
    if observed is not None:
        assert stopped.value.observed == observed


@pytest.mark.parametrize("controlled", [False, True])
def test_record_limit_counts_metadata_and_true_orphans_once(
    evidence: Path, controlled: bool
) -> None:
    write_item(evidence)
    (evidence / "$RORPHAN").write_bytes(b"orphan")
    events: list[ScanProgress] = []
    control = ScanControl(events.append) if controlled else None
    report = scan(evidence, ScanOptions(limits=WorkLimits(max_records=2)), control=control)
    assert len(report["records"]) == 2
    assert report["summary"]["candidates"] == report["summary"]["orphan_payloads"] == 1
    events.clear()
    with pytest.raises(WorkLimitExceeded) as stopped:
        scan(evidence, ScanOptions(limits=WorkLimits(max_records=1)), control=control)
    assert_limit(stopped, "max_records", 2)
    assert not any(event.phase == "complete" for event in events)


def test_controlled_discovery_reserves_metadata_before_materializing_candidates(
    evidence: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_item(evidence, "ONE")
    write_item(evidence, "TWO")

    def unexpected_read(_: Path):
        pytest.fail("Record ceiling must stop controlled discovery before metadata reads")

    monkeypatch.setattr(scanner, "_read_metadata", unexpected_read)
    events: list[ScanProgress] = []
    with pytest.raises(WorkLimitExceeded) as stopped:
        scan(
            evidence,
            ScanOptions(limits=WorkLimits(max_records=1)),
            control=ScanControl(events.append),
        )
    assert_limit(stopped, "max_records", 2)
    assert all(event.phase == "discovering" for event in events)


def test_payload_seen_before_its_metadata_is_not_reserved_as_an_orphan(
    evidence: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_item(evidence)
    original = scanner.os.scandir

    @contextmanager
    def payload_first(path):
        with original(path) as entries:
            yield iter(sorted(entries, key=lambda entry: not entry.name.startswith("$R")))

    monkeypatch.setattr(scanner.os, "scandir", payload_first)
    report = scan(evidence, ScanOptions(limits=WorkLimits(max_records=1)))
    assert len(report["records"]) == 1
    assert report["summary"]["orphan_payloads"] == 0


def test_interrupted_directory_inventory_does_not_invent_orphans(
    evidence: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_item(evidence)
    original = scanner.os.scandir

    @contextmanager
    def interrupted(path):
        with original(path) as entries:
            payload = next(entry for entry in entries if entry.name.startswith("$R"))

            def broken_entries():
                yield payload
                raise PermissionError("Directory inventory interrupted")

            yield broken_entries()

    monkeypatch.setattr(scanner.os, "scandir", interrupted)
    report = scan(evidence, ScanOptions(limits=WorkLimits(max_records=1)))
    assert len(report["records"]) == 1
    assert report["records"][0]["record_type"] == "discovery"
    assert report["summary"]["orphan_payloads"] == 0


def test_redirected_metadata_diagnostic_uses_one_record_budget(
    evidence: Path, tmp_path: Path
) -> None:
    target = tmp_path / "private"
    target.write_bytes(b"not acquired metadata")
    source = evidence / "$IABC"
    try:
        source.symlink_to(target)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"Creating test symlink unavailable: {exc}")
    (evidence / "$RABC").write_bytes(b"safe payload")
    report = scan(evidence, ScanOptions(limits=WorkLimits(max_records=1)))
    assert len(report["records"]) == 1
    assert report["records"][0]["record_type"] == "discovery"
    assert report["records"][0]["payload"]["status"] == "available_file"
    assert report["summary"]["orphan_payloads"] == 0


def test_discovery_diagnostics_are_bounded(evidence: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (evidence / "first").write_bytes(b"")
    (evidence / "second").write_bytes(b"")
    original = scanner.os.scandir

    class DeniedEntry:
        def __init__(self, entry) -> None:
            self.name = entry.name
            self.path = entry.path

        def stat(self, *, follow_symlinks: bool):
            raise PermissionError("Entry cannot be inspected")

    @contextmanager
    def inaccessible_entries(path):
        with original(path) as entries:
            yield (DeniedEntry(entry) for entry in entries)

    monkeypatch.setattr(scanner.os, "scandir", inaccessible_entries)
    with pytest.raises(WorkLimitExceeded) as stopped:
        scan(evidence, ScanOptions(limits=WorkLimits(max_records=1)))
    assert_limit(stopped, "max_records", 2)


def test_aggregate_hash_limit_preflights_each_opened_payload(evidence: Path) -> None:
    write_item(evidence, "ONE", b"1234")
    write_item(evidence, "TWO", b"5678")
    report = scan(
        evidence, ScanOptions(hash_payload=True, limits=WorkLimits(max_payload_hash_bytes=8))
    )
    assert report["summary"]["payloads_hashed"] == 2
    events: list[ScanProgress] = []
    with pytest.raises(WorkLimitExceeded) as stopped:
        scan(
            evidence,
            ScanOptions(hash_payload=True, limits=WorkLimits(max_payload_hash_bytes=7)),
            control=ScanControl(events.append),
        )
    assert_limit(stopped, "max_payload_hash_bytes", 8)
    assert {event.source_path for event in events if event.phase == "hashing"} == {
        str(evidence / "$RONE")
    }
    assert not any(event.phase == "complete" for event in events)


def test_hash_budget_charges_actual_chunks_before_digesting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    @contextmanager
    def growing_payload(_: Path):
        yield io.BytesIO(b"12345"), SimpleNamespace(st_size=3)

    monkeypatch.setattr(scanner, "_open_regular", growing_payload)
    monkeypatch.setattr(scanner, "HASH_CHUNK_BYTES", 2)
    with operation_budget(WorkLimits(max_payload_hash_bytes=4), operation="scan") as budget:
        with pytest.raises(WorkLimitExceeded) as stopped:
            scanner._hash_payload(Path("$RGROWING"))
        assert_limit(stopped, "max_payload_hash_bytes", 5)
        assert budget.payload_hash_bytes == 4


def test_empty_hash_does_not_consume_payload_bytes(evidence: Path) -> None:
    write_item(evidence, "EMPTY", b"")
    write_item(evidence, "ONE", b"x")
    report = scan(
        evidence, ScanOptions(hash_payload=True, limits=WorkLimits(max_payload_hash_bytes=1))
    )
    assert report["summary"]["payloads_hashed"] == 2
    assert report["records"][0]["payload"]["sha256"] == hashlib.sha256(b"").hexdigest()


def test_aggregate_metadata_limit_charges_each_read_once(evidence: Path) -> None:
    first = write_item(evidence, "ONE")
    second = write_item(evidence, "TWO")
    total = first.stat().st_size + second.stat().st_size
    consumed = []

    def progress(event: ScanProgress) -> None:
        if event.phase == "complete":
            consumed.append(current_budget().metadata_bytes)

    report = scan(
        evidence,
        ScanOptions(limits=WorkLimits(max_metadata_bytes=total)),
        control=ScanControl(progress),
    )
    assert report["summary"]["parsed"] == 2
    assert consumed == [total]
    with pytest.raises(WorkLimitExceeded) as stopped:
        scan(evidence, ScanOptions(limits=WorkLimits(max_metadata_bytes=total - 1)))
    assert_limit(stopped, "max_metadata_bytes", total)


def test_metadata_preflight_stops_before_read(monkeypatch: pytest.MonkeyPatch) -> None:
    class UnreadableStream:
        def read(self, _: int):
            pytest.fail("Metadata over the remaining aggregate budget must not be read")

    @contextmanager
    def metadata(_: Path):
        yield UnreadableStream(), SimpleNamespace(st_size=3)

    monkeypatch.setattr(scanner, "_open_regular", metadata)
    with operation_budget(WorkLimits(max_metadata_bytes=2), operation="scan"):
        with pytest.raises(WorkLimitExceeded) as stopped:
            scanner._read_metadata(Path("$IABC"))
        assert_limit(stopped, "max_metadata_bytes", 3)


def test_metadata_budget_charges_actual_bytes_before_changed_length_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    @contextmanager
    def growing_metadata(_: Path):
        yield io.BytesIO(b"123"), SimpleNamespace(st_size=2)

    monkeypatch.setattr(scanner, "_open_regular", growing_metadata)
    with operation_budget(WorkLimits(max_metadata_bytes=2), operation="scan"):
        with pytest.raises(WorkLimitExceeded) as stopped:
            scanner._read_metadata(Path("$IGROWING"))
        assert_limit(stopped, "max_metadata_bytes", 3)


def test_unrelated_directory_entries_are_bounded_before_candidate_processing(
    evidence: Path,
) -> None:
    for number in range(4):
        (evidence / f"unrelated-{number}").write_bytes(b"")
    assert scan(evidence, ScanOptions(limits=WorkLimits(max_visited_entries=4)))["records"] == []
    with pytest.raises(WorkLimitExceeded) as stopped:
        scan(evidence, ScanOptions(limits=WorkLimits(max_visited_entries=3)))
    assert_limit(stopped, "max_visited_entries", 4)


def test_pairing_reuses_complete_directory_inventory(evidence: Path) -> None:
    write_item(evidence, "ONE")
    write_item(evidence, "TWO")
    report = scan(evidence, ScanOptions(limits=WorkLimits(max_visited_entries=4)))
    assert report["summary"]["parsed"] == 2
    assert all(record["payload"]["status"] == "available_file" for record in report["records"])


def test_single_metadata_pairing_also_bounds_unrelated_entries(evidence: Path) -> None:
    source = write_item(evidence)
    (evidence / "unrelated").write_bytes(b"")
    with pytest.raises(WorkLimitExceeded) as stopped:
        scan(source, ScanOptions(limits=WorkLimits(max_visited_entries=2)))
    assert_limit(stopped, "max_visited_entries", 3)


def test_depth_is_checked_before_descending_and_root_is_zero(
    evidence: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    child = evidence / "child"
    child.mkdir()
    write_item(child)
    original = scanner.os.scandir
    visited = []

    def tracked(path):
        visited.append(Path(path))
        return original(path)

    monkeypatch.setattr(scanner.os, "scandir", tracked)
    with pytest.raises(WorkLimitExceeded) as stopped:
        scan(evidence, ScanOptions(recursive=True, limits=WorkLimits(max_depth=0)))
    assert_limit(stopped, "max_depth", 1)
    assert visited == [evidence]
    assert (
        scan(evidence, ScanOptions(recursive=True, limits=WorkLimits(max_depth=1)))["summary"][
            "parsed"
        ]
        == 1
    )


def test_payload_directories_remain_opaque_at_depth_ceiling(evidence: Path) -> None:
    payload = evidence / "$RFOLDER"
    payload.mkdir()
    write_item(payload)
    report = scan(
        evidence,
        ScanOptions(recursive=True, limits=WorkLimits(max_depth=0, max_visited_entries=1)),
    )
    assert len(report["records"]) == report["summary"]["orphan_payloads"] == 1
    assert report["records"][0]["payload"]["status"] == "available_directory"


def test_public_scan_uses_fresh_budget_and_restores_outer_context(evidence: Path) -> None:
    write_item(evidence)
    with operation_budget(WorkLimits(max_records=1), operation="outer") as outer:
        outer.reserve_record("outer", "already used")
        report = scan(evidence, ScanOptions(limits=WorkLimits(max_records=1)))
        assert report["summary"]["parsed"] == 1
        assert current_budget() is outer
        assert outer.records == {("outer", "already used")}
        assert outer.metadata_bytes == outer.payload_hash_bytes == outer.visited_entries == 0
    assert current_budget() is None


def test_concurrent_scans_keep_budget_exhaustion_isolated(tmp_path: Path) -> None:
    first = tmp_path.resolve() / "first"
    second = tmp_path.resolve() / "second"
    first.mkdir()
    second.mkdir()
    first_source = write_item(first, content=b"abc")
    second_source = write_item(second, content=b"xyz")
    barrier = Barrier(2)
    budgets = {}

    def progress(event: ScanProgress) -> None:
        if (
            event.phase == "processing"
            and event.source_path.endswith("$IABC.txt")
            and event.source_path not in budgets
        ):
            budgets[event.source_path] = current_budget()
            barrier.wait(timeout=5)

    with ThreadPoolExecutor(max_workers=2) as pool:
        stopped = pool.submit(
            scan,
            first_source,
            ScanOptions(hash_payload=True, limits=WorkLimits(max_payload_hash_bytes=2)),
            control=ScanControl(progress),
        )
        completed = pool.submit(
            scan,
            second_source,
            ScanOptions(hash_payload=True, limits=WorkLimits(max_payload_hash_bytes=3)),
            control=ScanControl(progress),
        )
        with pytest.raises(WorkLimitExceeded) as failure:
            stopped.result(timeout=10)
        assert_limit(failure, "max_payload_hash_bytes", 3)
        assert completed.result(timeout=10)["summary"]["payloads_hashed"] == 1
    assert len(budgets) == 2
    assert budgets[str(first_source)] is not budgets[str(second_source)]
    assert current_budget() is None


def test_deadline_after_analysis_prevents_complete_report(
    evidence: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = write_item(evidence)
    clock = [0.0]
    monkeypatch.setattr(work_limits, "monotonic", lambda: clock[0])
    original = scanner.build_timeline

    def slow_timeline(*args, **kwargs):
        result = original(*args, **kwargs)
        clock[0] = 11.0
        return result

    monkeypatch.setattr(scanner, "build_timeline", slow_timeline)
    events: list[ScanProgress] = []
    with pytest.raises(WorkLimitExceeded) as stopped:
        scan(
            source,
            ScanOptions(limits=WorkLimits(max_operation_seconds=10)),
            control=ScanControl(events.append),
        )
    assert_limit(stopped, "max_operation_seconds", 11.0)
    assert not any(event.phase == "complete" for event in events)
    assert current_budget() is None


def test_limits_do_not_expand_schema_two_report_options(evidence: Path) -> None:
    source = write_item(evidence)
    options = ScanOptions(False, False, "UTC", "CASE-1", "Examiner")
    assert options.limits is None
    report = scan(source, options)
    assert report["options"] == {
        "recursive": False,
        "hash_payload": False,
        "timezone": "UTC",
        "case_id": "CASE-1",
        "examiner": "Examiner",
    }
