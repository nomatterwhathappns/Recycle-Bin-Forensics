"""Filesystem integration tests: bytes, provenance, correlation and failure isolation."""

from __future__ import annotations

import hashlib
import os
import struct
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import pytest

from rbinforensics import scanner
from rbinforensics.scanner import EvidenceError, ScanOptions, scan

TICKS = 133_485_408_001_234_567  # 2024-01-01 00:00:00.1234567 UTC


def blob(path: str = r"C:\Users\Analyst\report.txt", size: int = 7, ticks: int = TICKS) -> bytes:
    encoded = (path + "\0").encode("utf-16-le")
    return struct.pack("<QQQI", 2, size, ticks, len(encoded) // 2) + encoded


@pytest.fixture
def evidence(tmp_path: Path) -> Path:
    directory = tmp_path.resolve() / "evidence"
    directory.mkdir()
    return directory


def write_item(directory: Path, name: str = "ABC.txt", **kwargs) -> Path:
    source = directory / ("$I" + name)
    source.write_bytes(blob(**kwargs))
    return source


def codes(record: dict) -> set[str]:
    return {issue["code"] for issue in record["issues"]}


def link_or_skip(link: Path, target: Path, directory: bool = False) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except (OSError, NotImplementedError):
        pytest.skip("Creating symlinks is unavailable for this OS/user.")


def test_single_metadata_preserves_bytes_path_and_raw_timestamp(evidence: Path) -> None:
    source = write_item(evidence, path=r"C:\資料\😀.txt")
    before = source.read_bytes()
    report = scan(source, ScanOptions(case_id="CASE-1", examiner="Analyst"))
    record = report["records"][0]
    assert report["schema_version"] == "2.0"
    assert report["options"]["case_id"] == "CASE-1"
    assert report["options"]["examiner"] == "Analyst"
    assert record["metadata"]["original_path"] == r"C:\資料\😀.txt"
    assert record["metadata"]["deletion_filetime"] == TICKS
    assert record["metadata"]["deleted_at_utc"] == "2024-01-01T00:00:00.1234567Z"
    assert record["metadata"]["deleted_at_display"] == "2024-01-01T00:00:00.1234567+00:00"
    assert record["source_sha256"] == hashlib.sha256(before).hexdigest()
    assert record["source_size"] == len(before)
    assert record["payload"]["status"] == "missing"
    assert record["status"] == "ok"
    assert source.read_bytes() == before


def test_payload_hash_is_opt_in_and_streamed(evidence: Path) -> None:
    content = b"payload" * (scanner.HASH_CHUNK_BYTES // 7 + 10)
    source = write_item(evidence, size=len(content))
    payload = evidence / "$RABC.txt"
    payload.write_bytes(content)
    default = scan(source)["records"][0]["payload"]
    assert default["status"] == "available_file"
    assert default["sha256"] is None
    assert default["hash_status"] == "not_requested"
    hashed = scan(source, ScanOptions(hash_payload=True))
    record = hashed["records"][0]
    assert record["payload"]["sha256"] == hashlib.sha256(content).hexdigest()
    assert record["payload"]["hash_status"] == "computed"
    assert record["payload"]["size_matches_metadata"] is True
    assert hashed["summary"]["payloads_hashed"] == 1
    assert record["status"] == "ok"


def test_newly_closed_artifacts_scan_repeatedly_without_false_change_errors(evidence: Path) -> None:
    """Windows lstat/fstat must agree for stable files immediately after writes.

    Build enough fresh files to catch timestamp-resolution/platform differences
    without a sleep masking the failure. Expected digests come from the known
    fixture bytes, not from a second invocation of the scanner being tested.
    """
    expected = {}
    for index in range(128):
        suffix = f"FRESH{index:04d}.txt"
        original = rf"C:\Users\Analyst\fresh-{index:04d}.txt"
        content = f"Harmless synthetic payload {index:04d}.\n".encode("ascii")
        source = write_item(evidence, suffix, path=original, size=len(content))
        payload = evidence / ("$R" + suffix)
        payload.write_bytes(content)
        expected[source.name] = {
            "source": source,
            "payload": payload,
            "metadata_bytes": blob(path=original, size=len(content)),
            "payload_bytes": content,
            "original_path": original,
        }

    first_records = None
    for _ in range(3):
        report = scan(evidence, ScanOptions(hash_payload=True))
        error_records = [record for record in report["records"] if record["status"] == "error"]
        assert report["summary"]["errors"] == 0, error_records
        assert report["summary"]["parsed"] == len(expected), report["records"]
        assert report["summary"]["payloads_hashed"] == len(expected), report["records"]
        assert len(report["records"]) == len(expected)
        for record in report["records"]:
            item = expected[record["source_name"]]
            assert record["status"] == "ok", record
            assert record["source_sha256"] == hashlib.sha256(item["metadata_bytes"]).hexdigest()
            assert record["payload"]["sha256"] == hashlib.sha256(item["payload_bytes"]).hexdigest()
            assert record["metadata"]["original_path"] == item["original_path"]
            assert record["metadata"]["deletion_filetime"] == TICKS
            assert record["payload"]["size_matches_metadata"] is True
        if first_records is None:
            first_records = report["records"]
        else:
            assert report["records"] == first_records

    for item in expected.values():
        assert item["source"].read_bytes() == item["metadata_bytes"]
        assert item["payload"].read_bytes() == item["payload_bytes"]


def test_size_mismatch_is_explicit_warning(evidence: Path) -> None:
    source = write_item(evidence, size=10)
    (evidence / "$RABC.txt").write_bytes(b"short")
    record = scan(source)["records"][0]
    assert record["payload"]["size_matches_metadata"] is False
    assert "payload_size_mismatch" in codes(record)
    assert record["status"] == "warning"


def test_folder_payload_never_recursively_hashes_contents(evidence: Path) -> None:
    source = write_item(evidence)
    folder = evidence / "$RABC.txt"
    folder.mkdir()
    (folder / "private.txt").write_text("data")
    report = scan(source, ScanOptions(hash_payload=True))
    payload = report["records"][0]["payload"]
    assert payload["status"] == "available_directory"
    assert payload["sha256"] is None
    assert payload["size_matches_metadata"] is None
    assert payload["hash_status"] == "not_applicable"


def test_recursive_scan_deterministic_and_sid_context_only(evidence: Path) -> None:
    nested = evidence / "S-1-5-21-123-456-789-1001"
    nested.mkdir()
    write_item(nested, "Z.txt")
    write_item(nested, "A.txt")
    write_item(evidence, "ROOT.txt")
    (evidence / "irrelevant.txt").write_text("not metadata")
    assert scan(evidence)["summary"]["candidates"] == 1
    report = scan(evidence, ScanOptions(recursive=True))
    assert report["summary"]["candidates"] == 3
    paths = [record["source_path"] for record in report["records"]]
    assert paths == sorted(paths)
    assert {r["sid"] for r in report["records"] if r["sid"]} == {nested.name}


def test_corrupt_file_cannot_abort_other_candidates(evidence: Path) -> None:
    write_item(evidence)
    broken = evidence / "$IBROKEN"
    broken.write_bytes(b"incomplete")
    report = scan(evidence)
    assert report["summary"]["parsed"] == 1
    assert report["summary"]["errors"] == 1
    bad = next(r for r in report["records"] if r["source_name"] == broken.name)
    assert bad["metadata"] is None
    assert bad["source_sha256"] == hashlib.sha256(b"incomplete").hexdigest()
    assert "truncated_header" in codes(bad)


@pytest.mark.parametrize("name", ["renamed-evidence.bin", "$I"])
def test_explicit_nonstandard_filename_parses_without_guessed_pair(
    evidence: Path, name: str
) -> None:
    source = evidence / name
    source.write_bytes(blob())
    record = scan(source)["records"][0]
    assert record["metadata"] is not None
    assert record["payload"]["status"] == "not_checked"
    assert "nonstandard_source_name" in codes(record)


def test_case_insensitive_payload_correlation(evidence: Path) -> None:
    source = write_item(evidence)
    (evidence / "$rabc.TXT").write_bytes(b"payload")
    record = scan(source)["records"][0]
    assert record["payload"]["status"] == "available_file"
    assert record["status"] == "warning"
    assert "payload_case_insensitive_match" in codes(record)


def test_unicode_casefold_equivalence_cannot_pair_different_names(evidence: Path) -> None:
    source = write_item(evidence, "FILEß.txt")
    (evidence / "$RFILEss.txt").write_bytes(b"payload")
    record = scan(source)["records"][0]
    assert record["payload"]["status"] == "missing"


def test_metadata_replacement_between_lstat_and_open_is_detected(
    evidence: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = write_item(evidence)
    original_open = scanner.os.open

    def replace_before_open(path, flags, *args, **kwargs):
        if Path(path) == source:
            source.write_bytes(b"replacement of different size")
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(scanner.os, "open", replace_before_open)
    record = scan(source)["records"][0]
    assert "changed_during_read" in codes(record)
    assert record["metadata"] is None
    assert record["source_sha256"] is None


def test_ambiguous_case_variants_are_not_arbitrarily_selected(evidence: Path) -> None:
    source = write_item(evidence)
    first = evidence / "$RABC.txt"
    second = evidence / "$rabc.TXT"
    first.write_bytes(b"payload")
    second.write_bytes(b"payload")
    if first.samefile(second):
        pytest.skip("Case-insensitive filesystem cannot contain ambiguous sibling names.")
    record = scan(source)["records"][0]
    assert record["payload"]["status"] == "ambiguous"
    assert "ambiguous_payload" in codes(record)


def test_symlink_candidates_and_directories_are_not_followed(
    evidence: Path, tmp_path: Path
) -> None:
    outside = tmp_path.resolve() / "outside"
    outside.mkdir()
    target = write_item(outside)
    link_or_skip(evidence / "$ILINK.txt", target)
    link_or_skip(evidence / "linked-folder", outside, directory=True)
    report = scan(evidence, ScanOptions(recursive=True))
    assert report["summary"]["parsed"] == 0
    assert report["summary"]["skipped"] == 2
    assert all("symlink_skipped" in codes(r) for r in report["records"])


def test_direct_symlink_input_rejected(evidence: Path) -> None:
    source = write_item(evidence)
    linked = evidence / "$ILINK.txt"
    link_or_skip(linked, source)
    with pytest.raises(EvidenceError, match="Symlink"):
        scan(linked)


def test_windows_reparse_attribute_is_rejected_without_symlink_mode(
    evidence: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = write_item(evidence)
    original_lstat = Path.lstat
    ordinary_mode = original_lstat(source).st_mode

    def with_windows_reparse_attribute(path: Path, *args, **kwargs):
        if path == source:
            return SimpleNamespace(st_mode=ordinary_mode, st_file_attributes=0x400)
        return original_lstat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", with_windows_reparse_attribute)
    with pytest.raises(EvidenceError, match="reparse"):
        scan(source)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows directory junction integration")
def test_windows_junction_payload_and_discovery_are_not_followed(
    evidence: Path, tmp_path: Path
) -> None:
    source = write_item(evidence)
    target = tmp_path.resolve() / "outside-junction-target"
    target.mkdir()
    write_item(target, "SECRET.txt")
    junction = evidence / "$RABC.txt"
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(target)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        pytest.skip(f"Creating Windows junction unavailable: {result.stderr.strip()}")
    try:
        single = scan(source, ScanOptions(hash_payload=True))["records"][0]
        assert single["payload"]["status"] == "symlink_skipped"
        assert single["payload"]["sha256"] is None
        assert "payload_symlink_skipped" in codes(single)
        report = scan(evidence, ScanOptions(recursive=True))
        assert report["summary"]["parsed"] == 1
        assert report["summary"]["skipped"] == 1
        assert not any(record["source_name"] == "$ISECRET.txt" for record in report["records"])
    finally:
        # Remove the junction entry itself; never recurse into its target.
        os.rmdir(junction)


def test_payload_symlink_not_hashed(evidence: Path, tmp_path: Path) -> None:
    source = write_item(evidence)
    target = tmp_path.resolve() / "outside-payload"
    target.write_bytes(b"payload")
    link_or_skip(evidence / "$RABC.txt", target)
    record = scan(source, ScanOptions(hash_payload=True))["records"][0]
    assert record["payload"]["status"] == "symlink_skipped"
    assert record["payload"]["sha256"] is None
    assert "payload_symlink_skipped" in codes(record)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFO required")
def test_special_files_cannot_block_reader(evidence: Path) -> None:
    source = write_item(evidence)
    os.mkfifo(evidence / "$RABC.txt")
    os.mkfifo(evidence / "$IFIFO")
    report = scan(evidence, ScanOptions(hash_payload=True))
    payload_record = next(r for r in report["records"] if r["source_name"] == source.name)
    assert payload_record["payload"]["status"] == "special_file_skipped"
    assert "payload_not_regular" in codes(payload_record)
    fifo_record = next(r for r in report["records"] if r["source_name"] == "$IFIFO")
    assert fifo_record["status"] == "error"
    with pytest.raises(EvidenceError, match="regular file or directory"):
        scan(evidence / "$IFIFO")


def test_metadata_size_guard_before_read(evidence: Path) -> None:
    source = evidence / "$IHUGE"
    source.write_bytes(b"x" * (scanner.MAX_METADATA_BYTES + 1))
    record = scan(source)["records"][0]
    assert "metadata_too_large" in codes(record)
    assert record["source_sha256"] is None
    assert record["metadata"] is None


def test_timestamp_warnings_propagate_with_null_display(evidence: Path) -> None:
    source = write_item(evidence, ticks=0)
    report = scan(source)
    record = report["records"][0]
    assert record["metadata"]["deleted_at_display"] is None
    assert "zero_deletion_time" in codes(record)
    assert report["summary"]["warnings"] == 1


def test_timezone_display_preserves_seventh_digit(evidence: Path) -> None:
    try:
        ZoneInfo("Asia/Jakarta")
    except ZoneInfoNotFoundError:
        pytest.skip("Host has no IANA timezone data.")
    source = write_item(evidence)
    record = scan(source, ScanOptions(timezone="Asia/Jakarta"))["records"][0]
    assert record["metadata"]["deleted_at_display"] == "2024-01-01T07:00:00.1234567+07:00"
    assert record["metadata"]["deleted_at_utc"] == "2024-01-01T00:00:00.1234567Z"


def test_source_read_error_isolated(evidence: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    good = write_item(evidence)
    bad = write_item(evidence, "BAD.txt")
    original = scanner._read_metadata

    def fail_one(path: Path):
        if path == bad:
            raise PermissionError("access denied")
        return original(path)

    monkeypatch.setattr(scanner, "_read_metadata", fail_one)
    report = scan(evidence)
    assert report["summary"]["parsed"] == 1
    assert report["summary"]["errors"] == 1
    assert next(r for r in report["records"] if r["source_path"] == str(good))["status"] == "ok"


@pytest.mark.parametrize("requested,severity", [(False, "warning"), (True, "error")])
def test_payload_directory_index_error_is_visible(
    evidence: Path, monkeypatch: pytest.MonkeyPatch, requested: bool, severity: str
) -> None:
    source = write_item(evidence)
    monkeypatch.setattr(
        scanner.os, "scandir", lambda _: (_ for _ in ()).throw(PermissionError("denied"))
    )
    record = scan(source, ScanOptions(hash_payload=requested))["records"][0]
    assert record["metadata"] is not None
    assert record["payload"]["status"] == "unreadable"
    assert record["issues"][-1]["severity"] == severity


def test_discovery_permission_error_is_a_report_record(
    evidence: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        scanner.os, "scandir", lambda _: (_ for _ in ()).throw(PermissionError("denied"))
    )
    report = scan(evidence)
    assert report["summary"]["errors"] == 1
    assert report["records"][0]["record_type"] == "discovery"
    assert "discovery_error" in codes(report["records"][0])


def test_hash_failure_does_not_discard_metadata(
    evidence: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = write_item(evidence)
    (evidence / "$RABC.txt").write_bytes(b"payload")

    def fail_hash(_: Path):
        raise EvidenceError("changed_during_read", "Changed payload")

    monkeypatch.setattr(scanner, "_hash_payload", fail_hash)
    record = scan(source, ScanOptions(hash_payload=True))["records"][0]
    assert record["metadata"] is not None
    assert record["status"] == "error"
    assert record["payload"]["hash_status"] == "unavailable"
    assert record["payload"]["sha256"] is None


def test_replacement_after_open_is_detected(evidence: Path) -> None:
    source = write_item(evidence)
    with pytest.raises(EvidenceError, match="changed"):
        with scanner._open_regular(source) as (stream, _):
            assert stream.read(1)
            source.write_bytes(b"replacement")


def test_windows_cross_api_ctime_difference_allows_unchanged_evidence(
    evidence: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stable Windows fstat/lstat ctime offset must not create a false alarm."""
    source = write_item(evidence)
    expected = source.read_bytes()
    original_fstat = scanner.os.fstat

    def fstat_with_fixed_ctime_offset(descriptor: int):
        info = original_fstat(descriptor)
        attributes = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
        attributes["st_ctime_ns"] += 1_000_000_000
        return SimpleNamespace(**attributes)

    monkeypatch.setattr(scanner, "_WINDOWS", True)
    monkeypatch.setattr(scanner.os, "fstat", fstat_with_fixed_ctime_offset)
    with scanner._open_regular(source) as (stream, _):
        assert stream.read() == expected


def test_windows_ctime_change_between_handle_reads_still_rejected(
    evidence: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ignoring cross-API ctime must not disable same-handle change detection."""
    source = write_item(evidence)
    original_fstat = scanner.os.fstat
    calls = 0

    def fstat_with_changing_ctime(descriptor: int):
        nonlocal calls
        info = original_fstat(descriptor)
        calls += 1
        attributes = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
        attributes["st_ctime_ns"] += calls * 1_000_000_000
        return SimpleNamespace(**attributes)

    monkeypatch.setattr(scanner, "_WINDOWS", True)
    monkeypatch.setattr(scanner.os, "fstat", fstat_with_changing_ctime)
    with pytest.raises(EvidenceError, match="changed while reading"):
        with scanner._open_regular(source) as (stream, _):
            assert stream.read()
    assert calls == 2


def test_display_conversion_error_preserves_utc_and_warns(
    evidence: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = write_item(evidence)

    def fail_conversion(*_):
        raise OverflowError("out of range")

    monkeypatch.setattr(scanner, "_display_time", fail_conversion)
    record = scan(source)["records"][0]
    assert record["metadata"]["deleted_at_display"] is None
    assert record["metadata"]["deleted_at_utc"].endswith("Z")
    assert "display_time_out_of_range" in codes(record)
