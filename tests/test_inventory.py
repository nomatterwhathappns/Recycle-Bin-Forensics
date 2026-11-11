"""Inventory integration tests retain unpaired content without inventing metadata."""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path

import pytest

from rbinforensics.scanner import ScanOptions, scan

TICKS = 133_485_408_001_234_567


def write_metadata(directory: Path, suffix: str = "ABC.pdf", size: int = 7) -> Path:
    encoded = (r"C:\Users\Analyst\report.pdf" + "\0").encode("utf-16-le")
    path = directory / ("$I" + suffix)
    path.write_bytes(struct.pack("<QQQI", 2, size, TICKS, len(encoded) // 2) + encoded)
    return path


@pytest.fixture
def evidence(tmp_path: Path) -> Path:
    directory = tmp_path.resolve() / "evidence"
    directory.mkdir()
    return directory


def test_orphan_file_inventory_preserves_observation_without_original_metadata(evidence: Path):
    path = evidence / "$RLONE.bin"
    path.write_bytes(b"unpaired payload")
    report = scan(evidence)
    record = report["records"][0]
    assert report["summary"]["orphan_payloads"] == 1
    assert report["summary"]["candidates"] == 0
    assert report["summary"]["parsed"] == 0
    assert record["record_type"] == "orphan_payload"
    assert record["source_path"] == str(path)
    assert record["source_size"] == len(b"unpaired payload")
    assert record["metadata"] is None
    assert record["payload"]["status"] == "available_file"
    assert record["payload"]["sha256"] is None
    assert record["payload"]["size_matches_metadata"] is None
    assert any(issue["code"] == "orphan_payload" for issue in record["issues"])
    assert report["timeline"]["events"] == []
    assert report["timeline"]["undated_records"] == 1


def test_orphan_hash_is_from_actual_payload_bytes(evidence: Path):
    content = b"harmless evidence content\0" * 10_000
    path = evidence / "$RLONE.bin"
    path.write_bytes(content)
    report = scan(evidence, ScanOptions(hash_payload=True))
    record = report["records"][0]
    expected = hashlib.sha256(content).hexdigest()
    assert record["source_sha256"] == expected
    assert record["payload"]["sha256"] == expected
    assert record["payload"]["hash_status"] == "computed"
    assert report["summary"]["payloads_hashed"] == 1
    assert path.read_bytes() == content


def test_payload_folder_is_inventory_item_and_not_a_recursive_artifact_container(evidence: Path):
    directory = evidence / "$RFOLDER"
    directory.mkdir()
    write_metadata(directory, "INSIDE.pdf")
    (directory / "$RINSIDE.pdf").write_bytes(b"payload")
    report = scan(evidence, ScanOptions(recursive=True, hash_payload=True))
    assert report["summary"]["orphan_payloads"] == 1
    assert report["summary"]["candidates"] == 0
    assert len(report["records"]) == 1
    record = report["records"][0]
    assert record["source_name"] == directory.name
    assert record["payload"]["status"] == "available_directory"
    assert record["payload"]["hash_status"] == "not_applicable"
    assert record["payload"]["sha256"] is None


def test_recycle_bin_container_remains_traversable_and_is_not_a_payload(evidence: Path):
    sid = "S-1-5-21-111-222-333-1001"
    directory = evidence / "$Recycle.Bin" / sid
    directory.mkdir(parents=True)
    write_metadata(directory)
    (directory / "$RABC.pdf").write_bytes(b"payload")
    (directory / "$RLONE.pdf").write_bytes(b"orphan")
    report = scan(evidence, ScanOptions(recursive=True))
    assert report["summary"]["candidates"] == 1
    assert report["summary"]["orphan_payloads"] == 1
    assert {record["source_name"] for record in report["records"]} == {"$IABC.pdf", "$RLONE.pdf"}
    assert {record["sid"] for record in report["records"]} == {sid}


def test_existing_corrupt_metadata_prevents_false_orphan_claim(evidence: Path):
    (evidence / "$ICORRUPT.txt").write_bytes(b"truncated")
    (evidence / "$RCORRUPT.txt").write_bytes(b"payload")
    report = scan(evidence)
    assert report["summary"]["errors"] == 1
    assert report["summary"]["orphan_payloads"] == 0
    assert len(report["records"]) == 1
    assert report["records"][0]["metadata"] is None


def test_paired_and_orphan_payloads_are_counted_once_each(evidence: Path):
    write_metadata(evidence)
    (evidence / "$RABC.pdf").write_bytes(b"payload")
    (evidence / "$RLONE.pdf").write_bytes(b"orphan")
    report = scan(evidence, ScanOptions(hash_payload=True))
    assert report["summary"]["candidates"] == 1
    assert report["summary"]["orphan_payloads"] == 1
    assert report["summary"]["payloads_hashed"] == 2
    assert len(report["records"]) == 2


def test_single_metadata_scope_does_not_inventory_unrequested_siblings(evidence: Path):
    source = write_metadata(evidence)
    (evidence / "$RABC.pdf").write_bytes(b"payload")
    (evidence / "$RLONE.pdf").write_bytes(b"unrequested")
    report = scan(source)
    assert report["summary"]["orphan_payloads"] == 0
    assert len(report["records"]) == 1
    assert report["records"][0]["source_name"] == source.name


def test_ambiguous_payload_matches_are_not_misclassified_as_metadata_free(evidence: Path):
    write_metadata(evidence)
    first = evidence / "$RABC.pdf"
    second = evidence / "$rabc.PDF"
    first.write_bytes(b"payload")
    second.write_bytes(b"payload")
    if first.samefile(second):
        pytest.skip("Case-insensitive filesystem cannot contain ambiguous sibling names.")
    report = scan(evidence)
    assert report["summary"]["orphan_payloads"] == 0
    assert report["records"][0]["payload"]["status"] == "ambiguous"


def test_orphan_payload_link_is_not_followed_or_hashed(evidence: Path, tmp_path: Path):
    target = tmp_path.resolve() / "outside-secret.txt"
    target.write_bytes(b"outside content")
    link = evidence / "$RLINK.txt"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("Creating symlinks is unavailable for this OS/user.")
    report = scan(evidence, ScanOptions(recursive=True, hash_payload=True))
    assert report["summary"]["payloads_hashed"] == 0
    assert all(record["source_sha256"] is None for record in report["records"])
    assert not any(
        record.get("payload", {}).get("sha256")
        for record in report["records"]
        if record.get("payload")
    )
    assert target.read_bytes() == b"outside content"


def test_reserved_bin_container_cannot_be_correlated_as_payload(evidence: Path):
    source = write_metadata(evidence, "ecycle.Bin")
    container = evidence / "$Recycle.Bin"
    container.mkdir()
    child = write_metadata(container, "CHILD.pdf")
    single = scan(source)
    assert single["records"][0]["payload"]["status"] == "missing"

    recursive = scan(evidence, ScanOptions(recursive=True))
    assert recursive["summary"]["parsed"] == 2
    assert recursive["summary"]["orphan_payloads"] == 0
    assert child.name in {record["source_name"] for record in recursive["records"]}
    outer = next(record for record in recursive["records"] if record["source_name"] == source.name)
    assert outer["payload"]["status"] == "missing"


def test_ascii_colliding_metadata_entries_warn_on_both_records(evidence: Path):
    first = write_metadata(evidence)
    second = evidence / "$iabc.PDF"
    second.write_bytes(first.read_bytes())
    if first.samefile(second):
        pytest.skip("Case-insensitive filesystem cannot contain colliding metadata names.")
    (evidence / "$RABC.pdf").write_bytes(b"payload")
    report = scan(evidence)
    assert report["summary"]["candidates"] == 2
    assert report["summary"]["orphan_payloads"] == 0
    for record in report["records"]:
        assert record["status"] == "warning"
        assert record["payload"]["status"] == "available_file"
        assert "metadata_name_collision" in {issue["code"] for issue in record["issues"]}


def test_orphan_hash_failure_retains_inventory_and_reports_error(evidence: Path, monkeypatch):
    path = evidence / "$RLONE.bin"
    path.write_bytes(b"orphan payload")

    def inaccessible(_):
        raise PermissionError("Synthetic payload access denied")

    monkeypatch.setattr("rbinforensics.scanner._hash_payload", inaccessible)
    report = scan(evidence, ScanOptions(hash_payload=True))
    record = report["records"][0]
    assert report["summary"]["orphan_payloads"] == 1
    assert report["summary"]["errors"] == 1
    assert report["summary"]["payloads_hashed"] == 0
    assert record["record_type"] == "orphan_payload"
    assert record["source_path"] == str(path)
    assert record["metadata"] is None
    assert record["source_sha256"] is None
    assert record["payload"]["status"] == "unreadable"
    assert record["payload"]["hash_status"] == "unavailable"
    assert record["payload"]["sha256"] is None
