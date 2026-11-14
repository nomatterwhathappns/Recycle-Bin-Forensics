"""Manifest/report pairs are exact, verifiable, and cleaned together on failure."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import struct
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

import pytest

from rbinforensics import limits as limit_module
from rbinforensics import output
from rbinforensics.analysis import FilterOptions
from rbinforensics.limits import WorkLimitExceeded, WorkLimits, operation_budget
from rbinforensics.manifest import ManifestError, verify_export
from rbinforensics.reports import render
from rbinforensics.scan_control import ScanCancelled, ScanControl
from rbinforensics.scanner import EvidenceError, ScanOptions, scan

FORMATS = ("json", "csv", "table", "html")
MANIFEST_LIMIT = 1024**2


def sidecar(path: Path) -> Path:
    return path.with_name(path.name + ".manifest.json")


@pytest.fixture
def report(tmp_path: Path) -> dict:
    directory = tmp_path / "evidence"
    directory.mkdir()
    original = 'C:\\資料\\report-😀&<>".txt'
    encoded = (original + "\0").encode("utf-16-le")
    (directory / "$IABC.txt").write_bytes(
        struct.pack("<QQQI", 2, 7, 133485408001234567, len(encoded) // 2) + encoded
    )
    (directory / "$RABC.txt").write_bytes(b"payload")
    (directory / "$RORPHAN.bin").write_bytes(b"orphan")
    return scan(
        directory,
        ScanOptions(hash_payload=True, timezone="UTC", case_id="CASE 資料", examiner="Analyst"),
        FilterOptions(query="report"),
    )


@pytest.fixture
def exported(report: dict, tmp_path: Path) -> Path:
    destination = tmp_path / "report.json"
    output.write_report(report, destination, "json")
    return destination


def load_manifest(path: Path) -> dict:
    return json.loads(sidecar(path).read_text(encoding="utf-8"))


def replace_manifest(path: Path, document: object) -> None:
    sidecar(path).write_text(json.dumps(document, ensure_ascii=True), encoding="utf-8")


@pytest.mark.parametrize("format_name", FORMATS)
def test_export_pair_binds_exact_existing_report_bytes_and_provenance(
    report: dict, tmp_path: Path, format_name: str
) -> None:
    before = copy.deepcopy(report)
    expected = render(report, format_name).encode("utf-8")
    destination = tmp_path / ("report." + format_name)
    limits = WorkLimits(max_export_bytes=len(expected))
    result = output.write_report(report, destination, format_name, limits=limits)
    assert result == destination
    assert destination.read_bytes() == expected
    document = load_manifest(destination)
    assert document["manifest_schema_version"] == "1.0"
    assert document["tool"] == report["tool"]
    created = datetime.fromisoformat(document["created_at_utc"].replace("Z", "+00:00"))
    assert created.utcoffset().total_seconds() == 0
    assert document["report"] == {
        "filename": destination.name,
        "format": format_name,
        "size_bytes": len(expected),
        "sha256": hashlib.sha256(expected).hexdigest(),
    }
    assert document["forensic_schema_version"] == report["schema_version"]
    assert document["inventory"] == {
        "total_records": len(report["records"]),
        "selected_records": len(report["selection"]["record_indexes"]),
    }
    assert document["case"] == {"case_id": "CASE 資料", "examiner": "Analyst"}
    assert document["scan"] == {
        "input": report["input"],
        "started_at_utc": report["started_at_utc"],
        "completed_at_utc": report["completed_at_utc"],
        "options": report["options"],
    }
    assert document["selection"] == {
        "active": report["selection"]["active"],
        "filters": report["selection"]["filters"],
        "timezone": report["options"]["timezone"],
    }
    assert document["runtime_limits"] == limits.to_dict()
    assert "context" not in document
    assert verify_export(destination) == document
    assert report == before
    if format_name == "json":
        assert json.loads(expected) == report
        assert "manifest_schema_version" not in json.loads(expected)


def test_context_is_copied_verbatim_without_mutating_the_report(
    report: dict, tmp_path: Path
) -> None:
    context = {"source": "desktop", "note": "資料\n\u202e", "nested": {"ids": [1, None, True]}}
    expected = copy.deepcopy(context)
    before = copy.deepcopy(report)
    destination = tmp_path / "context.json"
    output.write_report(report, destination, "json", context=context)
    context["nested"]["ids"].append("later mutation")
    assert load_manifest(destination)["context"] == expected
    assert verify_export(destination)["context"] == expected
    assert report == before


def test_sidecar_size_is_independent_of_the_report_export_budget(
    report: dict, tmp_path: Path
) -> None:
    expected = render(report, "csv").encode("utf-8")
    destination = tmp_path / "compact.csv"
    output.write_report(
        report,
        destination,
        "csv",
        limits=WorkLimits(max_export_bytes=len(expected)),
        context={"description": "x" * 20_000},
    )
    assert sidecar(destination).stat().st_size > len(expected)
    assert destination.read_bytes() == expected
    assert verify_export(destination)["report"]["size_bytes"] == len(expected)


def test_oversize_generated_manifest_removes_the_pair(report: dict, tmp_path: Path) -> None:
    destination = tmp_path / "report.json"
    with pytest.raises(ManifestError):
        output.write_report(
            report, destination, "json", context={"description": "x" * MANIFEST_LIMIT}
        )
    assert not destination.exists()
    assert not sidecar(destination).exists()


def test_preexisting_sidecar_blocks_export_without_claiming_report(
    report: dict, tmp_path: Path
) -> None:
    destination = tmp_path / "report.json"
    sidecar(destination).write_text("another writer's manifest", encoding="utf-8")
    with pytest.raises((EvidenceError, FileExistsError, ManifestError)):
        output.write_report(report, destination, "json")
    assert not destination.exists()
    assert sidecar(destination).read_text("utf-8") == "another writer's manifest"


def test_sidecar_creation_race_preserves_the_other_writer_and_cleans_report(
    report: dict, tmp_path: Path, monkeypatch
) -> None:
    destination = tmp_path / "report.json"
    manifest_path = sidecar(destination)
    original_open = Path.open
    original_private = output._open_private

    @contextmanager
    def race_open(path):
        if path == manifest_path:
            with original_open(path, "w", encoding="utf-8") as competitor:
                competitor.write("racing manifest")
        with original_private(path) as stream:
            yield stream

    monkeypatch.setattr(output, "_open_private", race_open)
    with pytest.raises((EvidenceError, FileExistsError, ManifestError)):
        output.write_report(report, destination, "json")
    assert not destination.exists()
    assert manifest_path.read_text("utf-8") == "racing manifest"


@pytest.mark.parametrize("target", ["report", "manifest"])
@pytest.mark.parametrize("stage", ["write", "fsync", "close"])
@pytest.mark.parametrize("failure_kind", ["io", "deadline", "cancel"])
def test_failure_at_either_file_cleans_both_owned_paths(
    report: dict, tmp_path: Path, monkeypatch, target: str, stage: str, failure_kind: str
) -> None:
    destination = tmp_path / "report.json"
    manifest_path = sidecar(destination)
    clock = [0.0]
    monkeypatch.setattr(limit_module, "monotonic", lambda: clock[0])
    control = ScanControl()
    original_private = output._open_private
    original_fsync = output.os.fsync
    descriptor_paths = {}
    triggered = []

    def trip(path: Path, current_stage: str) -> None:
        target_path = destination if target == "report" else manifest_path
        if triggered or path != target_path or current_stage != stage:
            return
        triggered.append((path, current_stage))
        if failure_kind == "io":
            raise OSError("injected pair export failure")
        if failure_kind == "deadline":
            clock[0] = 2.0
        else:
            control.cancel()

    class TrackedStream:
        def __init__(self, stream, path):
            self.stream, self.path = stream, path

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def write(self, chunk):
            result = self.stream.write(chunk)
            trip(self.path, "write")
            return result

    @contextmanager
    def track_open(path):
        with original_private(path) as stream:
            descriptor_paths[stream.fileno()] = path
            yield TrackedStream(stream, path)
        trip(path, "close")

    def track_fsync(descriptor):
        original_fsync(descriptor)
        trip(descriptor_paths[descriptor], "fsync")

    monkeypatch.setattr(output, "_open_private", track_open)
    monkeypatch.setattr(output.os, "fsync", track_fsync)
    expected_failure = {
        "io": OSError,
        "deadline": WorkLimitExceeded,
        "cancel": ScanCancelled,
    }[failure_kind]
    with pytest.raises(expected_failure):
        with operation_budget(
            WorkLimits(max_operation_seconds=1), operation="export", control=control
        ):
            output.write_report(report, destination, "json")
    assert triggered, "The intended late file operation must have been exercised."
    assert not destination.exists()
    assert not manifest_path.exists()


@pytest.mark.skipif(os.name == "nt", reason="Windows prevents replacing open output handles")
@pytest.mark.parametrize("replacement", ["report", "manifest"])
def test_pair_cleanup_preserves_any_concurrent_replacement(
    report: dict, tmp_path: Path, monkeypatch, replacement: str
) -> None:
    destination = tmp_path / "report.json"
    manifest_path = sidecar(destination)
    replacement_path = destination if replacement == "report" else manifest_path
    original_fsync = output.os.fsync
    count = [0]

    def replace_then_fail(descriptor):
        original_fsync(descriptor)
        count[0] += 1
        if count[0] == 2:
            replacement_path.unlink()
            replacement_path.write_text("another writer's file", encoding="utf-8")
            raise OSError("late manifest disk failure")

    monkeypatch.setattr(output.os, "fsync", replace_then_fail)
    with pytest.raises(OSError, match="late manifest disk failure"):
        output.write_report(report, destination, "json")
    assert count[0] == 2
    assert replacement_path.read_text("utf-8") == "another writer's file"
    other_path = manifest_path if replacement == "report" else destination
    assert not other_path.exists()


def test_verifier_rejects_report_tampering_even_when_size_stays_the_same(exported: Path) -> None:
    content = bytearray(exported.read_bytes())
    content[len(content) // 2] ^= 1
    exported.write_bytes(content)
    with pytest.raises(ManifestError):
        verify_export(exported)


def test_verifier_rejects_truncated_report(exported: Path) -> None:
    exported.write_bytes(exported.read_bytes()[:-1])
    with pytest.raises(ManifestError):
        verify_export(exported)


@pytest.mark.parametrize(
    "filename",
    [
        "../report.json",
        "/report.json",
        "nested/report.json",
        "nested\\report.json",
        "C:\\report.json",
        ".",
        "..",
        "",
        "other.json",
        "report.json\0",
    ],
)
def test_verifier_never_follows_manifest_report_filenames(exported: Path, filename: str) -> None:
    document = load_manifest(exported)
    document["report"]["filename"] = filename
    replace_manifest(exported, document)
    with pytest.raises(ManifestError):
        verify_export(exported)


@pytest.mark.parametrize(
    "field,value",
    [
        ("format", "xml"),
        ("format", None),
        ("format", []),
        ("format", {}),
        ("size_bytes", -1),
        ("size_bytes", True),
        ("size_bytes", "100"),
        ("sha256", "z" * 64),
        ("sha256", "a" * 63),
        ("sha256", None),
    ],
)
def test_verifier_rejects_malformed_binding_fields(
    exported: Path, field: str, value: object
) -> None:
    document = load_manifest(exported)
    document["report"][field] = value
    replace_manifest(exported, document)
    with pytest.raises(ManifestError):
        verify_export(exported)


@pytest.mark.parametrize(
    "field,value",
    [
        ("manifest_schema_version", "2.0"),
        ("manifest_schema_version", 1),
        ("report", []),
        ("report", None),
        ("created_at_utc", "yesterday"),
        ("tool", None),
        ("inventory", []),
        ("runtime_limits", "unlimited"),
        ("runtime_limits", {}),
    ],
)
def test_verifier_rejects_malformed_manifest_structure(
    exported: Path, field: str, value: object
) -> None:
    document = load_manifest(exported)
    document[field] = value
    replace_manifest(exported, document)
    with pytest.raises(ManifestError):
        verify_export(exported)


@pytest.mark.parametrize(
    "content",
    [
        b"{",
        b"[]",
        b"null",
        b"\xff",
        b'{"manifest_schema_version": "1.0", "report": NaN}',
        b'{"value": ' + b"1" * 5_000 + b"}",
        b"[" * 1_500 + b"0" + b"]" * 1_500,
    ],
)
def test_verifier_wraps_malformed_json_as_manifest_error(exported: Path, content: bytes) -> None:
    sidecar(exported).write_bytes(content)
    with pytest.raises(ManifestError):
        verify_export(exported)


def test_verifier_rejects_duplicate_json_keys(exported: Path) -> None:
    document = sidecar(exported).read_text("utf-8")
    document = document.replace(
        '"manifest_schema_version": "1.0"',
        '"manifest_schema_version": "1.0", "manifest_schema_version": "1.0"',
    )
    sidecar(exported).write_text(document, encoding="utf-8")
    with pytest.raises(ManifestError):
        verify_export(exported)


@pytest.mark.parametrize("nonfinite", [float("nan"), float("inf"), float("-inf")])
def test_verifier_rejects_nonfinite_json_inside_optional_context(
    exported: Path, nonfinite: float
) -> None:
    document = load_manifest(exported)
    document["context"] = {"value": nonfinite}
    replace_manifest(exported, document)
    with pytest.raises(ManifestError):
        verify_export(exported)


def test_verifier_rejects_oversize_sidecar_before_parsing(exported: Path) -> None:
    sidecar(exported).write_bytes(b" " * (MANIFEST_LIMIT + 1))
    with pytest.raises(ManifestError):
        verify_export(exported)


@pytest.mark.parametrize("missing", ["report", "manifest"])
def test_verifier_wraps_missing_pair_members(exported: Path, missing: str) -> None:
    (exported if missing == "report" else sidecar(exported)).unlink()
    with pytest.raises(ManifestError):
        verify_export(exported)


@pytest.mark.parametrize("target", ["report", "manifest"])
def test_verifier_rejects_symlink_pair_members(exported: Path, tmp_path: Path, target: str) -> None:
    path = exported if target == "report" else sidecar(exported)
    original = tmp_path / (target + "-original")
    path.rename(original)
    try:
        path.symlink_to(original)
    except (OSError, NotImplementedError):
        pytest.skip("This host cannot create symlinks.")
    with pytest.raises(ManifestError):
        verify_export(exported)


def test_verifier_rejects_symlink_parent(exported: Path, tmp_path: Path) -> None:
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(exported.parent, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("This host cannot create symlinks.")
    with pytest.raises(ManifestError):
        verify_export(alias / exported.name)


def test_symlink_sidecar_blocks_export_and_preserves_target(report: dict, tmp_path: Path) -> None:
    destination = tmp_path / "report.json"
    target = tmp_path / "existing-manifest"
    target.write_text("existing bytes", encoding="utf-8")
    try:
        sidecar(destination).symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("This host cannot create symlinks.")
    with pytest.raises((EvidenceError, ManifestError)):
        output.write_report(report, destination, "json")
    assert not destination.exists()
    assert sidecar(destination).is_symlink()
    assert target.read_text("utf-8") == "existing bytes"
