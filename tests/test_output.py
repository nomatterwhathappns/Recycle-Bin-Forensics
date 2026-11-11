"""Export failure must preserve files owned by somebody else."""

from __future__ import annotations

import os
import struct
from pathlib import Path

import pytest

from rbinforensics import output
from rbinforensics.scanner import EvidenceError, scan


@pytest.fixture
def report(tmp_path: Path) -> dict:
    source = tmp_path.resolve() / "evidence" / "$IABC.txt"
    source.parent.mkdir()
    path = (r"C:\Users\Demo\file.txt" + "\0").encode("utf-16-le")
    source.write_bytes(struct.pack("<QQQI", 2, 7, 133485408001234567, len(path) // 2) + path)
    return scan(source)


@pytest.mark.skipif(os.name == "nt", reason="Windows prevents replacing this open output handle")
def test_failed_write_preserves_concurrent_replacement(report: dict, tmp_path: Path, monkeypatch):
    destination = tmp_path.resolve() / "report.json"

    def replace_then_fail(_descriptor):
        destination.unlink()
        destination.write_text("another writer's output", encoding="utf-8")
        raise OSError("simulated disk failure")

    monkeypatch.setattr(output.os, "fsync", replace_then_fail)
    with pytest.raises(OSError, match="simulated disk failure"):
        output.write_report(report, destination, "json")
    assert destination.read_text("utf-8") == "another writer's output"


def test_single_file_evidence_directory_stays_protected_after_source_replacement(report: dict):
    source = Path(report["input"])
    source.unlink()
    source.mkdir()
    destination = source.parent / "report.json"
    with pytest.raises(EvidenceError, match="outside the evidence directory"):
        output.write_report(report, destination, "json")
    assert not destination.exists()


def test_cleanup_failure_does_not_mask_original_write_error(
    report: dict, tmp_path: Path, monkeypatch
):
    destination = tmp_path.resolve() / "report.json"
    original_unlink = Path.unlink

    def fail_cleanup(path, *args, **kwargs):
        if path == destination:
            raise PermissionError("cleanup unavailable")
        return original_unlink(path, *args, **kwargs)

    def fail_sync(_descriptor):
        raise OSError("original disk error")

    monkeypatch.setattr(output.os, "fsync", fail_sync)
    monkeypatch.setattr(Path, "unlink", fail_cleanup)
    with pytest.raises(OSError, match="original disk error"):
        output.write_report(report, destination, "json")


def test_render_failure_never_creates_output(report: dict, tmp_path: Path):
    destination = tmp_path.resolve() / "report.json"
    with pytest.raises(ValueError, match="Unknown report format"):
        output.write_report(report, destination, "invalid")
    assert not destination.exists()
