"""One exclusive, evidence-safe report writer shared by CLI and desktop."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from .reports import render
from .scanner import EvidenceError, absolute_path, ensure_no_symlinks


def validate_output(source: Path, output: Path, *, source_was_file: bool = False) -> None:
    source, output = absolute_path(source), absolute_path(output)
    ensure_no_symlinks(output)
    if output.exists():
        raise EvidenceError("output_exists", "Output already exists; choose a new filename.")
    root = source if not source_was_file and source.is_dir() else source.parent
    if output == root or root in output.parents:
        raise EvidenceError(
            "output_inside_evidence", "Report output must be outside the evidence directory."
        )
    if not output.parent.is_dir():
        raise EvidenceError("output_parent_missing", "Output parent directory must already exist.")


def write_report(report: dict, destination: Path, format_name: str) -> Path:
    output = absolute_path(destination)
    source = Path(report["input"])
    source_was_file = any(
        record["record_type"] == "metadata" and record["source_path"] == str(source)
        for record in report["records"]
    )
    validate_output(source, output, source_was_file=source_was_file)
    text = render(report, format_name)
    validate_output(source, output, source_was_file=source_was_file)
    created_identity: tuple[int, int] | None = None
    try:
        with output.open("x", encoding="utf-8", newline="") as stream:
            opened = os.fstat(stream.fileno())
            created_identity = opened.st_dev, opened.st_ino
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        if created_identity is not None:
            try:
                current = output.lstat()
                if (
                    stat.S_ISREG(current.st_mode)
                    and (current.st_dev, current.st_ino) == created_identity
                ):
                    output.unlink()
            except OSError:
                pass
        raise
    return output
