"""One exclusive, evidence-safe report writer shared by CLI and desktop."""

from __future__ import annotations

import os
import stat
from contextlib import closing
from pathlib import Path

from .limits import WorkLimits, operation_budget
from .reports import iter_render
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


def write_report(
    report: dict, destination: Path, format_name: str, *, limits: WorkLimits | None = None
) -> Path:
    output = absolute_path(destination)
    source = Path(report["input"])
    created_identity: tuple[int, int] | None = None
    try:
        with operation_budget(limits, operation="export", reuse=True) as budget:
            budget.check_record_count(len(report["records"]))
            source_was_file = False
            for record in report["records"]:
                budget.check()
                if record["record_type"] == "metadata" and record["source_path"] == str(source):
                    source_was_file = True
                    break
            validate_output(source, output, source_was_file=source_was_file)
            with closing(iter_render(report, format_name, limits=limits)) as chunks:
                # Validate the format and first chunk before claiming a filename.
                first = next(chunks)
                validate_output(source, output, source_was_file=source_was_file)
                budget.check()
                with output.open("x", encoding="utf-8", newline="") as stream:
                    opened = os.fstat(stream.fileno())
                    created_identity = opened.st_dev, opened.st_ino
                    stream.write(first)
                    for chunk in chunks:
                        stream.write(chunk)
                        budget.check()
                    stream.flush()
                    budget.check()
                    os.fsync(stream.fileno())
                    budget.check()
                budget.check()
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
