"""One exclusive, evidence-safe report writer shared by CLI and desktop."""

from __future__ import annotations

import hashlib
import os
import stat
from contextlib import closing
from pathlib import Path

from .limits import WorkLimits, operation_budget
from .manifest import build_manifest, iter_manifest, manifest_path
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
    report: dict,
    destination: Path,
    format_name: str,
    *,
    limits: WorkLimits | None = None,
    context: dict | None = None,
) -> Path:
    output = absolute_path(destination)
    sidecar = manifest_path(output)
    source = Path(report["input"])
    created: dict[Path, tuple[int, int]] = {}
    ownership_handles: list[int] = []

    def remember_created(path: Path, stream) -> None:
        opened = os.fstat(stream.fileno())
        created[path] = opened.st_dev, opened.st_ino
        # Keep the inode allocated after the text stream closes. Otherwise an
        # unlinked report's inode could be reused by a concurrent replacement
        # while we finish the sidecar, defeating an inode-only cleanup check.
        ownership_handles.append(os.dup(stream.fileno()))

    def validate_pair(*, source_was_file: bool) -> None:
        validate_output(source, output, source_was_file=source_was_file)
        validate_output(source, sidecar, source_was_file=source_was_file)

    def check_owned(path: Path, size: int) -> None:
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or (info.st_dev, info.st_ino) != created[path]
            or info.st_size != size
        ):
            raise EvidenceError(
                "output_changed", "Export output changed while it was being written."
            )

    try:
        with operation_budget(limits, operation="export", reuse=True) as budget:
            budget.check_record_count(len(report["records"]))
            source_was_file = False
            for record in report["records"]:
                budget.check()
                if record["record_type"] == "metadata" and record["source_path"] == str(source):
                    source_was_file = True
                    break
            validate_pair(source_was_file=source_was_file)
            digest = hashlib.sha256()
            size = 0
            with closing(iter_render(report, format_name, limits=limits)) as chunks:
                # Validate the format and first chunk before claiming a filename.
                first = next(chunks)
                validate_pair(source_was_file=source_was_file)
                budget.check()
                with output.open("x", encoding="utf-8", newline="") as stream:
                    remember_created(output, stream)

                    def write_chunk(chunk: str) -> None:
                        nonlocal size
                        budget.check()
                        encoded = chunk.encode("utf-8")
                        if stream.write(chunk) != len(chunk):
                            raise OSError("Incomplete report write.")
                        digest.update(encoded)
                        size += len(encoded)
                        budget.check()

                    write_chunk(first)
                    for chunk in chunks:
                        write_chunk(chunk)
                    stream.flush()
                    budget.check()
                    os.fsync(stream.fileno())
                    budget.check()
                budget.check()
            check_owned(output, size)
            manifest = build_manifest(
                report,
                output,
                format_name,
                size,
                digest.hexdigest(),
                limits=budget.limits,
                context=context,
            )
            validate_output(source, sidecar, source_was_file=source_was_file)
            budget.check()
            manifest_size = 0
            with sidecar.open("x", encoding="utf-8", newline="") as stream:
                remember_created(sidecar, stream)
                for chunk in iter_manifest(manifest):
                    budget.check()
                    if stream.write(chunk) != len(chunk):
                        raise OSError("Incomplete manifest write.")
                    manifest_size += len(chunk.encode("utf-8"))
                    budget.check()
                stream.flush()
                budget.check()
                os.fsync(stream.fileno())
                budget.check()
            budget.check()
            check_owned(output, size)
            check_owned(sidecar, manifest_size)
    except BaseException:
        for path, identity in reversed(tuple(created.items())):
            try:
                current = path.lstat()
                if stat.S_ISREG(current.st_mode) and (current.st_dev, current.st_ino) == identity:
                    path.unlink()
            except OSError:
                pass
        raise
    finally:
        for descriptor in ownership_handles:
            try:
                os.close(descriptor)
            except OSError:
                pass
    return output
