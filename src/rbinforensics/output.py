"""One exclusive, evidence-safe report writer shared by CLI and desktop."""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Iterator
from contextlib import closing, contextmanager
from pathlib import Path
from typing import TextIO

from .limits import WorkLimits, operation_budget
from .manifest import build_manifest, iter_manifest, manifest_path
from .reports import iter_render
from .scanner import EvidenceError, absolute_path, ensure_no_symlinks


@contextmanager
def _open_private(path: Path) -> Iterator[TextIO]:
    """Claim a new file with private POSIX permissions from its first instant."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags, 0o600)
    identity = None
    try:
        opened = os.fstat(descriptor)
        identity = opened.st_dev, opened.st_ino
        stream = os.fdopen(descriptor, "w", encoding="utf-8", newline="")
    except BaseException:
        # fdopen can fail before the writer has a stream to register. Retain
        # ownership while unlinking on POSIX; Windows needs the handle closed.
        if os.name == "nt":
            try:
                os.close(descriptor)
            except OSError:
                pass
        if identity is not None:
            try:
                current = path.lstat()
                if stat.S_ISREG(current.st_mode) and (current.st_dev, current.st_ino) == identity:
                    path.unlink()
            except OSError:
                pass
        if os.name != "nt":
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise
    with stream:
        yield stream


def _sharing_context(context: dict | None) -> dict | None:
    """Carry only complete, validated numeric phase budgets into sharing files."""
    if context is None:
        return None
    if not isinstance(context, dict):
        raise ValueError("Export context must be a JSON object.")
    result = {}
    required = set(WorkLimits().to_dict())
    for name in ("scan_limits", "filter_limits"):
        if name in context:
            value = context[name]
            if not isinstance(value, dict) or set(value) != required:
                raise ValueError(f"Invalid sharing context {name}.")
            result[name] = WorkLimits(**value).to_dict()
    return result


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
    redacted: bool = False,
) -> Path:
    if type(redacted) is not bool:
        raise ValueError("redacted must be a boolean.")
    output = absolute_path(destination)
    sidecar = manifest_path(output)
    source = Path(report["input"])
    created: dict[Path, tuple[int, int]] = {}
    ownership_handles: list[int] = []

    def close_ownership_handles() -> None:
        while ownership_handles:
            try:
                os.close(ownership_handles.pop())
            except OSError:
                pass

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
            export_report = report
            if redacted:
                from .privacy import redact_report

                export_report = redact_report(report)
                context = _sharing_context(context)
            digest = hashlib.sha256()
            size = 0
            with closing(iter_render(export_report, format_name, limits=limits)) as chunks:
                # Validate the format and first chunk before claiming a filename.
                first = next(chunks)
                validate_pair(source_was_file=source_was_file)
                budget.check()
                with _open_private(output) as stream:
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
                export_report,
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
            with _open_private(sidecar) as stream:
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
        # Windows denies unlinking files held by ordinary Python handles.
        # POSIX retains these references until after rollback to prevent inode
        # reuse from making an unrelated replacement appear to be ours.
        if os.name == "nt":
            close_ownership_handles()
        for path, identity in reversed(tuple(created.items())):
            try:
                current = path.lstat()
                if stat.S_ISREG(current.st_mode) and (current.st_dev, current.st_ino) == identity:
                    path.unlink()
            except OSError:
                pass
        raise
    finally:
        close_ownership_handles()
    return output
