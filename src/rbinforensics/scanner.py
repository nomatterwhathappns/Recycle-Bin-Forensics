"""Read bounded metadata, correlate sibling payloads, and retain provenance.

Never use the original Windows path to open a file. Evidence paths come only
from the examiner's input and directory entries. This is a logical-artifact
reader, not an acquisition tool or a substitute for a write blocker.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO
from zoneinfo import ZoneInfo

from . import __version__
from .parser import ParseError, parse_metadata

MAX_METADATA_BYTES = 128 * 1024
HASH_CHUNK_BYTES = 1024 * 1024
SID_PATTERN = re.compile(r"S-\d+(?:-\d+)+", re.IGNORECASE)
ASCII_CASE = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


class EvidenceError(ValueError):
    """An unsafe, changed, or unreadable evidence item."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ScanOptions:
    recursive: bool = False
    hash_payload: bool = False
    timezone: str = "UTC"
    case_id: str | None = None
    examiner: str | None = None


def absolute_path(path: Path) -> Path:
    """Make an absolute path without resolving away symlink evidence."""
    return Path(os.path.abspath(path))


def ensure_no_symlinks(path: Path) -> None:
    """Reject symlinks and Windows reparse points; do not resolve them first."""
    for component in reversed((path, *path.parents)):
        try:
            info = component.lstat()
        except FileNotFoundError:
            continue
        if _redirects(info):
            raise EvidenceError("symlink_skipped", f"Symlink/reparse-point component: {component}")


def _redirects(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


@contextmanager
def _open_regular(path: Path) -> Iterator[tuple[BinaryIO, os.stat_result]]:
    ensure_no_symlinks(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise EvidenceError("not_regular_file", "Evidence item is not a regular file.")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    # A file replaced with a FIFO between lstat/open must not hang the scan.
    flags |= getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or _identity(before) != _identity(opened):
            raise EvidenceError(
                "changed_during_read",
                f"Evidence changed while opening it (lstat={_identity(before)}, fstat={_identity(opened)}).",
            )
        yield stream, opened
        after = os.fstat(stream.fileno())
        # Also detect replacement of the directory entry during a read.
        if _identity(opened) != _identity(after) or _identity(after) != _identity(path.lstat()):
            raise EvidenceError("changed_during_read", "Evidence changed while reading it.")


def _read_metadata(path: Path) -> tuple[bytes, str]:
    with _open_regular(path) as (stream, info):
        if info.st_size > MAX_METADATA_BYTES:
            raise EvidenceError("metadata_too_large", "Metadata exceeds the 128 KiB safety limit.")
        data = stream.read(MAX_METADATA_BYTES + 1)
        if len(data) > MAX_METADATA_BYTES:
            raise EvidenceError("metadata_too_large", "Metadata exceeds the 128 KiB safety limit.")
        if len(data) != info.st_size:
            raise EvidenceError("changed_during_read", "Metadata length changed during read.")
    return data, hashlib.sha256(data).hexdigest()


def _hash_payload(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    length = 0
    with _open_regular(path) as (stream, _):
        for block in iter(lambda: stream.read(HASH_CHUNK_BYTES), b""):
            digest.update(block)
            length += len(block)
    return digest.hexdigest(), length


def _issue(record: dict, code: str, message: str = "", severity: str = "warning") -> None:
    record["issues"].append({"code": code, "severity": severity, "message": message or code})
    if severity == "error":
        record["status"] = "error"
    elif record["status"] == "ok":
        record["status"] = "warning"


def _new_record(path: Path, record_type: str = "metadata") -> dict:
    return {
        "record_type": record_type,
        "source_path": str(path),
        "source_name": path.name,
        "source_size": None,
        "source_sha256": None,
        "sid": next((p.name for p in path.parents if SID_PATTERN.fullmatch(p.name)), None),
        "status": "ok",
        "metadata": None,
        "payload": None,
        "issues": [],
    }


def _discover(directory: Path, recursive: bool, issues: list[dict]) -> Iterator[Path]:
    # An explicit stack avoids Python recursion limits on deep directory trees.
    pending = [directory]
    while pending:
        current = pending.pop()
        try:
            ensure_no_symlinks(current)
            with os.scandir(current) as entries:
                ordered = sorted(entries, key=lambda e: e.name)
            children = []
            for entry in ordered:
                path = Path(entry.path)
                try:
                    if _redirects(entry.stat(follow_symlinks=False)):
                        if recursive or entry.name.lower().startswith("$i"):
                            record = _new_record(path, "discovery")
                            _issue(
                                record,
                                "symlink_skipped",
                                "Symlinks/reparse points are never followed.",
                            )
                            record["status"] = "skipped"
                            issues.append(record)
                    elif entry.is_dir(follow_symlinks=False):
                        if recursive:
                            children.append(path)
                    elif entry.name.lower().startswith("$i"):
                        yield path
                except OSError as exc:
                    record = _new_record(path, "discovery")
                    _issue(record, "discovery_error", str(exc), "error")
                    issues.append(record)
            pending.extend(reversed(children))
        except (OSError, EvidenceError) as exc:
            record = _new_record(current, "discovery")
            _issue(record, getattr(exc, "code", "discovery_error"), str(exc), "error")
            issues.append(record)


def _payload(record: dict, source: Path, requested: bool, indexes: dict) -> dict:
    result = {
        "path": None,
        "status": "not_checked",
        "size": None,
        "sha256": None,
        "hash_status": "not_requested" if not requested else "unavailable",
        "size_matches_metadata": None,
    }
    if not source.name.lower().startswith("$i") or len(source.name) <= 2:
        _issue(record, "nonstandard_source_name", "Cannot infer a sibling $R filename.")
        return result
    expected_name = "$R" + source.name[2:]
    # Avoid Unicode casefold equivalences such as sharp-s -> ss, which could
    # falsely correlate two different artifacts on a copied POSIX tree.
    wanted = expected_name.translate(ASCII_CASE)
    try:
        if source.parent not in indexes:
            index: dict[str, list[Path]] = {}
            with os.scandir(source.parent) as entries:
                for entry in entries:
                    if entry.name.lower().startswith("$r"):
                        key = entry.name.translate(ASCII_CASE)
                        index.setdefault(key, []).append(Path(entry.path))
            indexes[source.parent] = index
        matches = indexes[source.parent].get(wanted, [])
        if not matches:
            result["status"] = "missing"
            return result
        if len(matches) != 1:
            result["status"] = "ambiguous"
            _issue(record, "ambiguous_payload", "Multiple case-insensitive $R matches.")
            return result
        path = matches[0]
        if path.name != expected_name:
            _issue(
                record,
                "payload_case_insensitive_match",
                "Sibling matched using ASCII case-insensitive names.",
            )
        result["path"] = str(path)
        info = path.lstat()
        if _redirects(info):
            result["status"] = "symlink_skipped"
            _issue(
                record,
                "payload_symlink_skipped",
                "Payload symlinks/reparse points are never opened.",
            )
        elif stat.S_ISDIR(info.st_mode):
            result["status"] = "available_directory"
            result["hash_status"] = "not_applicable"
        elif stat.S_ISREG(info.st_mode):
            result["status"] = "available_file"
            result["size"] = info.st_size
            result["size_matches_metadata"] = info.st_size == record["metadata"]["original_size"]
            if not result["size_matches_metadata"]:
                _issue(
                    record, "payload_size_mismatch", "Observed $R size differs from $I metadata."
                )
            if requested:
                digest, length = _hash_payload(path)
                result.update(sha256=digest, size=length, hash_status="computed")
                if length != info.st_size or _identity(info) != _identity(path.lstat()):
                    raise EvidenceError(
                        "changed_during_read", "Payload changed before/during hashing."
                    )
        else:
            result["status"] = "special_file_skipped"
            _issue(record, "payload_not_regular", "Special files are never opened.")
    except (OSError, EvidenceError) as exc:
        result.update(status="unreadable", sha256=None, size_matches_metadata=None)
        if requested:
            result["hash_status"] = "unavailable"
        _issue(
            record,
            getattr(exc, "code", "payload_unreadable"),
            str(exc),
            "error" if requested else "warning",
        )
    return result


def _display_time(value: str | None, zone: ZoneInfo | timezone) -> str | None:
    if value is None:
        return None
    # Python 3.10 accepts at most six fractional digits. datetime is used only
    # for the timezone offset; retain all seven source digits separately.
    parsed = datetime.fromisoformat(value[:26] + "+00:00")
    local = parsed.astimezone(zone).isoformat(timespec="seconds")
    return local[:19] + "." + value[20:27] + local[19:]


def scan(input_path: Path, options: ScanOptions | None = None) -> dict:
    """Return a JSON-serializable report; structural input errors raise.

    Every discovered candidate produces its own result. A corrupt record cannot
    abort the rest of a case. Warnings never fabricate missing metadata.
    """
    options = options or ScanOptions()
    source = absolute_path(input_path)
    ensure_no_symlinks(source)
    info = source.stat()
    if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
        raise EvidenceError("invalid_input", "Input must be a regular file or directory.")
    zone = timezone.utc if options.timezone == "UTC" else ZoneInfo(options.timezone)
    started = datetime.now(timezone.utc).isoformat()
    records: list[dict] = []
    discovery: list[dict] = []
    candidates = _discover(source, options.recursive, discovery) if source.is_dir() else [source]
    indexes: dict = {}
    for path in candidates:
        record = _new_record(path)
        try:
            data, digest = _read_metadata(path)
            record.update(source_size=len(data), source_sha256=digest)
            metadata = parse_metadata(data)
            record["metadata"] = asdict(metadata)
            record["metadata"].pop("warnings")
            try:
                record["metadata"]["deleted_at_display"] = _display_time(
                    metadata.deleted_at_utc, zone
                )
            except (OverflowError, ValueError):
                record["metadata"]["deleted_at_display"] = None
                _issue(record, "display_time_out_of_range", "Timezone conversion is out of range.")
            for code in metadata.warnings:
                _issue(record, code)
            record["payload"] = _payload(record, path, options.hash_payload, indexes)
        except (OSError, EvidenceError, ParseError) as exc:
            _issue(record, getattr(exc, "code", "source_unreadable"), str(exc), "error")
        records.append(record)
    records.extend(discovery)
    records.sort(key=lambda item: item["source_path"])
    return {
        "schema_version": "1.0",
        "tool": {"name": "rbinforensics", "version": __version__},
        "started_at_utc": started,
        "completed_at_utc": datetime.now(timezone.utc).isoformat(),
        "input": str(source),
        "options": asdict(options),
        "summary": {
            "candidates": sum(r["record_type"] == "metadata" for r in records),
            "parsed": sum(r["metadata"] is not None for r in records),
            "errors": sum(r["status"] == "error" for r in records),
            "warnings": sum(any(i["severity"] == "warning" for i in r["issues"]) for r in records),
            "skipped": sum(r["status"] == "skipped" for r in records),
            "payloads_hashed": sum(bool(r["payload"] and r["payload"]["sha256"]) for r in records),
        },
        "records": records,
    }
