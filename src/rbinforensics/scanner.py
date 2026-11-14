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
from contextvars import ContextVar
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO
from zoneinfo import ZoneInfo

from . import __version__
from .analysis import (
    FilterOptions,
    apply_filters,
    build_timeline,
    selected_records,
    validate_filters,
)
from .limits import WorkLimits, check_budget, current_budget, operation_budget
from .parser import ParseError, parse_metadata
from .scan_control import ScanControl, ScanProgress

MAX_METADATA_BYTES = 128 * 1024
HASH_CHUNK_BYTES = 1024 * 1024
SID_PATTERN = re.compile(r"S-\d+(?:-\d+)+", re.IGNORECASE)
ASCII_CASE = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
_WINDOWS = os.name == "nt"


@dataclass
class _ProgressState:
    control: ScanControl
    processed: int = 0
    total: int | None = None


_ACTIVE_SCAN: ContextVar[_ProgressState | None] = ContextVar("rbf_active_scan", default=None)


def _check_cancel() -> None:
    check_budget()
    state = _ACTIVE_SCAN.get()
    if state is not None:
        state.control.check()


def _progress(
    phase: str, path: Path | None = None, *, length: int = 0, size: int | None = None
) -> None:
    _check_cancel()
    state = _ACTIVE_SCAN.get()
    if state is not None:
        state.control.emit(
            ScanProgress(
                phase,
                state.processed,
                state.total,
                str(path) if path is not None else None,
                length,
                size,
            )
        )
    _check_cancel()


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
    limits: WorkLimits | None = None


def absolute_path(path: Path) -> Path:
    """Make an absolute path without resolving away symlink evidence."""
    return Path(os.path.abspath(path))


def ensure_no_symlinks(path: Path) -> None:
    """Reject symlinks and Windows reparse points; do not resolve them first."""
    for component in reversed((path, *path.parents)):
        _check_cancel()
        try:
            info = component.lstat()
        except FileNotFoundError:
            continue
        if _redirects(info):
            raise EvidenceError("symlink_skipped", f"Symlink/reparse-point component: {component}")
        _check_cancel()


def _redirects(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _cross_api_identity(info: os.stat_result) -> tuple[int, ...]:
    # Windows Python 3.13 can expose different ctime values via lstat and
    # fstat for the same unchanged file. Compare ctime only within the same
    # API below; retain device/inode/size/mtime across the path and handle.
    signature = _identity(info)
    return signature[:-1] if _WINDOWS else signature


@contextmanager
def _open_regular(path: Path) -> Iterator[tuple[BinaryIO, os.stat_result]]:
    ensure_no_symlinks(path)
    _check_cancel()
    before = path.lstat()
    _check_cancel()
    if not stat.S_ISREG(before.st_mode):
        raise EvidenceError("not_regular_file", "Evidence item is not a regular file.")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    # A file replaced with a FIFO between lstat/open must not hang the scan.
    flags |= getattr(os, "O_NONBLOCK", 0)
    _check_cancel()
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        _check_cancel()
        opened = os.fstat(stream.fileno())
        _check_cancel()
        if not stat.S_ISREG(opened.st_mode) or _cross_api_identity(before) != _cross_api_identity(
            opened
        ):
            raise EvidenceError(
                "changed_during_read",
                f"Evidence changed while opening it (lstat={_identity(before)}, fstat={_identity(opened)}).",
            )
        yield stream, opened
        _check_cancel()
        after = os.fstat(stream.fileno())
        _check_cancel()
        path_after = path.lstat()
        _check_cancel()
        # Also detect replacement of the directory entry during a read.
        if (
            _identity(opened) != _identity(after)
            or _identity(before) != _identity(path_after)
            or _cross_api_identity(after) != _cross_api_identity(path_after)
        ):
            raise EvidenceError("changed_during_read", "Evidence changed while reading it.")


def _read_metadata(path: Path) -> tuple[bytes, str]:
    _check_cancel()
    with _open_regular(path) as (stream, info):
        if info.st_size > MAX_METADATA_BYTES:
            raise EvidenceError("metadata_too_large", "Metadata exceeds the 128 KiB safety limit.")
        budget = current_budget()
        if budget is not None:
            budget.check_metadata_capacity(info.st_size)
        _check_cancel()
        data = stream.read(MAX_METADATA_BYTES + 1)
        _check_cancel()
        if budget is not None:
            budget.consume_metadata_bytes(len(data))
        if len(data) > MAX_METADATA_BYTES:
            raise EvidenceError("metadata_too_large", "Metadata exceeds the 128 KiB safety limit.")
        if len(data) != info.st_size:
            raise EvidenceError("changed_during_read", "Metadata length changed during read.")
    return data, hashlib.sha256(data).hexdigest()


def _hash_payload(path: Path) -> tuple[str, int]:
    _check_cancel()
    digest = hashlib.sha256()
    length = 0
    with _open_regular(path) as (stream, info):
        budget = current_budget()
        if budget is not None:
            budget.check_hash_capacity(info.st_size)
        _progress("hashing", path, length=0, size=info.st_size)
        while True:
            _check_cancel()
            block = stream.read(HASH_CHUNK_BYTES)
            _check_cancel()
            if not block:
                break
            if budget is not None:
                budget.consume_hash_bytes(len(block))
            digest.update(block)
            length += len(block)
            _progress("hashing", path, length=length, size=info.st_size)
    _check_cancel()
    return digest.hexdigest(), length


def _issue(record: dict, code: str, message: str = "", severity: str = "warning") -> None:
    record["issues"].append({"code": code, "severity": severity, "message": message or code})
    if severity == "error":
        record["status"] = "error"
    elif record["status"] == "ok":
        record["status"] = "warning"


def _new_record(path: Path, record_type: str = "metadata") -> dict:
    _reserve_record(path, record_type)
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


def _reserve_record(path: Path, record_type: str = "metadata") -> None:
    budget = current_budget()
    if budget is not None:
        # An observed $I entry is admitted during inventory, before it can
        # become either a metadata result or its discovery diagnostic.
        kind = (
            "metadata"
            if record_type == "discovery" and path.name.lower().startswith("$i")
            else record_type
        )
        budget.reserve_record(kind, path)


def _is_payload_name(name: str) -> bool:
    return len(name) > 2 and name.lower().startswith("$r") and name.lower() != "$recycle.bin"


def _discovery_metadata_jobs(
    discovery: list[dict], metadata_names: dict[Path, set[str]]
) -> list[dict]:
    """Find observed $I entries whose source could not safely be read.

    Only entries registered inside an inventoried directory qualify. A generic
    failed/redirected directory must not cause a sibling outside input scope to
    be opened. These records retain null metadata/source hashes; the safe $R
    sibling can still be observed using the same filename-only correlation.
    """
    jobs = []
    for record in discovery:
        _check_cancel()
        path = Path(record["source_path"])
        if path.name.lower().startswith("$i") and path.name.translate(
            ASCII_CASE
        ) in metadata_names.get(path.parent, set()):
            jobs.append(record)
    return jobs


def _discover(
    directory: Path,
    recursive: bool,
    issues: list[dict],
    payloads: list[Path],
    metadata_names: dict[Path, set[str]],
    indexes: dict[Path, dict[str, list[Path]]],
) -> Iterator[Path]:
    # An explicit stack avoids Python recursion limits on deep directory trees.
    pending = [(directory, 0)]
    while pending:
        _check_cancel()
        current, depth = pending.pop()
        budget = current_budget()
        if budget is not None:
            budget.check_depth(depth)
        _progress("discovering", current)
        try:
            ensure_no_symlinks(current)
            _check_cancel()
            with os.scandir(current) as entries:
                collected = []
                for entry in entries:
                    _check_cancel()
                    if budget is not None:
                        budget.visit_entry()
                    if entry.name.lower().startswith("$i"):
                        _reserve_record(Path(entry.path))
                    collected.append(entry)
                _check_cancel()
                ordered = sorted(collected, key=lambda e: e.name)
            _check_cancel()
            names: set[str] = set()
            index: dict[str, list[Path]] = {}
            for entry in ordered:
                _check_cancel()
                if entry.name.lower().startswith("$i"):
                    names.add(entry.name.translate(ASCII_CASE))
                if _is_payload_name(entry.name):
                    index.setdefault(entry.name.translate(ASCII_CASE), []).append(Path(entry.path))
            # Publish only a complete directory inventory. In particular, a
            # failed listing cannot establish that a collected $R is orphaned.
            metadata_names[current] = names
            indexes[current] = index
            for matches in index.values():
                for path in matches:
                    _check_cancel()
                    if ("$I" + path.name[2:]).translate(ASCII_CASE) not in names:
                        _reserve_record(path, "orphan_payload")
                        payloads.append(path)
            children = []
            for entry in ordered:
                _check_cancel()
                path = Path(entry.path)
                _progress("discovering", path)
                is_payload = _is_payload_name(entry.name)
                try:
                    entry_info = entry.stat(follow_symlinks=False)
                    _check_cancel()
                    if _redirects(entry_info):
                        if not is_payload and (recursive or entry.name.lower().startswith("$i")):
                            record = _new_record(path, "discovery")
                            _issue(
                                record,
                                "symlink_skipped",
                                "Symlinks/reparse points are never followed.",
                            )
                            record["status"] = "skipped"
                            issues.append(record)
                    elif stat.S_ISDIR(entry_info.st_mode):
                        if entry.name.lower().startswith("$i"):
                            yield path
                        elif recursive and not is_payload:
                            children.append((path, depth + 1))
                    elif entry.name.lower().startswith("$i"):
                        yield path
                except OSError as exc:
                    record = _new_record(path, "discovery")
                    _issue(record, "discovery_error", str(exc), "error")
                    issues.append(record)
            pending.extend(reversed(children))
            _check_cancel()
        except (OSError, EvidenceError) as exc:
            record = _new_record(current, "discovery")
            _issue(record, getattr(exc, "code", "discovery_error"), str(exc), "error")
            issues.append(record)


def _empty_payload(requested: bool) -> dict:
    return {
        "path": None,
        "status": "not_checked",
        "size": None,
        "sha256": None,
        "hash_status": "not_requested" if not requested else "unavailable",
        "size_matches_metadata": None,
    }


def _inspect_payload(record: dict, path: Path, requested: bool, result: dict) -> None:
    _check_cancel()
    result["path"] = str(path)
    info = path.lstat()
    _check_cancel()
    if _redirects(info):
        result["status"] = "symlink_skipped"
        _issue(
            record, "payload_symlink_skipped", "Payload symlinks/reparse points are never opened."
        )
        if record["status"] != "error":
            record["status"] = "skipped"
    elif stat.S_ISDIR(info.st_mode):
        result["status"] = "available_directory"
        result["hash_status"] = "not_applicable"
    elif stat.S_ISREG(info.st_mode):
        result["status"] = "available_file"
        result["size"] = info.st_size
        if record["metadata"] is not None:
            result["size_matches_metadata"] = info.st_size == record["metadata"]["original_size"]
            if not result["size_matches_metadata"]:
                _issue(
                    record, "payload_size_mismatch", "Observed $R size differs from $I metadata."
                )
        if requested:
            digest, length = _hash_payload(path)
            result.update(sha256=digest, size=length, hash_status="computed")
            _check_cancel()
            if length != info.st_size or _identity(info) != _identity(path.lstat()):
                raise EvidenceError("changed_during_read", "Payload changed before/during hashing.")
            _check_cancel()
    else:
        result["status"] = "special_file_skipped"
        _issue(record, "payload_not_regular", "Special files are never opened.")
        if record["status"] != "error":
            record["status"] = "skipped"


def _payload_failure(record: dict, result: dict, exc: Exception, requested: bool) -> None:
    result.update(status="unreadable", sha256=None, size_matches_metadata=None)
    if requested:
        result["hash_status"] = "unavailable"
    _issue(
        record,
        getattr(exc, "code", "payload_unreadable"),
        str(exc),
        "error" if requested else "warning",
    )


def _payload(record: dict, source: Path, requested: bool, indexes: dict) -> dict:
    result = _empty_payload(requested)
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
            _check_cancel()
            with os.scandir(source.parent) as entries:
                for entry in entries:
                    _check_cancel()
                    budget = current_budget()
                    if budget is not None:
                        budget.visit_entry()
                    if _is_payload_name(entry.name):
                        key = entry.name.translate(ASCII_CASE)
                        index.setdefault(key, []).append(Path(entry.path))
            _check_cancel()
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
        _inspect_payload(record, path, requested, result)
    except (OSError, EvidenceError) as exc:
        _payload_failure(record, result, exc, requested)
    return result


def _orphan_payload(path: Path, requested: bool) -> dict:
    record = _new_record(path, "orphan_payload")
    _issue(
        record, "orphan_payload", "No sibling $I entry was found; original path/time are unknown."
    )
    result = _empty_payload(requested)
    try:
        _inspect_payload(record, path, requested, result)
        record["source_size"] = result["size"]
        record["source_sha256"] = result["sha256"]
        if result["status"] in ("symlink_skipped", "special_file_skipped"):
            record["status"] = "skipped"
    except (OSError, EvidenceError) as exc:
        _payload_failure(record, result, exc, requested)
    record["payload"] = result
    return record


def _display_time(value: str | None, zone: ZoneInfo | timezone) -> str | None:
    if value is None:
        return None
    # Python 3.10 accepts at most six fractional digits. datetime is used only
    # for the timezone offset; retain all seven source digits separately.
    parsed = datetime.fromisoformat(value[:26] + "+00:00")
    local = parsed.astimezone(zone).isoformat(timespec="seconds")
    return local[:19] + "." + value[20:27] + local[19:]


def _scan(
    input_path: Path, options: ScanOptions | None = None, filters: FilterOptions | None = None
) -> dict:
    """Return a JSON-serializable report; structural input errors raise.

    Every discovered candidate produces its own result. A corrupt record cannot
    abort the rest of a case. Warnings never fabricate missing metadata.
    """
    options = options or ScanOptions()
    filters = filters or FilterOptions()
    _check_cancel()
    validate_filters(filters)
    source = absolute_path(input_path)
    ensure_no_symlinks(source)
    info = source.stat()
    _check_cancel()
    if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
        raise EvidenceError("invalid_input", "Input must be a regular file or directory.")
    zone = timezone.utc if options.timezone == "UTC" else ZoneInfo(options.timezone)
    started = datetime.now(timezone.utc).isoformat()
    records: list[dict] = []
    discovery: list[dict] = []
    orphan_candidates: list[Path] = []
    metadata_names: dict[Path, set[str]] = {}
    indexes: dict[Path, dict[str, list[Path]]] = {}
    _progress("discovering", source)
    candidates = (
        _discover(source, options.recursive, discovery, orphan_candidates, metadata_names, indexes)
        if stat.S_ISDIR(info.st_mode)
        else [source]
    )
    state = _ACTIVE_SCAN.get()
    discovery_jobs: list[dict] | None = None
    if state is not None:
        # Establish a truthful denominator before item processing. Keep the
        # existing streaming path for clients that do not request progress.
        candidates = list(candidates)
        _check_cancel()
        discovery_jobs = _discovery_metadata_jobs(discovery, metadata_names)
        state.total = len(candidates) + len(orphan_candidates) + len(discovery_jobs)
        _progress("processing", source)
    for path in candidates:
        _check_cancel()
        _progress("processing", path)
        record = _new_record(path)
        try:
            data, digest = _read_metadata(path)
            record.update(source_size=len(data), source_sha256=digest)
            metadata = parse_metadata(data)
            _check_cancel()
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
                _check_cancel()
                _issue(record, code)
            record["payload"] = _payload(record, path, options.hash_payload, indexes)
        except (OSError, EvidenceError, ParseError) as exc:
            _issue(record, getattr(exc, "code", "source_unreadable"), str(exc), "error")
            record["payload"] = _payload(record, path, options.hash_payload, indexes)
        records.append(record)
        if state is not None:
            state.processed += 1
    groups: dict[tuple[Path, str], list[dict]] = {}
    for record in records:
        _check_cancel()
        path = Path(record["source_path"])
        groups.setdefault((path.parent, path.name.translate(ASCII_CASE)), []).append(record)
    for group in groups.values():
        _check_cancel()
        if len(group) > 1:
            for record in group:
                _check_cancel()
                _issue(
                    record,
                    "metadata_name_collision",
                    "Multiple $I names differ only by ASCII case; review association.",
                )
    for path in orphan_candidates:
        _check_cancel()
        _progress("processing", path)
        records.append(_orphan_payload(path, options.hash_payload))
        if state is not None:
            state.processed += 1
    if discovery_jobs is None:
        discovery_jobs = _discovery_metadata_jobs(discovery, metadata_names)
    for record in discovery_jobs:
        _check_cancel()
        path = Path(record["source_path"])
        _progress("processing", path)
        # Never read the redirected/unreadable $I itself. Its name is enough
        # to inspect a safe sibling without inventing original path or time.
        record["payload"] = _payload(record, path, options.hash_payload, indexes)
        if state is not None:
            state.processed += 1
    records.extend(discovery)
    _check_cancel()
    records.sort(key=lambda item: item["source_path"])
    report = {
        "schema_version": "2.0",
        "tool": {"name": "rbinforensics", "version": __version__},
        "started_at_utc": started,
        "completed_at_utc": datetime.now(timezone.utc).isoformat(),
        "input": str(source),
        # Work limits are operation controls, not forensic evidence fields.
        # Preserve the strict schema-2 report contract and its five options.
        "options": {
            "recursive": options.recursive,
            "hash_payload": options.hash_payload,
            "timezone": options.timezone,
            "case_id": options.case_id,
            "examiner": options.examiner,
        },
        "summary": {
            "candidates": sum(r["record_type"] == "metadata" for r in records),
            "parsed": sum(r["metadata"] is not None for r in records),
            "errors": sum(r["status"] == "error" for r in records),
            "warnings": sum(any(i["severity"] == "warning" for i in r["issues"]) for r in records),
            "skipped": sum(r["status"] == "skipped" for r in records),
            "payloads_hashed": sum(bool(r["payload"] and r["payload"]["sha256"]) for r in records),
            "orphan_payloads": sum(r["record_type"] == "orphan_payload" for r in records),
        },
        "records": records,
    }
    _check_cancel()
    report = apply_filters(report, filters)
    _check_cancel()
    report["timeline"] = build_timeline(selected_records(report))
    _check_cancel()
    _progress("complete", source)
    return report


def scan(
    input_path: Path,
    options: ScanOptions | None = None,
    filters: FilterOptions | None = None,
    *,
    control: ScanControl | None = None,
) -> dict:
    """Analyze evidence, optionally reporting progress and honouring cancel.

    Progress callbacks execute on the caller's scanning thread. Discovery has
    no total; controlled scans establish an item total before processing. Only
    the final ``complete`` phase means the entire report is ready. Cancellation
    raises ``ScanCancelled``; exhausted workload limits raise
    ``WorkLimitExceeded``. Neither returns a partial completed report.
    """
    options = options or ScanOptions()
    state = _ProgressState(control) if control is not None else None
    token = _ACTIVE_SCAN.set(state)
    try:
        # Public calls always own a fresh budget; nested callbacks and other
        # threads must neither spend nor replace an outer scan's allowances.
        with operation_budget(options.limits, operation="scan", control=control):
            return _scan(input_path, options, filters)
    finally:
        _ACTIVE_SCAN.reset(token)
