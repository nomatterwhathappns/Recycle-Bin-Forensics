"""Bounded export manifests and independent checks of an explicit report file.

Checksums establish whether report bytes match this sidecar. They do not prove
who produced the report or authenticate the supplied evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .limits import WorkLimits, check_budget, operation_budget
from .scanner import EvidenceError, _open_regular, absolute_path

MAX_MANIFEST_BYTES = 1024**2
MANIFEST_SCHEMA_VERSION = "1.0"
_FORMATS = frozenset(("json", "csv", "table", "html"))
_REQUIRED = frozenset(
    (
        "manifest_schema_version",
        "tool",
        "created_at_utc",
        "report",
        "forensic_schema_version",
        "inventory",
        "case",
        "scan",
        "selection",
        "runtime_limits",
    )
)


class ManifestError(ValueError):
    """An export manifest is unsafe, malformed, incomplete, or does not match."""


def manifest_path(report_path: Path) -> Path:
    """Derive the sibling path without trusting any content in the manifest."""
    path = Path(report_path)
    return path.with_name(path.name + ".manifest.json")


def build_manifest(
    report: dict,
    report_path: Path,
    format_name: str,
    size_bytes: int,
    sha256: str,
    *,
    limits: WorkLimits,
    context: dict | None = None,
) -> dict:
    options = report["options"]
    selection = report.get("selection") or {}
    inventory_count = len(report["records"])
    selected_count = len(selection.get("record_indexes", range(inventory_count)))
    result = {
        "manifest_schema_version": MANIFEST_SCHEMA_VERSION,
        "tool": {"name": "rbinforensics", "version": __version__},
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "report": {
            "filename": report_path.name,
            "format": format_name,
            "size_bytes": size_bytes,
            "sha256": sha256,
        },
        "forensic_schema_version": report["schema_version"],
        "inventory": {"total_records": inventory_count, "selected_records": selected_count},
        "case": {"case_id": options.get("case_id"), "examiner": options.get("examiner")},
        "scan": {
            "input": report["input"],
            "started_at_utc": report.get("started_at_utc"),
            "completed_at_utc": report.get("completed_at_utc"),
            "options": options,
        },
        "selection": {
            "active": selection.get("active", False),
            "filters": selection.get("filters") or {},
            "timezone": options.get("timezone", "UTC"),
        },
        "runtime_limits": limits.to_dict(),
    }
    if context is not None:
        if not isinstance(context, dict):
            raise ManifestError("Manifest context must be a JSON object.")
        result["context"] = context
    if report.get("report_kind") == "redacted-sharing":
        result["report_kind"] = "redacted-sharing"
    validate_manifest(result, report_path)
    return result


def iter_manifest(manifest: dict) -> Iterator[str]:
    """Bound the sidecar independently; report output bytes are already charged."""
    size = 0
    try:
        _check_json_bounds(manifest)
        encoder = json.JSONEncoder(ensure_ascii=True, indent=2, allow_nan=False)
        for chunk in encoder.iterencode(manifest):
            check_budget()
            size += len(chunk.encode("utf-8"))
            if size > MAX_MANIFEST_BYTES:
                raise ManifestError("Manifest exceeds the 1 MiB safety limit.")
            yield chunk
        if size + 1 > MAX_MANIFEST_BYTES:
            raise ManifestError("Manifest exceeds the 1 MiB safety limit.")
        check_budget()
        yield "\n"
    except (TypeError, RecursionError, ValueError) as exc:
        if isinstance(exc, ManifestError):
            raise
        raise ManifestError(f"Manifest is not bounded JSON: {exc}") from exc


def _check_json_bounds(value: object) -> None:
    """Reject oversized source values before JSONEncoder allocates their escapes.

    This lower bound never rejects a manifest whose final JSON fits. The exact
    encoded-byte limit is still checked by the iterator before each write.
    """
    size = 0
    active: set[int] = set()

    def visit(item: object) -> None:
        nonlocal size
        check_budget()
        size += len(item) + 2 if isinstance(item, str) else 1
        if size > MAX_MANIFEST_BYTES:
            raise ManifestError("Manifest exceeds the 1 MiB safety limit.")
        if isinstance(item, (dict, list, tuple)):
            identity = id(item)
            if identity in active:
                raise ManifestError("Manifest contains a circular JSON value.")
            active.add(identity)
            if isinstance(item, dict):
                for key, child in item.items():
                    if not isinstance(key, str):
                        raise ManifestError("Manifest JSON object keys must be strings.")
                    visit(key)
                    visit(child)
            else:
                for child in item:
                    visit(child)
            active.remove(identity)

    visit(value)


def _object(value: object, keys: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        raise ManifestError(f"Invalid manifest {label} fields.")
    return value


def _string(value: object, label: str, *, nullable: bool = False) -> None:
    if nullable and value is None:
        return
    if not isinstance(value, str) or not value:
        raise ManifestError(f"Invalid manifest {label}.")


def _utc(value: object, label: str, *, nullable: bool = False) -> None:
    if nullable and value is None:
        return
    _string(value, label)
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if moment.utcoffset() is None or moment.utcoffset().total_seconds() != 0:
            raise ValueError("UTC required")
    except (ValueError, OverflowError) as exc:
        raise ManifestError(f"Invalid manifest {label}; expected a UTC timestamp.") from exc


def validate_manifest(manifest: object, report_path: Path) -> dict:
    """Validate version 1 before a verifier opens the explicitly supplied report."""
    if not isinstance(manifest, dict) or not _REQUIRED <= set(manifest) <= _REQUIRED | {
        "context",
        "report_kind",
    }:
        raise ManifestError("Invalid manifest fields.")
    if manifest["manifest_schema_version"] != MANIFEST_SCHEMA_VERSION:
        raise ManifestError("Unsupported manifest schema version.")
    tool = _object(manifest["tool"], {"name", "version"}, "tool")
    if tool["name"] != "rbinforensics":
        raise ManifestError("Invalid manifest tool name.")
    _string(tool["version"], "tool version")
    _utc(manifest["created_at_utc"], "creation time")
    exported = _object(manifest["report"], {"filename", "format", "size_bytes", "sha256"}, "report")
    name = exported["filename"]
    if (
        not isinstance(name, str)
        or name in ("", ".", "..")
        or any(character in name for character in ("/", "\\", "\0"))
        or name != report_path.name
    ):
        raise ManifestError("Manifest filename must match the explicitly supplied report basename.")
    if not isinstance(exported["format"], str) or exported["format"] not in _FORMATS:
        raise ManifestError("Invalid manifest report format.")
    if type(exported["size_bytes"]) is not int or exported["size_bytes"] < 0:
        raise ManifestError("Invalid manifest report byte size.")
    if (
        not isinstance(exported["sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", exported["sha256"]) is None
    ):
        raise ManifestError("Invalid manifest SHA-256 digest.")
    _string(manifest["forensic_schema_version"], "forensic schema version")
    if "report_kind" in manifest:
        if (
            manifest["report_kind"] != "redacted-sharing"
            or manifest["forensic_schema_version"] != "sharing-1.0"
        ):
            raise ManifestError("Invalid manifest sharing report kind or schema.")
    elif manifest["forensic_schema_version"] == "sharing-1.0":
        raise ManifestError("Sharing manifests must identify their redacted report kind.")
    inventory = _object(manifest["inventory"], {"total_records", "selected_records"}, "inventory")
    if any(type(value) is not int or value < 0 for value in inventory.values()):
        raise ManifestError("Invalid manifest inventory counts.")
    if inventory["selected_records"] > inventory["total_records"]:
        raise ManifestError("Manifest selected count exceeds its inventory count.")
    case = _object(manifest["case"], {"case_id", "examiner"}, "case")
    for key, value in case.items():
        if value is not None and not isinstance(value, str):
            raise ManifestError(f"Invalid manifest {key}.")
    scan = _object(
        manifest["scan"], {"input", "started_at_utc", "completed_at_utc", "options"}, "scan"
    )
    _string(scan["input"], "scan input")
    _utc(scan["started_at_utc"], "scan start", nullable=True)
    _utc(scan["completed_at_utc"], "scan completion", nullable=True)
    if not isinstance(scan["options"], dict):
        raise ManifestError("Invalid manifest scan options.")
    selection = _object(manifest["selection"], {"active", "filters", "timezone"}, "selection")
    if type(selection["active"]) is not bool or not isinstance(selection["filters"], dict):
        raise ManifestError("Invalid manifest selection.")
    _string(selection["timezone"], "timezone")
    if not isinstance(manifest["runtime_limits"], dict) or set(manifest["runtime_limits"]) != set(
        WorkLimits().to_dict()
    ):
        raise ManifestError("Invalid manifest runtime limits.")
    try:
        WorkLimits(**manifest["runtime_limits"])
    except (TypeError, ValueError) as exc:
        raise ManifestError("Invalid manifest runtime limits.") from exc
    if "context" in manifest and not isinstance(manifest["context"], dict):
        raise ManifestError("Invalid manifest context.")
    return manifest


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ManifestError(f"Duplicate manifest JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ManifestError(f"Invalid manifest JSON constant: {value}")


def verify_export(report_path: Path, *, limits: WorkLimits | None = None) -> dict:
    """Check one explicit report against its bounded, safe sibling manifest."""
    path = absolute_path(report_path)
    sidecar = manifest_path(path)
    try:
        with operation_budget(limits, operation="verify export", reuse=True) as budget:
            with _open_regular(sidecar) as (stream, info):
                if info.st_size > MAX_MANIFEST_BYTES:
                    raise ManifestError("Manifest exceeds the 1 MiB safety limit.")
                data = stream.read(MAX_MANIFEST_BYTES + 1)
                budget.check()
                if len(data) > MAX_MANIFEST_BYTES:
                    raise ManifestError("Manifest exceeds the 1 MiB safety limit.")
                if len(data) != info.st_size:
                    raise ManifestError("Manifest changed while reading it.")
            try:
                manifest = json.loads(
                    data.decode("utf-8"),
                    object_pairs_hook=_unique_object,
                    parse_constant=_reject_constant,
                )
            except ValueError as exc:
                raise ManifestError(f"Invalid manifest JSON: {exc}") from exc
            validate_manifest(manifest, path)
            budget.check()
            digest = hashlib.sha256()
            size = 0
            with _open_regular(path) as (stream, info):
                if info.st_size != manifest["report"]["size_bytes"]:
                    raise ManifestError("Report byte size does not match the manifest.")
                while True:
                    budget.check()
                    chunk = stream.read(1024**2)
                    budget.check()
                    if not chunk:
                        break
                    size += len(chunk)
                    digest.update(chunk)
            if size != manifest["report"]["size_bytes"]:
                raise ManifestError("Report byte size does not match the manifest.")
            if digest.hexdigest() != manifest["report"]["sha256"]:
                raise ManifestError("Report SHA-256 digest does not match the manifest.")
            budget.check()
        return manifest
    except (OSError, EvidenceError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ManifestError(f"Cannot verify export: {exc}") from exc
