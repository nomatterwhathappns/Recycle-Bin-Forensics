"""Faithful JSON, spreadsheet-safe CSV, and terminal-safe human summaries."""

from __future__ import annotations

import csv
import io
import json
import unicodedata
from collections.abc import Iterator

from .limits import WorkLimits, check_budget, operation_budget


def safe_text(value: object) -> str:
    text = str(value)
    parts = []
    for offset in range(0, len(text), 4096):
        check_budget()
        parts.append(
            "".join(
                f"\\u{ord(char):04x}" if unicodedata.category(char).startswith("C") else char
                for char in text[offset : offset + 4096]
            )
        )
    return "".join(parts)


def _csv_text(value: object) -> object:
    if not isinstance(value, str):
        return value
    # Spreadsheet applications can execute formulas even in quoted CSV cells.
    # JSON is the authoritative, unmodified machine-readable representation.
    value = safe_text(value)
    if value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


CSV_FIELDS = (
    "source_path",
    "source_sha256",
    "source_size",
    "sid",
    "status",
    "format_version",
    "original_path",
    "original_size",
    "deletion_filetime",
    "deleted_at_utc",
    "deleted_at_display",
    "payload_status",
    "payload_path",
    "payload_size",
    "payload_sha256",
    "payload_hash_status",
    "issues",
    "record_type",
)


def _selected_records(report: dict) -> Iterator[dict]:
    records = report["records"]
    selection = report.get("selection") or {}
    for index in selection.get("record_indexes", range(len(records))):
        check_budget()
        yield records[index]


def _issue_codes(record: dict) -> Iterator[str]:
    for issue in record["issues"]:
        check_budget()
        yield issue["code"]


def _iter_csv(report: dict) -> Iterator[str]:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=CSV_FIELDS)
    writer.writeheader()
    yield output.getvalue()
    for record in _selected_records(report):
        output.seek(0)
        output.truncate()
        metadata = record["metadata"] or {}
        payload = record["payload"] or {}
        row = {
            key: record.get(key)
            for key in ("source_path", "source_sha256", "source_size", "sid", "status")
        }
        row.update({key: metadata.get(key) for key in CSV_FIELDS[5:11]})
        row.update(
            {"payload_" + key: payload.get(key) for key in ("status", "path", "size", "sha256")}
        )
        row["payload_hash_status"] = payload.get("hash_status")
        row["issues"] = ";".join(_issue_codes(record))
        row["record_type"] = record["record_type"]
        writer.writerow({key: _csv_text(value) for key, value in row.items()})
        yield output.getvalue()


def _iter_table(report: dict) -> Iterator[str]:
    yield f"Recycle Bin Forensics {report['tool']['version']}\n"
    yield f"Input: {safe_text(report['input'])}\n"
    for record in _selected_records(report):
        yield f"\n[{record['status'].upper()}] {safe_text(record['source_path'])}\n"
        yield f"  Record type   : {record['record_type']}\n"
        if record["metadata"]:
            metadata = record["metadata"]
            yield f"  Original path : {safe_text(metadata['original_path'])}\n"
            yield f"  Original size : {metadata['original_size']} bytes\n"
            yield f"  Deleted (UTC) : {metadata['deleted_at_utc'] or 'unknown'}\n"
            yield f"  Display time  : {metadata['deleted_at_display'] or 'unknown'} ({safe_text(report['options']['timezone'])})\n"
            yield f"  Format        : v{metadata['format_version']}\n"
            yield f"  Payload       : {record['payload']['status']}\n"
            if record["payload"]["sha256"]:
                yield f"  Payload SHA256: {record['payload']['sha256']}\n"
        if record["source_sha256"]:
            yield f"  Source SHA256 : {record['source_sha256']}\n"
        if record["metadata"] is None and record["payload"]:
            yield f"  Payload       : {record['payload']['status']}\n"
            if record["payload"]["sha256"]:
                yield f"  Payload SHA256: {record['payload']['sha256']}\n"
        for issue in record["issues"]:
            check_budget()
            yield f"  {issue['severity'].upper()} [{safe_text(issue['code'])}]: {safe_text(issue['message'])}\n"
    summary = report["summary"]
    yield "\nSummary: " + ", ".join(f"{k}={v}" for k, v in summary.items()) + "\n"
    selection = report.get("selection")
    if selection:
        yield f"Selection: {selection['matched']} shown, {selection['excluded']} excluded; summary covers full scan.\n"
    timeline = report.get("timeline")
    if timeline:
        yield f"Timeline: {len(timeline['events'])} dated records, {timeline['undated_records']} undated.\n"
    if not summary["candidates"] and not summary.get("orphan_payloads"):
        yield "No $I metadata candidates or orphan $R items found. Use --recursive for nested SID directories.\n"


def iter_render(
    report: dict, format_name: str, *, limits: WorkLimits | None = None
) -> Iterator[str]:
    """Yield checked output chunks, charging their exact UTF-8 size once.

    A failed iterator is incomplete. File callers must remove their own partial
    output; interactive callers should use :func:`render` before displaying it.
    """
    with operation_budget(limits, operation="render", reuse=True) as budget:
        budget.check_record_count(len(report["records"]))
        if format_name == "json":
            chunks = json.JSONEncoder(ensure_ascii=True, indent=2, allow_nan=False).iterencode(
                report
            )
        elif format_name == "csv":
            chunks = _iter_csv(report)
        elif format_name == "table":
            chunks = _iter_table(report)
        elif format_name == "html":
            from .html_report import _iter_html

            chunks = _iter_html(report)
        else:
            raise ValueError(f"Unknown report format: {format_name}")
        for chunk in chunks:
            budget.consume_export_bytes(len(chunk.encode("utf-8")))
            yield chunk
            budget.check()
        if format_name == "json":
            budget.consume_export_bytes(1)
            yield "\n"
        budget.check()


def render(report: dict, format_name: str, *, limits: WorkLimits | None = None) -> str:
    """Return a complete bounded rendering before a caller displays any text."""
    with operation_budget(limits, operation="render", reuse=True) as budget:
        text = "".join(iter_render(report, format_name, limits=limits))
        budget.check()
        return text


def render_csv(report: dict, *, limits: WorkLimits | None = None) -> str:
    return render(report, "csv", limits=limits)


def render_table(report: dict, *, limits: WorkLimits | None = None) -> str:
    return render(report, "table", limits=limits)
