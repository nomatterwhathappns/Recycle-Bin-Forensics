"""Faithful JSON, spreadsheet-safe CSV, and terminal-safe human summaries."""

from __future__ import annotations

import csv
import io
import json
import unicodedata


def safe_text(value: object) -> str:
    text = str(value)
    return "".join(
        f"\\u{ord(char):04x}" if unicodedata.category(char).startswith("C") else char
        for char in text
    )


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
)


def render_csv(report: dict) -> str:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=CSV_FIELDS)
    writer.writeheader()
    for record in report["records"]:
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
        row["issues"] = ";".join(issue["code"] for issue in record["issues"])
        writer.writerow({key: _csv_text(value) for key, value in row.items()})
    return output.getvalue()


def render_table(report: dict) -> str:
    lines = [
        f"Recycle Bin Forensics {report['tool']['version']}",
        f"Input: {safe_text(report['input'])}",
    ]
    for record in report["records"]:
        lines.extend(("", f"[{record['status'].upper()}] {safe_text(record['source_path'])}"))
        if record["metadata"]:
            metadata = record["metadata"]
            lines.extend(
                (
                    f"  Original path : {safe_text(metadata['original_path'])}",
                    f"  Original size : {metadata['original_size']} bytes",
                    f"  Deleted (UTC) : {metadata['deleted_at_utc'] or 'unknown'}",
                    f"  Display time  : {metadata['deleted_at_display'] or 'unknown'} ({safe_text(report['options']['timezone'])})",
                    f"  Format        : v{metadata['format_version']}",
                    f"  Payload       : {record['payload']['status']}",
                )
            )
            if record["payload"]["sha256"]:
                lines.append(f"  Payload SHA256: {record['payload']['sha256']}")
        if record["source_sha256"]:
            lines.append(f"  Source SHA256 : {record['source_sha256']}")
        for issue in record["issues"]:
            lines.append(
                f"  {issue['severity'].upper()} [{safe_text(issue['code'])}]: {safe_text(issue['message'])}"
            )
    summary = report["summary"]
    lines.extend(("", "Summary: " + ", ".join(f"{k}={v}" for k, v in summary.items())))
    if not summary["candidates"]:
        lines.append("No $I metadata candidates found. Use --recursive for nested SID directories.")
    return "\n".join(lines) + "\n"


def render(report: dict, format_name: str) -> str:
    if format_name == "json":
        return json.dumps(report, ensure_ascii=True, indent=2, allow_nan=False) + "\n"
    if format_name == "csv":
        return render_csv(report)
    if format_name == "table":
        return render_table(report)
    raise ValueError(f"Unknown report format: {format_name}")
