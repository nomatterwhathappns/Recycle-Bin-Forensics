"""Construct explicitly labelled sharing derivatives without changing evidence.

Only known report fields are copied. Aliases exist for one call and their
mapping is never included in the derivative. Exact times, sizes, and counts
remain useful for explanation but can still make a case recognizable; this is
redaction, not a guarantee of anonymity.
"""

from __future__ import annotations

from .limits import check_budget, operation_budget

SHARING_SCHEMA_VERSION = "sharing-1.0"
SHARING_REPORT_KIND = "redacted-sharing"
_WITHHELD = "[withheld]"
_SUMMARY_FIELDS = (
    "candidates",
    "parsed",
    "errors",
    "warnings",
    "skipped",
    "payloads_hashed",
    "orphan_payloads",
)
_METADATA_FIELDS = (
    "format_version",
    "original_size",
    "deletion_filetime",
    "deleted_at_utc",
    "deleted_at_display",
)
_EVENT_FIELDS = (
    "original_size",
    "deletion_filetime",
    "deleted_at_utc",
    "deleted_at_display",
    "payload_status",
)


def _fields(source: dict, names: tuple[str, ...]) -> dict:
    """Copy expected immutable facts, never an arbitrary nested object."""
    result = {}
    for name in names:
        check_budget()
        value = source.get(name)
        if value is not None and type(value) not in (str, bool, int, float):
            raise ValueError(f"Expected a scalar report field: {name}.")
        result[name] = value
    return result


class _Aliases:
    def __init__(self, prefix: str) -> None:
        self.prefix = prefix
        self.values: dict[str, str] = {}

    def __call__(self, value: str | None) -> str | None:
        check_budget()
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("Expected a string to redact.")
        if value not in self.values:
            self.values[value] = f"{self.prefix}{len(self.values) + 1:06d}"
        return self.values[value]


def redact_report(report: dict) -> dict:
    """Return an isolated, whitelisted sharing view of a complete schema-2 report.

    Preserve the supplied inventory, selection indexes, and derived timeline;
    filtering is not run again against aliases. Source/output safety checks must
    use the original report before this function removes its evidence paths.
    """
    if not isinstance(report, dict) or report.get("schema_version") != "2.0":
        raise ValueError("Redaction requires a complete forensic schema-2.0 report.")
    with operation_budget(operation="redaction", reuse=True) as budget:
        budget.check_record_count(len(report["records"]))
        paths = _Aliases("path-")
        sids = _Aliases("sid-")
        extensions = _Aliases(".extension-")
        options = report["options"]
        result = {
            "schema_version": SHARING_SCHEMA_VERSION,
            "report_kind": SHARING_REPORT_KIND,
            "derived_from_schema_version": "2.0",
            "redaction": {
                "policy_version": "1.0",
                "paths_names_sids_extensions": "per-export aliases",
                "case_examiner_search_text": "withheld",
                "diagnostic_text": "withheld",
                "evidence_hashes": "withheld",
                "retained": "counts, sizes, times, statuses, diagnostic codes",
                "notice": "Sharing derivative; retained facts can still identify a case.",
            },
            "tool": {
                "name": "rbinforensics",
                "version": _fields(report["tool"], ("version",))["version"],
            },
            **_fields(report, ("started_at_utc", "completed_at_utc")),
            "input": paths(report["input"]),
            "options": {
                **_fields(options, ("recursive", "hash_payload", "timezone")),
                "case_id": None,
                "examiner": None,
            },
            "summary": _fields(report["summary"], _SUMMARY_FIELDS),
            "records": [],
        }
        for record in report["records"]:
            budget.check()
            metadata = record.get("metadata")
            payload = record.get("payload")
            redacted = {
                **_fields(record, ("record_type", "source_size", "status")),
                "source_path": paths(record["source_path"]),
                "source_name": paths(record["source_name"]),
                "source_sha256": None,
                "sid": sids(record.get("sid")),
                "metadata": None,
                "payload": None,
                "issues": [],
            }
            if metadata is not None:
                redacted["metadata"] = {
                    **_fields(metadata, _METADATA_FIELDS),
                    "original_path": paths(metadata["original_path"]),
                }
            if payload is not None:
                redacted["payload"] = {
                    **_fields(payload, ("status", "size", "hash_status", "size_matches_metadata")),
                    "path": paths(payload.get("path")),
                    "sha256": None,
                }
            for issue in record["issues"]:
                budget.check()
                redacted["issues"].append(
                    {
                        **_fields(issue, ("code", "severity")),
                        "message": "Diagnostic text withheld.",
                    }
                )
            result["records"].append(redacted)
        selection = report.get("selection")
        if selection is not None:
            filters = selection["filters"]
            indexes = []
            for index in selection["record_indexes"]:
                budget.check()
                if type(index) is not int:
                    raise ValueError("Expected integer selection indexes.")
                indexes.append(index)
            result["selection"] = {
                **_fields(selection, ("active", "matched", "excluded")),
                "filters": {
                    **_fields(filters, ("deleted_after", "deleted_before", "min_size", "max_size")),
                    "query": _WITHHELD if filters.get("query") is not None else None,
                    "extensions": [".withheld"] if filters.get("extensions") else [],
                    "sid": _WITHHELD if filters.get("sid") is not None else None,
                },
                "record_indexes": indexes,
            }
        timeline = report.get("timeline")
        if timeline is not None:
            redacted_timeline = {
                "order": "deletion_time_ascending",
                **_fields(timeline, ("undated_records",)),
                "events": [],
                "daily_counts": [],
                "by_sid": [],
                "by_extension": [],
            }
            for event in timeline["events"]:
                budget.check()
                redacted_timeline["events"].append(
                    {
                        **_fields(event, _EVENT_FIELDS),
                        "source_path": paths(event["source_path"]),
                        "original_path": paths(event["original_path"]),
                        "sid": sids(event.get("sid")),
                    }
                )
            for day in timeline["daily_counts"]:
                budget.check()
                redacted_timeline["daily_counts"].append(_fields(day, ("date_utc", "count")))
            for item in timeline["by_sid"]:
                budget.check()
                redacted_timeline["by_sid"].append(
                    {"sid": sids(item.get("sid")), **_fields(item, ("count",))}
                )
            for item in timeline["by_extension"]:
                budget.check()
                extension = item["extension"]
                redacted_timeline["by_extension"].append(
                    {
                        "extension": extensions(extension) if extension else "",
                        **_fields(item, ("count",)),
                    }
                )
            result["timeline"] = redacted_timeline
        budget.check()
        return result
