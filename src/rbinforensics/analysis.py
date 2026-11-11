"""Pure selection and timeline analysis over observed Recycle Bin records.

Selections never discard scan evidence or diagnostics from JSON. Date filters
use integer FILETIME ticks so the seventh fractional digit is not rounded away.
"""

from __future__ import annotations

import copy
import ntpath
import re
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime

_EPOCH = datetime(1601, 1, 1)
_TICKS_PER_SECOND = 10_000_000
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}\Z")
_INSTANT = re.compile(
    r"(?P<date>\d{4}-\d{2}-\d{2})[Tt ]"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?:\.(?P<fraction>\d{1,7}))?"
    r"(?P<offset>Z|z|[+-]\d{2}:\d{2})\Z"
)


@dataclass(frozen=True)
class FilterOptions:
    """AND-combined filters; all bounds are inclusive.

    A bare date means midnight UTC, including for ``deleted_before``. Use an
    explicit end-of-day timestamp when a complete ending day is intended.
    """

    query: str | None = None
    extensions: tuple[str, ...] = ()
    sid: str | None = None
    deleted_after: str | None = None
    deleted_before: str | None = None
    min_size: int | None = None
    max_size: int | None = None


def _instant_ticks(value: str) -> int:
    """Parse an explicit-zone ISO instant with up to seven decimal places."""
    if _DATE.fullmatch(value):
        try:
            moment = datetime.strptime(value, "%Y-%m-%d")
        except ValueError as exc:
            raise ValueError(f"Invalid calendar date: {value!r}.") from exc
        offset_seconds = 0
        fraction = 0
    else:
        match = _INSTANT.fullmatch(value)
        if match is None:
            raise ValueError(
                "Deletion bounds require YYYY-MM-DD or an ISO datetime with an explicit "
                "Z/±HH:MM offset and at most seven fractional digits."
            )
        try:
            calendar = datetime.strptime(match["date"], "%Y-%m-%d")
            moment = calendar.replace(
                hour=int(match["hour"]),
                minute=int(match["minute"]),
                second=int(match["second"]),
            )
        except ValueError as exc:
            raise ValueError(f"Invalid calendar datetime: {value!r}.") from exc
        fraction = int((match["fraction"] or "").ljust(7, "0"))
        offset = match["offset"]
        offset_seconds = 0
        if offset.upper() != "Z":
            hours, minutes = int(offset[1:3]), int(offset[4:6])
            if hours > 23 or minutes > 59:
                raise ValueError(f"Invalid UTC offset: {offset!r}.")
            offset_seconds = (hours * 60 + minutes) * 60
            if offset[0] == "-":
                offset_seconds = -offset_seconds
    delta = moment - _EPOCH
    seconds = delta.days * 86_400 + delta.seconds - offset_seconds
    return seconds * _TICKS_PER_SECOND + fraction


def _normalized(filters: FilterOptions) -> dict:
    values = asdict(filters)
    normalized = []
    for extension in filters.extensions:
        text = extension.strip().casefold()
        if not text.startswith("."):
            text = "." + text
        if text in (".", "..") or any(char in text for char in "/\\*?\x00"):
            raise ValueError(f"Invalid extension filter: {extension!r}.")
        if text not in normalized:
            normalized.append(text)
    values["extensions"] = normalized
    if values["query"] == "":
        values["query"] = None
    if values["sid"] is not None:
        values["sid"] = values["sid"].strip() or None
    return values


def validate_filters(filters: FilterOptions) -> None:
    """Reject impossible bounds and malformed extension/date options."""
    _normalized(filters)
    for field in ("min_size", "max_size"):
        value = getattr(filters, field)
        if value is not None and (
            isinstance(value, bool) or not isinstance(value, int) or value < 0
        ):
            raise ValueError(f"{field} must be a nonnegative integer number of bytes.")
    if filters.min_size is not None and filters.max_size is not None:
        if filters.min_size > filters.max_size:
            raise ValueError("min_size must not exceed max_size.")
    after = _instant_ticks(filters.deleted_after) if filters.deleted_after is not None else None
    before = _instant_ticks(filters.deleted_before) if filters.deleted_before is not None else None
    if after is not None and before is not None and after > before:
        raise ValueError("deleted_after must not exceed deleted_before.")


def _matches(record: dict, values: dict, after: int | None, before: int | None) -> bool:
    # Filtering is a view, never a way to hide incomplete scan scope.
    if record["record_type"] == "discovery" or record.get("status") in ("error", "skipped"):
        return True
    metadata = record.get("metadata") or {}
    if values["query"] is not None:
        needle = values["query"].casefold()
        fields = (metadata.get("original_path", ""), record["source_path"], record["source_name"])
        if not any(needle in field.casefold() for field in fields):
            return False
    if values["extensions"]:
        original = metadata.get("original_path")
        if original is None and record["record_type"] != "orphan_payload":
            return False
        name = original if original is not None else record["source_name"]
        if not any(ntpath.basename(name).casefold().endswith(ext) for ext in values["extensions"]):
            return False
    if values["sid"] is not None:
        if (record.get("sid") or "").casefold() != values["sid"].casefold():
            return False
    if after is not None or before is not None:
        # A missing/unrepresentable deletion time is not a dated observation.
        if not metadata.get("deleted_at_utc"):
            return False
        ticks = metadata["deletion_filetime"]
        if (after is not None and ticks < after) or (before is not None and ticks > before):
            return False
    if values["min_size"] is not None or values["max_size"] is not None:
        if not metadata:
            return False
        size = metadata["original_size"]
        if values["min_size"] is not None and size < values["min_size"]:
            return False
        if values["max_size"] is not None and size > values["max_size"]:
            return False
    return True


def apply_filters(report: dict, filters: FilterOptions) -> dict:
    """Return a deep-copied report with an explicit selection over all records."""
    validate_filters(filters)
    values = _normalized(filters)
    after = _instant_ticks(filters.deleted_after) if filters.deleted_after is not None else None
    before = _instant_ticks(filters.deleted_before) if filters.deleted_before is not None else None
    indexes = [
        index
        for index, record in enumerate(report["records"])
        if _matches(record, values, after, before)
    ]
    result = copy.deepcopy(report)
    result["selection"] = {
        "filters": values,
        "active": any(value is not None and value != [] for value in values.values()),
        "matched": len(indexes),
        "excluded": len(report["records"]) - len(indexes),
        "record_indexes": indexes,
    }
    return result


def selected_records(report: dict) -> list[dict]:
    """Return the records in a report's selection, or all records without one."""
    if "selection" not in report:
        return report["records"]
    return [report["records"][index] for index in report["selection"]["record_indexes"]]


def build_timeline(records: list[dict]) -> dict:
    """Build an ascending deletion timeline from dated metadata observations.

    Undated, failed, orphan and discovery records are counted separately; no
    filesystem modification/creation timestamp substitutes for deletion time.
    Aggregates describe only the dated events included in this timeline.
    """
    events = []
    extensions: Counter[str] = Counter()
    for record in records:
        metadata = record.get("metadata")
        if not metadata or not metadata.get("deleted_at_utc"):
            continue
        try:
            _instant_ticks(metadata["deleted_at_utc"])
        except (TypeError, ValueError):
            continue
        payload = record.get("payload") or {}
        events.append(
            {
                "source_path": record["source_path"],
                "sid": record.get("sid"),
                "original_path": metadata["original_path"],
                "original_size": metadata["original_size"],
                "deletion_filetime": metadata["deletion_filetime"],
                "deleted_at_utc": metadata["deleted_at_utc"],
                "deleted_at_display": metadata.get("deleted_at_display"),
                "payload_status": payload.get("status"),
            }
        )
        extensions[ntpath.splitext(metadata["original_path"])[1].casefold()] += 1
    events.sort(key=lambda event: (event["deletion_filetime"], event["source_path"]))
    days = Counter(event["deleted_at_utc"][:10] for event in events)
    sids = Counter(event["sid"] for event in events)
    return {
        "order": "deletion_time_ascending",
        "events": events,
        "undated_records": len(records) - len(events),
        "daily_counts": [
            {"date_utc": date, "count": count} for date, count in sorted(days.items())
        ],
        "by_sid": [
            {"sid": sid, "count": count}
            for sid, count in sorted(sids.items(), key=lambda item: item[0] or "")
        ],
        "by_extension": [
            {"extension": extension, "count": count}
            for extension, count in sorted(extensions.items())
        ],
    }
