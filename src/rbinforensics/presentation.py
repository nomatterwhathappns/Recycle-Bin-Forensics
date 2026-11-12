"""Pure desktop presentation helpers over observed, immutable scan records.

Sorting operates over the whole selected dataset before a page is displayed.
Recorded uint64 values remain integers; formatted text and floating point are
never used to order sizes or deletion instants. Equal keys retain the input
order, which is deterministic for scanner-produced datasets.
"""

from __future__ import annotations

from collections.abc import Callable

_PAYLOAD_LABELS = {
    "available_file": "File tersedia",
    "available_directory": "Folder tersedia",
    "missing": "Tidak ditemukan",
    "not_checked": "Belum diperiksa",
    "ambiguous": "Pasangan ambigu",
    "symlink_skipped": "Dilewati: symlink/junction",
    "special_file_skipped": "Dilewati: file khusus",
    "unreadable": "Gagal diperiksa",
}


def record_label(record: dict) -> str:
    """Return a concise row label without obscuring errors or skipped data."""
    status = record.get("status")
    if status == "error":
        return "Error"
    if status == "skipped":
        return "Dilewati"
    if record.get("record_type") == "orphan_payload":
        return "Orphan"
    if (record.get("payload") or {}).get("status") == "missing":
        return "Payload hilang"
    if status == "warning":
        return "Perlu ditinjau"
    return "OK" if status == "ok" else "Tidak diketahui"


def display_statuses(record: dict) -> tuple[str, str]:
    """Separate metadata decoding from the independent payload observation.

    A parsed metadata object stays decoded even if optional payload hashing
    later fails. An orphan's absent metadata is not a metadata parsing error.
    """
    if record.get("metadata") is not None:
        metadata_status = "Berhasil dibaca"
    elif record.get("record_type") == "orphan_payload":
        metadata_status = "Tidak ditemukan"
    elif record.get("status") == "skipped":
        metadata_status = "Dilewati"
    elif record.get("record_type") == "metadata" and record.get("status") == "error":
        metadata_status = "Gagal dibaca"
    else:
        metadata_status = "Tidak tersedia"
    payload = record.get("payload")
    payload_status = (
        _PAYLOAD_LABELS.get(payload.get("status"), "Tidak diketahui")
        if payload is not None
        else "Belum diperiksa"
    )
    return metadata_status, payload_status


def _path_key(record: dict) -> str | None:
    metadata = record.get("metadata") or {}
    path = metadata.get("original_path") or record.get("source_name")
    return path.casefold() if isinstance(path, str) and path else None


def _nonnegative_integer(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


def _time_key(record: dict) -> int | None:
    metadata = record.get("metadata")
    if metadata is None or not metadata.get("deleted_at_utc"):
        return None
    return _nonnegative_integer(metadata.get("deletion_filetime"))


def _size_key(record: dict) -> int | None:
    metadata = record.get("metadata")
    if metadata is not None:
        return _nonnegative_integer(metadata.get("original_size"))
    return _nonnegative_integer((record.get("payload") or {}).get("size"))


def sort_records(records: list[dict], column: str, descending: bool = False) -> list[dict]:
    """Return a sorted view, with unknown values last in either direction.

    Only references are reordered: neither the records nor the input list are
    modified. The GUI can keep the full audit report and timeline independent
    from this display order. Equal and unknown keys retain their input order.
    """
    key_functions: dict[str, Callable[[dict], str | int | None]] = {
        "path": _path_key,
        "time": _time_key,
        "size": _size_key,
        "status": record_label,
    }
    try:
        key = key_functions[column]
    except KeyError as exc:
        raise ValueError(f"Unsupported sort column: {column!r}.") from exc
    known: list[tuple[str | int, dict]] = []
    unknown = []
    for record in records:
        value = key(record)
        if value is None:
            unknown.append(record)
        else:
            known.append((value, record))
    known.sort(key=lambda item: item[0], reverse=descending)
    return [record for _, record in known] + unknown
