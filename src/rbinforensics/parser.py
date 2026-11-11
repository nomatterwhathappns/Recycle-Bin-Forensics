"""Decode Windows Recycle Bin ``$I`` metadata without touching a filesystem.

All offsets are bytes, integers are unsigned little-endian, and path lengths
count UTF-16 code units (not Python characters). Only the two documented layouts
are accepted; unexpected bytes are reported rather than silently discarded.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import PureWindowsPath

HEADER_SIZE = 24  # 0x00: version QWORD; 0x08: size QWORD; 0x10: FILETIME QWORD.
V1_PATH_OFFSET = HEADER_SIZE
V1_PATH_UNITS = 260
V1_SIZE = V1_PATH_OFFSET + V1_PATH_UNITS * 2
V2_LENGTH_OFFSET = HEADER_SIZE  # DWORD, includes the terminal UTF-16 NUL.
V2_PATH_OFFSET = V2_LENGTH_OFFSET + 4
MAX_PATH_UNITS = 32_768
TICKS_PER_SECOND = 10_000_000
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


class ParseError(ValueError):
    """Invalid or unsupported metadata, with a stable machine-readable code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Metadata:
    """Decoded values; the raw integer FILETIME is retained without rounding."""

    format_version: int
    original_size: int
    deletion_filetime: int
    deleted_at_utc: str | None
    original_path: str
    warnings: tuple[str, ...]


def _filetime(ticks: int, warnings: list[str]) -> str | None:
    if ticks == 0:
        warnings.append("zero_deletion_time")
        return None
    # Integer arithmetic preserves all 100-nanosecond ticks. datetime itself
    # supports only microseconds; use it for whole seconds and format ticks
    # separately, avoiding float timestamps and local-time conversions.
    seconds, fraction = divmod(ticks, TICKS_PER_SECOND)
    try:
        value = FILETIME_EPOCH + timedelta(seconds=seconds)
    except OverflowError:
        warnings.append("deletion_time_out_of_range")
        return None
    return (
        f"{value.year:04d}-{value.month:02d}-{value.day:02d}"
        f"T{value.hour:02d}:{value.minute:02d}:{value.second:02d}"
        f".{fraction:07d}Z"
    )


def _decode_path(field: bytes, version: int, warnings: list[str]) -> str:
    if version == 1:
        # Find a NUL on a code-unit boundary, not via bytes.split(b"\0\0"):
        # ASCII UTF-16 has zero bytes between characters, which can overlap.
        end = next(
            (i for i in range(0, len(field), 2) if field[i : i + 2] == b"\0\0"),
            None,
        )
        if end is None:
            warnings.append("missing_path_terminator")
        else:
            if any(field[end + 2 :]):
                warnings.append("nonzero_path_padding")
            field = field[:end]
    elif field.endswith(b"\0\0"):
        field = field[:-2]
    else:
        warnings.append("missing_path_terminator")

    try:
        path = field.decode("utf-16-le", errors="strict")
    except UnicodeDecodeError as exc:
        raise ParseError("invalid_utf16", "Original path is not valid UTF-16LE.") from exc

    if not path:
        warnings.append("empty_original_path")
    if "\0" in path:
        warnings.append("embedded_nul_in_path")
    if any(ord(char) < 32 and char != "\0" for char in path):
        warnings.append("control_characters_in_path")
    # Use Windows lexical rules even when running on Unix. This value is evidence
    # text only: it must never be resolved or opened as a path on the examiner's OS.
    if path and not PureWindowsPath(path).is_absolute():
        warnings.append("non_absolute_windows_path")
    return path


def parse_metadata(data: bytes) -> Metadata:
    """Parse a complete version-1 or version-2 ``$I`` byte sequence.

    Structural failures raise :class:`ParseError`. Parseable anomalies remain in
    ``warnings`` so the caller can distinguish decoded values from clean records.
    No recovery or truncation of a malformed declared path is attempted.
    """
    if len(data) < HEADER_SIZE:
        raise ParseError(
            "truncated_header", f"Expected at least {HEADER_SIZE} header bytes; got {len(data)}."
        )
    version, size, ticks = struct.unpack_from("<QQQ", data, 0)
    warnings: list[str] = []
    if version == 1:
        expected = V1_SIZE
        if len(data) < expected:
            raise ParseError(
                "truncated_path", f"Version 1 requires {expected} bytes; got {len(data)}."
            )
        field = data[V1_PATH_OFFSET:expected]
    elif version == 2:
        if len(data) < V2_PATH_OFFSET:
            raise ParseError("truncated_header", "Version 2 is missing its path-length DWORD.")
        (units,) = struct.unpack_from("<I", data, V2_LENGTH_OFFSET)
        if not 1 <= units <= MAX_PATH_UNITS:
            raise ParseError(
                "invalid_path_length",
                f"Path length {units} is outside the supported range 1..{MAX_PATH_UNITS} code units.",
            )
        expected = V2_PATH_OFFSET + units * 2
        if len(data) < expected:
            raise ParseError(
                "truncated_path",
                f"Declared path requires {expected} bytes; got {len(data)}.",
            )
        field = data[V2_PATH_OFFSET:expected]
    else:
        raise ParseError("unsupported_version", f"Unsupported $I format version: {version}.")

    if len(data) > expected:
        warnings.append("trailing_data")
    path = _decode_path(field, version, warnings)
    deleted_at = _filetime(ticks, warnings)
    return Metadata(version, size, ticks, deleted_at, path, tuple(warnings))
