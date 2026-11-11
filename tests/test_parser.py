"""Synthetic byte-level tests, independently assembled without parser constants."""

import struct
from datetime import datetime, timezone

import pytest

from rbinforensics.parser import ParseError, parse_metadata

UNIX_EPOCH_FILETIME = 116_444_736_000_000_000


def test_literal_v2_bytes():
    # A second oracle independent of the struct.pack fixture builders: size 5,
    # Unix epoch in FILETIME, nine UTF-16 code units including the terminator.
    data = bytes.fromhex(
        "0200000000000000 0500000000000000 00803ed5deb19d01 09000000 "
        "43003a005c0061002e007400780074000000"
    )
    result = parse_metadata(data)
    assert result.format_version == 2
    assert result.original_size == 5
    assert result.original_path == r"C:\a.txt"
    assert result.deleted_at_utc == "1970-01-01T00:00:00.0000000Z"
    assert result.warnings == ()


def version1(path=r"C:\Users\Analyst\report.txt", size=42, ticks=UNIX_EPOCH_FILETIME):
    field = (path + "\0").encode("utf-16-le")
    assert len(field) <= 520
    return struct.pack("<QQQ", 1, size, ticks) + field.ljust(520, b"\0")


def version2(path=r"C:\Users\Analyst\report.txt", size=42, ticks=UNIX_EPOCH_FILETIME):
    field = (path + "\0").encode("utf-16-le")
    return struct.pack("<QQQI", 2, size, ticks, len(field) // 2) + field


@pytest.mark.parametrize("builder", [version1, version2])
def test_valid_layouts(builder):
    result = parse_metadata(builder())
    assert result.original_path == r"C:\Users\Analyst\report.txt"
    assert result.original_size == 42
    assert result.deletion_filetime == UNIX_EPOCH_FILETIME
    assert result.deleted_at_utc == "1970-01-01T00:00:00.0000000Z"
    assert result.warnings == ()


def test_version_number():
    assert parse_metadata(version1()).format_version == 1
    assert parse_metadata(version2()).format_version == 2


@pytest.mark.parametrize("builder", [version1, version2])
def test_non_ascii_and_non_bmp(builder):
    path = "C:\\数据\\cat-🐈.txt"
    assert parse_metadata(builder(path)).original_path == path


@pytest.mark.parametrize("builder", [version1, version2])
def test_uint64_size(builder):
    assert parse_metadata(builder(size=2**64 - 1)).original_size == 2**64 - 1


@pytest.mark.parametrize("builder", [version1, version2])
def test_100ns_precision(builder):
    parsed = parse_metadata(builder(ticks=UNIX_EPOCH_FILETIME + 12_345_679))
    assert parsed.deleted_at_utc == "1970-01-01T00:00:01.2345679Z"


def test_first_nonzero_tick():
    assert parse_metadata(version2(ticks=1)).deleted_at_utc == "1601-01-01T00:00:00.0000001Z"


def test_zero_timestamp():
    result = parse_metadata(version2(ticks=0))
    assert result.deleted_at_utc is None
    assert result.deletion_filetime == 0
    assert result.warnings == ("zero_deletion_time",)


def test_largest_representable_timestamp():
    delta = datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc) - datetime(
        1601, 1, 1, tzinfo=timezone.utc
    )
    ticks = (delta.days * 86400 + delta.seconds) * 10_000_000 + 9_999_999
    assert parse_metadata(version2(ticks=ticks)).deleted_at_utc == "9999-12-31T23:59:59.9999999Z"
    result = parse_metadata(version2(ticks=ticks + 1))
    assert result.deleted_at_utc is None
    assert "deletion_time_out_of_range" in result.warnings


def test_unsigned_timestamp_overflow():
    result = parse_metadata(version2(ticks=2**64 - 1))
    assert result.deleted_at_utc is None
    assert result.deletion_filetime == 2**64 - 1
    assert "deletion_time_out_of_range" in result.warnings


@pytest.mark.parametrize("length", [0, 1, 7, 8, 16, 23])
def test_short_header(length):
    with pytest.raises(ParseError) as caught:
        parse_metadata(version2()[:length])
    assert caught.value.code == "truncated_header"


@pytest.mark.parametrize("length", [24, 25, 26, 27])
def test_missing_v2_length(length):
    with pytest.raises(ParseError) as caught:
        parse_metadata(version2()[:length])
    assert caught.value.code == "truncated_header"


@pytest.mark.parametrize("version", [0, 3, 0x0100000000000000, 2**64 - 1])
def test_unsupported_version(version):
    with pytest.raises(ParseError) as caught:
        parse_metadata(struct.pack("<QQQ", version, 42, UNIX_EPOCH_FILETIME))
    assert caught.value.code == "unsupported_version"


@pytest.mark.parametrize("units", [0, 32769, 2**32 - 1])
def test_invalid_declared_length(units):
    with pytest.raises(ParseError) as caught:
        parse_metadata(struct.pack("<QQQI", 2, 0, UNIX_EPOCH_FILETIME, units))
    assert caught.value.code == "invalid_path_length"


@pytest.mark.parametrize("builder", [version1, version2])
def test_truncated_path(builder):
    with pytest.raises(ParseError) as caught:
        parse_metadata(builder()[:-1])
    assert caught.value.code == "truncated_path"


def test_v2_declared_length_is_not_python_character_count():
    encoded = "C:\\🐈\0".encode("utf-16-le")
    correct = struct.pack("<QQQI", 2, 1, UNIX_EPOCH_FILETIME, len(encoded) // 2) + encoded
    assert parse_metadata(correct).original_path == "C:\\🐈"


def test_v2_boundary_path_length():
    field = ("C:\\" + "x" * 32764 + "\0").encode("utf-16-le")
    assert len(field) == 32768 * 2
    data = struct.pack("<QQQI", 2, 1, UNIX_EPOCH_FILETIME, 32768) + field
    assert len(parse_metadata(data).original_path) == 32767


@pytest.mark.parametrize("builder", [version1, version2])
def test_extra_bytes_are_flagged(builder):
    result = parse_metadata(builder() + b"extra")
    assert result.warnings == ("trailing_data",)


def test_invalid_utf16_v2():
    data = struct.pack("<QQQI", 2, 1, UNIX_EPOCH_FILETIME, 2) + b"\x00\xd8\x00\x00"
    with pytest.raises(ParseError) as caught:
        parse_metadata(data)
    assert caught.value.code == "invalid_utf16"


def test_invalid_utf16_v1():
    data = struct.pack("<QQQ", 1, 1, UNIX_EPOCH_FILETIME) + b"\x00\xd8" + b"\0" * 518
    with pytest.raises(ParseError) as caught:
        parse_metadata(data)
    assert caught.value.code == "invalid_utf16"


def test_v1_nonzero_padding_is_visible():
    data = bytearray(version1())
    data[-2:] = b"x\0"
    parsed = parse_metadata(bytes(data))
    assert parsed.original_path == r"C:\Users\Analyst\report.txt"
    assert parsed.warnings == ("nonzero_path_padding",)


def test_v1_no_terminator():
    data = struct.pack("<QQQ", 1, 1, UNIX_EPOCH_FILETIME) + ("C:\\" + "x" * 257).encode("utf-16-le")
    parsed = parse_metadata(data)
    assert len(parsed.original_path) == 260
    assert parsed.warnings == ("missing_path_terminator",)


def test_v2_no_terminator():
    field = r"C:\test.txt".encode("utf-16-le")
    data = struct.pack("<QQQI", 2, 1, UNIX_EPOCH_FILETIME, len(field) // 2) + field
    parsed = parse_metadata(data)
    assert parsed.original_path == r"C:\test.txt"
    assert parsed.warnings == ("missing_path_terminator",)


def test_embedded_nul_is_retained_and_flagged_v2():
    parsed = parse_metadata(version2("C:\\one\0two"))
    assert parsed.original_path == "C:\\one\0two"
    assert parsed.warnings == ("embedded_nul_in_path",)


@pytest.mark.parametrize("builder", [version1, version2])
def test_empty_path(builder):
    assert parse_metadata(builder("")).warnings == ("empty_original_path",)


@pytest.mark.parametrize("path", ["relative.txt", "C:relative.txt", "\\rooted-without-drive"])
def test_suspicious_non_absolute_paths(path):
    assert parse_metadata(version2(path)).warnings == ("non_absolute_windows_path",)


@pytest.mark.parametrize(
    "path",
    [
        r"\\server\share\folder\file.txt",
        r"\\server\share",
        "//server/share",
        r"\\?\C:\long\file.txt",
        "\\\\?\\C:\\",
    ],
)
def test_unc_and_extended_windows_paths(path):
    assert parse_metadata(version2(path)).warnings == ()


def test_control_character_path():
    parsed = parse_metadata(version2("C:\\evil\nname"))
    assert parsed.original_path == "C:\\evil\nname"
    assert parsed.warnings == ("control_characters_in_path",)


def test_frozen_metadata():
    from dataclasses import FrozenInstanceError

    result = parse_metadata(version2())
    with pytest.raises(FrozenInstanceError):
        result.original_size = 999
