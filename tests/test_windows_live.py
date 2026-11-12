"""Opt-in validation against artifacts produced by the real Windows shell.

Run only on a disposable Windows validation host:
    $env:RBF_RUN_WINDOWS_LIVE = '1'
    python -m pytest tests/test_windows_live.py -v

The shell recycles only this test's UUID-named temporary file. Candidate lookup
uses its unique extension in the current user's bin. There is no empty-bin
operation, and cleanup requires both the recorded original path and a matching
known payload digest. These samples validate the tested Windows build, not every
Windows release or an independently maintained forensic corpus.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import platform
import re
import subprocess
import time
import uuid
from ctypes import wintypes
from datetime import datetime, timezone
from pathlib import Path

import pytest

from rbinforensics.parser import Metadata, ParseError, parse_metadata
from rbinforensics.scanner import ScanOptions, ensure_no_symlinks, scan

pytestmark = pytest.mark.skipif(
    os.name != "nt" or os.environ.get("RBF_RUN_WINDOWS_LIVE") != "1",
    reason="Requires Windows and explicit RBF_RUN_WINDOWS_LIVE=1 on a disposable host.",
)

FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
TICKS_PER_SECOND = 10_000_000


def _clock_ticks() -> int:
    """Independent expected interval, using integer arithmetic only."""
    elapsed = datetime.now(timezone.utc) - FILETIME_EPOCH
    return (elapsed.days * 86400 + elapsed.seconds) * TICKS_PER_SECOND + elapsed.microseconds * 10


def _current_sid() -> str:
    # Read only the SID from output bytes; no locale-sensitive header or account
    # name is used, and no shell is involved in executing this system command.
    completed = subprocess.run(
        ["whoami.exe", "/user", "/fo", "csv", "/nh"],
        capture_output=True,
        check=True,
    )
    match = re.search(rb"\bS-\d+(?:-\d+)+\b", completed.stdout)
    assert match is not None, "Windows did not return a current-user SID."
    return match.group().decode("ascii")


def _send_own_file_to_recycle_bin(source: Path) -> None:
    """Invoke the native shell for one literal, freshly created sample path."""
    assert source.is_file()
    assert "rbf-" in source.suffix
    # SHFileOperation does not support the extended-length \\?\ namespace.
    assert len(str(source).encode("utf-16-le")) // 2 < 260, "Validation path exceeds MAX_PATH."

    class SHFILEOPSTRUCTW(ctypes.Structure):
        _fields_ = [
            ("hwnd", wintypes.HWND),
            ("wFunc", wintypes.UINT),
            ("pFrom", wintypes.LPCWSTR),
            ("pTo", wintypes.LPCWSTR),
            ("fFlags", wintypes.WORD),
            ("fAnyOperationsAborted", wintypes.BOOL),
            ("hNameMappings", wintypes.LPVOID),
            ("lpszProgressTitle", wintypes.LPCWSTR),
        ]

    from_text = str(source) + "\0"
    # Include the list terminator plus the string terminator. Count UTF-16 code
    # units explicitly so a non-BMP filename has enough space on Windows.
    from_buffer = ctypes.create_unicode_buffer(
        from_text, len(from_text.encode("utf-16-le")) // 2 + 1
    )
    operation = SHFILEOPSTRUCTW()
    operation.wFunc = 0x0003  # FO_DELETE
    operation.pFrom = ctypes.cast(from_buffer, wintypes.LPCWSTR)
    # SILENT | NOCONFIRMATION | ALLOWUNDO (recycle) | NOERRORUI.
    operation.fFlags = 0x0004 | 0x0010 | 0x0040 | 0x0400
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    function = shell.SHFileOperationW
    function.argtypes = [ctypes.POINTER(SHFILEOPSTRUCTW)]
    function.restype = ctypes.c_int
    result = function(ctypes.byref(operation))
    assert result == 0, f"Native recycle operation failed: shell status={result}."
    assert not operation.fAnyOperationsAborted, "Native recycle operation was aborted."
    assert not source.exists(), "Shell returned success without removing the source sample."


def _find_owned_artifact(directory: Path, extension: str, original: Path) -> tuple[Path, Metadata]:
    deadline = time.monotonic() + 10
    matches: list[tuple[Path, Metadata]] = []
    while time.monotonic() < deadline:
        matches = []
        if directory.is_dir():
            ensure_no_symlinks(directory)
            # Only this test's random extension can match, avoiding unrelated
            # user artifact reads when the test is deliberately run locally.
            for candidate in directory.glob(f"$I*{extension}"):
                ensure_no_symlinks(candidate)
                try:
                    metadata = parse_metadata(candidate.read_bytes())
                except (OSError, ParseError):
                    continue
                if os.path.normcase(metadata.original_path) == os.path.normcase(str(original)):
                    matches.append((candidate, metadata))
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            pytest.fail("More than one native artifact claims the unique sample path.")
        time.sleep(0.1)
    pytest.fail(
        "Native recycling did not produce a matching $I artifact within 10 seconds. "
        "This enabled validation requires a local volume with functioning Recycle Bin."
    )


def _cleanup_verified_pair(metadata_path: Path, original: Path, expected_digest: str) -> None:
    """Remove only a still-verified pair belonging to this individual test."""
    payload_path = metadata_path.with_name("$R" + metadata_path.name[2:])
    ensure_no_symlinks(metadata_path)
    ensure_no_symlinks(payload_path)
    current = parse_metadata(metadata_path.read_bytes())
    assert os.path.normcase(current.original_path) == os.path.normcase(str(original))
    assert hashlib.sha256(payload_path.read_bytes()).hexdigest() == expected_digest
    payload_path.unlink()
    metadata_path.unlink()


@pytest.mark.parametrize("sample_name", ["ascii-sample", "unicode-資料-📄"])
def test_native_recycle_metadata_matches_controlled_ground_truth(
    tmp_path: Path, sample_name: str, record_property
) -> None:
    """Exercise real shell bytes against independently known sample facts."""
    extension = ".rbf-" + uuid.uuid4().hex
    source = tmp_path.resolve() / (sample_name + extension)
    content = ("RBF CONTROLLED WINDOWS VALIDATION\n" + sample_name + "\n").encode("utf-8")
    expected_digest = hashlib.sha256(content).hexdigest()
    with source.open("xb") as stream:
        stream.write(content)
    current_sid = _current_sid()
    bin_directory = Path(source.anchor) / "$Recycle.Bin" / current_sid
    record_property("windows_build", platform.version())
    record_property("sample_kind", "unicode" if "unicode" in sample_name else "ascii")

    lower_bound = _clock_ticks()
    _send_own_file_to_recycle_bin(source)
    upper_bound = _clock_ticks()
    metadata_path, native_metadata = _find_owned_artifact(bin_directory, extension, source)
    payload_path = metadata_path.with_name("$R" + metadata_path.name[2:])
    ensure_no_symlinks(payload_path)
    # Only a verified path+payload pair can be eligible for cleanup. If the
    # payload does not match, leave it intact for diagnosis rather than deleting.
    owned_pair_verified = False
    try:
        assert payload_path.is_file(), "Native $R payload is missing."
        actual_digest = hashlib.sha256(payload_path.read_bytes()).hexdigest()
        assert actual_digest == expected_digest, "Native payload differs from known sample bytes."
        owned_pair_verified = True
        record_property("native_i_format", str(native_metadata.format_version))
        assert native_metadata.original_size == len(content)
        tolerance = 2 * TICKS_PER_SECOND
        assert (
            lower_bound - tolerance <= native_metadata.deletion_filetime <= upper_bound + tolerance
        )
        assert native_metadata.deleted_at_utc is not None
        assert not native_metadata.warnings, native_metadata.warnings

        report = scan(metadata_path, ScanOptions(hash_payload=True))
        assert report["summary"]["errors"] == 0, report["records"]
        assert report["summary"]["parsed"] == 1
        assert report["summary"]["payloads_hashed"] == 1
        record = next(item for item in report["records"] if item["record_type"] == "metadata")
        assert os.path.normcase(record["metadata"]["original_path"]) == os.path.normcase(
            str(source)
        )
        assert record["metadata"]["original_size"] == len(content)
        assert record["metadata"]["deletion_filetime"] == native_metadata.deletion_filetime
        assert record["payload"]["sha256"] == expected_digest
        assert record["payload"]["size_matches_metadata"] is True
        assert record["source_sha256"] == hashlib.sha256(metadata_path.read_bytes()).hexdigest()
        # An explicit output setting preserves only this verified, generated
        # sample for an independent parser job. Never collect unrelated bins.
        capture = os.environ.get("RBF_WINDOWS_SAMPLE_DIR")
        if capture:
            capture_root = Path(capture).absolute()
            ensure_no_symlinks(capture_root)
            capture_root.mkdir(parents=True, exist_ok=True)
            ensure_no_symlinks(capture_root)
            destination = capture_root / sample_name
            destination.mkdir()
            ensure_no_symlinks(metadata_path)
            sample = metadata_path.read_bytes()
            assert hashlib.sha256(sample).hexdigest() == record["source_sha256"]
            with (destination / metadata_path.name).open("xb") as stream:
                stream.write(sample)
            provenance = {
                "sample_kind": "controlled_windows_shell",
                "windows_build": platform.version(),
                "original_path": str(source),
                "original_size": len(content),
                "payload_sha256": expected_digest,
                "metadata_name": metadata_path.name,
                "metadata_sha256": hashlib.sha256(sample).hexdigest(),
                "deletion_lower_bound_filetime": lower_bound - tolerance,
                "deletion_upper_bound_filetime": upper_bound + tolerance,
                "note": "Freshly generated test data; not case evidence. Payload verified before cleanup.",
            }
            with (destination / "provenance.json").open("x", encoding="utf-8") as stream:
                json.dump(provenance, stream, indent=2, ensure_ascii=False)
    finally:
        if owned_pair_verified:
            _cleanup_verified_pair(metadata_path, source, expected_digest)
