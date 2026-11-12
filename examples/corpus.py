"""Deterministic synthetic corpus and an independently specified result oracle.

Generation uses only the standard library. No expected field is obtained by
calling the parser/scanner under test. The verifier imports that engine only
after checking the manifest and the complete file/directory inventory.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import struct
from pathlib import Path

CORPUS_ID = "rbf-synthetic-v1"
SID = "S-1-5-21-111111111-222222222-333333333-1001"
PREFIX = f"evidence/$Recycle.Bin/{SID}"
TICKS = 133_485_408_001_234_567
UTC = "2024-01-01T00:00:00.1234567Z"
NOTICE = (
    b"SYNTHETIC VALIDATION CORPUS ONLY. No real user data.\n"
    b"Hand-specified test bytes; not acquired from a Windows device.\n"
    b"The corpus contains deliberate errors. Read manifest.json and docs/DATASET.md.\n"
)


def encode_metadata(version: int, path: str, size: int, ticks: int = TICKS) -> bytes:
    """Construct documented little-endian layouts without using the parser."""
    field = (path + "\0").encode("utf-16-le")
    header = struct.pack("<QQQ", version, size, ticks)
    if version == 1:
        if len(field) > 520:
            raise ValueError("Version 1 path exceeds its fixed 260-code-unit field.")
        return header + field.ljust(520, b"\0")
    if version == 2:
        return header + struct.pack("<I", len(field) // 2) + field
    raise ValueError("Corpus encoding supports versions 1 and 2 only.")


def _specification() -> tuple[dict[str, bytes], set[str], list[dict]]:
    files = {"SYNTHETIC_EVIDENCE.txt": NOTICE}
    directories = {"evidence", "evidence/$Recycle.Bin", PREFIX}
    cases = []

    def payload_expectation(name: str, content: bytes | str | None, size: int | None) -> dict:
        if content is None:
            return {
                "path": None,
                "status": "missing",
                "size": None,
                "sha256": None,
                "hash_status": "unavailable",
                "size_matches_metadata": None,
            }
        path = f"{PREFIX}/$R{name}"
        if content == "directory":
            directories.add(path)
            files[path + "/readme.txt"] = b"SYNTHETIC folder contents.\n"
            # A payload folder is data, not a second Recycle Bin container.
            files[path + "/$IINSIDE.txt"] = encode_metadata(2, r"C:\Demo\inside.txt", 0)
            return {
                "path": path,
                "status": "available_directory",
                "size": None,
                "sha256": None,
                "hash_status": "not_applicable",
                "size_matches_metadata": None,
            }
        assert isinstance(content, bytes)
        files[path] = content
        return {
            "path": path,
            "status": "available_file",
            "size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
            "hash_status": "computed",
            "size_matches_metadata": len(content) == size if size is not None else None,
        }

    def add(
        case_id: str,
        suffix: str,
        data: bytes,
        metadata: dict | None,
        content: bytes | str | None = None,
        issues: tuple[str, ...] = (),
        status: str = "ok",
    ) -> None:
        source = f"{PREFIX}/$I{suffix}"
        files[source] = data
        payload = payload_expectation(
            suffix, content, metadata["original_size"] if metadata is not None else None
        )
        cases.append(
            {
                "id": case_id,
                "source": source,
                "record_type": "metadata",
                "expected": {
                    "metadata": metadata,
                    "status": status,
                    "issue_codes": list(issues),
                    "payload": payload,
                    "source_size": len(data),
                    "source_sha256": hashlib.sha256(data).hexdigest(),
                    "sid": SID,
                },
            }
        )

    def valid(
        case_id: str,
        suffix: str,
        version: int,
        path: str,
        size: int,
        content: bytes | str | None = None,
        *,
        ticks: int = TICKS,
        utc: str | None = UTC,
        issues: tuple[str, ...] = (),
        trailing: bytes = b"",
    ) -> None:
        expected = {
            "format_version": version,
            "original_path": path,
            "original_size": size,
            "deletion_filetime": ticks,
            "deleted_at_utc": utc,
        }
        add(
            case_id,
            suffix,
            encode_metadata(version, path, size, ticks) + trailing,
            expected,
            content,
            issues,
            "warning" if issues else "ok",
        )

    valid("v1-ascii", "V10001.txt", 1, r"C:\Demo\notes.txt", 6, b"notes\n")
    valid("v2-unicode", "V20002.txt", 2, "C:\\Demo\\資料-📄.txt", 8, b"unicode\n")
    valid("zero-size", "ZERO03.bin", 2, r"C:\Demo\empty.bin", 0, b"")
    valid("large-uint64", "LARGE04.bin", 2, r"C:\Demo\large.bin", 2**53 + 3)
    valid("max-uint64", "MAX005.bin", 1, r"C:\Demo\max.bin", 2**64 - 1)
    valid(
        "adjacent-tick",
        "TICK06.txt",
        2,
        r"C:\Demo\tick.txt",
        5,
        b"tick\n",
        ticks=TICKS + 1,
        utc="2024-01-01T00:00:00.1234568Z",
    )
    valid("missing-payload", "MISS07.pdf", 2, r"C:\Demo\missing.pdf", 1024)
    valid(
        "size-mismatch",
        "SIZE08.txt",
        2,
        r"C:\Demo\mismatch.txt",
        100,
        b"short\n",
        issues=("payload_size_mismatch",),
    )
    valid("paired-folder", "DIR009", 2, r"C:\Demo\folder", 0, "directory")
    valid(
        "unknown-time",
        "TIME10.txt",
        2,
        r"C:\Demo\unknown-time.txt",
        0,
        b"",
        ticks=0,
        utc=None,
        issues=("zero_deletion_time",),
    )
    valid(
        "trailing-bytes",
        "TAIL11.txt",
        2,
        r"C:\Demo\trailing.txt",
        0,
        b"",
        trailing=b"DEMO",
        issues=("trailing_data",),
    )
    valid("long-path", "LONG12.txt", 2, "C:\\Demo\\" + "folder\\" * 50 + "long.txt", 0, b"")
    malformed = [
        ("truncated-header", "BAD013.bin", b"\x02\0\0", "truncated_header", b"paired\n"),
        (
            "truncated-v1-path",
            "BAD014.bin",
            struct.pack("<QQQ", 1, 0, TICKS),
            "truncated_path",
            None,
        ),
        (
            "truncated-v2-path",
            "BAD015.bin",
            struct.pack("<QQQI", 2, 0, TICKS, 20) + b"A\0",
            "truncated_path",
            None,
        ),
        (
            "unsupported-version",
            "BAD016.bin",
            struct.pack("<QQQ", 99, 0, TICKS),
            "unsupported_version",
            None,
        ),
        (
            "invalid-utf16",
            "BAD017.bin",
            struct.pack("<QQQI", 2, 0, TICKS, 2) + b"\0\xd8\0\0",
            "invalid_utf16",
            None,
        ),
        (
            "invalid-path-length",
            "BAD018.bin",
            struct.pack("<QQQI", 2, 0, TICKS, 0),
            "invalid_path_length",
            None,
        ),
    ]
    for case_id, suffix, data, error, content in malformed:
        add(case_id, suffix, data, None, content, (error,), "error")
    for case_id, suffix, content in (
        ("orphan-file", "ORPH19.bin", b"SYNTHETIC orphan\n"),
        ("orphan-folder", "ORPH20", "directory"),
    ):
        payload = payload_expectation(suffix, content, None)
        cases.append(
            {
                "id": case_id,
                "source": payload["path"],
                "record_type": "orphan_payload",
                "expected": {
                    "metadata": None,
                    "status": "warning",
                    "issue_codes": ["orphan_payload"],
                    "payload": payload,
                    "source_size": payload["size"],
                    "source_sha256": payload["sha256"],
                    "sid": SID,
                },
            }
        )
    return files, directories, cases


def expected_manifest() -> dict:
    """Return the canonical oracle from fixed inputs, never observed scan output."""
    files, directories, cases = _specification()
    return {
        "schema_version": "1.0",
        "corpus_id": CORPUS_ID,
        "synthetic": True,
        "evidence_root": "evidence",
        "scan_options": {"recursive": True, "hash_payload": True, "timezone": "UTC"},
        "expected_summary": {
            "candidates": 18,
            "parsed": 12,
            "errors": 6,
            "warnings": 5,
            "skipped": 0,
            "payloads_hashed": 10,
            "orphan_payloads": 2,
        },
        "files": [
            {"path": path, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            for path, data in sorted(files.items())
        ],
        "directories": sorted(directories),
        "cases": cases,
    }


def _ensure_unredirected(path: Path) -> None:
    for item in reversed((path, *path.parents)):
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or (
            getattr(info, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        ):
            raise ValueError(f"Refusing a symlink/reparse-point path: {item}")


def generate_corpus(destination: Path) -> dict:
    """Create a new corpus directory, refusing existing or redirected destinations."""
    destination = Path(os.path.abspath(destination))
    _ensure_unredirected(destination)
    destination.mkdir(parents=True, exist_ok=False)
    files, directories, _ = _specification()
    for directory in sorted(directories):
        (destination / directory).mkdir()
    for relative, data in sorted(files.items()):
        with (destination / relative).open("xb") as stream:
            stream.write(data)
    manifest = expected_manifest()
    with (destination / "manifest.json").open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    return manifest


def _inventory(root: Path) -> tuple[dict[str, bytes], list[str]]:
    files: dict[str, bytes] = {}
    directories: list[str] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        _ensure_unredirected(directory)
        for path in directory.iterdir():
            _ensure_unredirected(path)
            relative = path.relative_to(root).as_posix()
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                directories.append(relative)
                pending.append(path)
            elif stat.S_ISREG(info.st_mode):
                if info.st_size > 1024 * 1024:
                    raise ValueError(f"Unexpected oversized corpus file: {relative}")
                files[relative] = path.read_bytes()
            else:
                raise ValueError(f"Unexpected nonregular item: {relative}")
    return files, sorted(directories)


def verify_corpus(destination: Path) -> dict:
    """Check the fixed oracle, complete inventory, then actual engine observations.

    Any extra/missing/tampered item or field mismatch is a failed validation.
    The result is JSON serializable; failures return status=failed and diagnostics.
    """
    root = Path(os.path.abspath(destination))
    failures: list[str] = []
    expected = expected_manifest()
    try:
        _ensure_unredirected(root)
        files, directories = _inventory(root)
        manifest = json.loads(files.pop("manifest.json"))
        if manifest != expected:
            failures.append("manifest.json differs from the canonical corpus specification")
        if directories != expected["directories"]:
            failures.append("Directory inventory differs from the canonical corpus specification")
        inventory = [
            {"path": path, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            for path, data in sorted(files.items())
        ]
        if inventory != expected["files"]:
            failures.append(
                "File inventory/size/SHA-256 differs from the canonical corpus specification"
            )
    except (OSError, ValueError, KeyError) as exc:
        failures.append(f"Corpus inventory cannot be verified: {exc}")
    if failures:
        return {
            "corpus_id": CORPUS_ID,
            "status": "failed",
            "cases_checked": 0,
            "failures": failures,
        }
    from rbinforensics.scanner import ScanOptions, scan

    report = scan(root / expected["evidence_root"], ScanOptions(**expected["scan_options"]))
    if report["summary"] != expected["expected_summary"]:
        failures.append("Scan summary differs from the hand-specified corpus totals")
    records = {
        Path(record["source_path"]).relative_to(root).as_posix(): record
        for record in report["records"]
    }
    expected_sources = {case["source"] for case in expected["cases"]}
    if set(records) != expected_sources or len(records) != len(report["records"]):
        failures.append("Observed record inventory differs from the case list")
    for case in expected["cases"]:
        record = records.get(case["source"])
        if record is None:
            continue
        actual = {
            "metadata": {key: record["metadata"].get(key) for key in case["expected"]["metadata"]}
            if record["metadata"] is not None and case["expected"]["metadata"] is not None
            else record["metadata"],
            "status": record["status"],
            "issue_codes": sorted(issue["code"] for issue in record["issues"]),
            "payload": {
                **record["payload"],
                "path": Path(record["payload"]["path"]).relative_to(root).as_posix()
                if record["payload"]["path"] is not None
                else None,
            },
            "source_size": record["source_size"],
            "source_sha256": record["source_sha256"],
            "sid": record["sid"],
        }
        expected_record = {
            **case["expected"],
            "issue_codes": sorted(case["expected"]["issue_codes"]),
        }
        if record["record_type"] != case["record_type"]:
            failures.append(f"{case['id']}: record_type differs")
        for field, value in expected_record.items():
            if actual[field] != value:
                failures.append(
                    f"{case['id']}: {field} differs (expected {value!r}, observed {actual[field]!r})"
                )
    return {
        "corpus_id": CORPUS_ID,
        "status": "failed" if failures else "passed",
        "cases_checked": len(expected["cases"]),
        "files_verified": len(expected["files"]),
        "failures": failures,
    }
