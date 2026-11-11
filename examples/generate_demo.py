"""Generate clearly synthetic Recycle Bin artefacts; never copy real user data.

The destination must not exist. Run from a checkout, for example:
    python examples/generate_demo.py work/demo
"""

from __future__ import annotations

import argparse
import struct
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
DEMO_TIME = datetime(2026, 1, 15, 3, 4, 5, 123456, tzinfo=timezone.utc)


def demo_filetime() -> int:
    """Return 2026-01-15T03:04:05.1234567Z without floating-point rounding."""
    delta = DEMO_TIME - EPOCH
    return ((delta.days * 86400 + delta.seconds) * 10_000_000) + delta.microseconds * 10 + 7


def metadata(version: int, original_path: str, size: int, *, offset_days: int = 0) -> bytes:
    """Build independent, documented test bytes, not a Windows acquisition."""
    encoded_path = original_path.encode("utf-16-le") + b"\x00\x00"
    header = struct.pack("<QQQ", version, size, demo_filetime() + offset_days * 86400 * 10_000_000)
    if version == 1:
        if len(encoded_path) > 520:
            raise ValueError("The version 1 demo path exceeds its fixed 260-code-unit field")
        return header + encoded_path.ljust(520, b"\x00")
    if version == 2:
        return header + struct.pack("<I", len(encoded_path) // 2) + encoded_path
    raise ValueError("Demo generation supports versions 1 and 2 only")


def write_new(path: Path, contents: bytes) -> None:
    with path.open("xb") as handle:
        handle.write(contents)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path, help="New directory for synthetic evidence")
    parser.add_argument(
        "--include-broken",
        action="store_true",
        help="Also generate one deliberately truncated $I file to demonstrate partial failure",
    )
    args = parser.parse_args(argv)

    try:
        args.destination.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        parser.error("Destination already exists; choose a new directory to avoid overwriting data")
    except OSError as exc:
        parser.error(f"Cannot create destination: {exc}")

    # A realistic folder layout, with a deliberately synthetic SID and fictitious paths.
    evidence = args.destination / "$Recycle.Bin" / "S-1-5-21-111111111-222222222-333333333-1001"
    evidence.mkdir(parents=True)
    first_payload = b"SYNTHETIC DEMO ONLY: sample notes.\n"
    second_payload = b"SYNTHETIC DEMO ONLY: sample report.\n"
    samples = [
        ("DEMO01.txt", 1, r"C:\Users\Demo\Documents\notes.txt", first_payload),
        ("DEMO02.txt", 2, "C:\\Users\\Demo\\Documents\\laporan-\U0001f4c4.txt", second_payload),
        ("DEMO03.pdf", 2, r"C:\Users\Demo\Downloads\missing-demo.pdf", None),
    ]
    try:
        for offset_days, (suffix, version, original_path, payload) in enumerate(samples):
            size = len(payload) if payload is not None else 32_768
            write_new(
                evidence / f"$I{suffix}",
                metadata(version, original_path, size, offset_days=offset_days),
            )
            if payload is not None:
                write_new(evidence / f"$R{suffix}", payload)
        write_new(evidence / "$RORPHAN04.bin", b"SYNTHETIC ORPHAN: no metadata exists.\n")
        orphan_directory = evidence / "$RORPHAN05"
        orphan_directory.mkdir()
        write_new(orphan_directory / "notes.txt", b"SYNTHETIC ORPHAN DIRECTORY CONTENT.\n")
        if args.include_broken:
            write_new(evidence / "$IBROKEN.bin", struct.pack("<Q", 2) + b"truncated")
        write_new(
            args.destination / "SYNTHETIC_EVIDENCE.txt",
            b"Generated demonstration data only.\n"
            b"Not acquired from Windows; not an independently verified compatibility corpus.\n"
            b"Paths and SID are fictitious. The third record intentionally has no $R payload.\n",
        )
    except OSError as exc:
        parser.exit(1, f"Generation failed; an incomplete demo may remain: {exc}\n")
    print(f"Created synthetic evidence in {args.destination}")
    print("Scan the nested $Recycle.Bin folder with --recursive.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
