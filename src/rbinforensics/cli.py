"""Command-line boundary: validate options and keep output outside evidence."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from . import __version__
from .reports import render, safe_text
from .scanner import EvidenceError, ScanOptions, absolute_path, ensure_no_symlinks, scan


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rbf",
        description="Read Windows Recycle Bin $I metadata without modifying source contents.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser(
        "scan", help="Analyze a $I file or a folder of collected artifacts"
    )
    command.add_argument("input", type=Path, help="A $I file or evidence directory")
    command.add_argument(
        "--recursive", action="store_true", help="Include nested directories (e.g. SID folders)"
    )
    command.add_argument("--format", choices=("table", "json", "csv"), default="table")
    command.add_argument(
        "--output", type=Path, help="Create a NEW report outside the evidence directory"
    )
    command.add_argument(
        "--timezone", default="UTC", help="Display timezone (default: UTC; e.g. Asia/Jakarta)"
    )
    command.add_argument(
        "--hash-payload", action="store_true", help="Also SHA-256 hash regular sibling $R files"
    )
    command.add_argument(
        "--case-id", help="Examiner-supplied case identifier, copied into JSON options"
    )
    command.add_argument("--examiner", help="Examiner-supplied name, copied into JSON options")
    return parser


def _validate_output(source: Path, output: Path) -> None:
    ensure_no_symlinks(output)
    if output.exists():
        raise EvidenceError("output_exists", "Output already exists; choose a new filename.")
    # Even single-file analysis must not create a report among its sibling evidence.
    root = source if source.is_dir() else source.parent
    if output == root or root in output.parents:
        raise EvidenceError(
            "output_inside_evidence", "Report output must be outside the evidence directory."
        )
    if not output.parent.is_dir():
        raise EvidenceError("output_parent_missing", "Output parent directory must already exist.")


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    source = absolute_path(args.input)
    output = absolute_path(args.output) if args.output else None
    try:
        if args.timezone != "UTC":
            ZoneInfo(args.timezone)
        if output:
            _validate_output(source, output)
        options = ScanOptions(
            args.recursive, args.hash_payload, args.timezone, args.case_id, args.examiner
        )
        report = scan(source, options)
        text = render(report, args.format)
        if output:
            # Revalidate after scanning; never truncate an existing file. Remove
            # a partial report if a write fails so it cannot look like a full run.
            _validate_output(source, output)
            created = False
            try:
                with output.open("x", encoding="utf-8", newline="") as stream:
                    created = True
                    stream.write(text)
                    stream.flush()
                    os.fsync(stream.fileno())
            except BaseException:
                if created:
                    output.unlink(missing_ok=True)
                raise
            print(f"Report saved: {safe_text(output)}", file=sys.stderr)
        else:
            sys.stdout.write(text)
        summary = report["summary"]
        if summary["errors"] or summary["skipped"]:
            return 1
        return 0 if summary["candidates"] else 2
    except ZoneInfoNotFoundError:
        print(
            "rbf: unknown timezone or missing timezone database; install tzdata if needed.",
            file=sys.stderr,
        )
        return 2
    except (OSError, EvidenceError, ValueError) as exc:
        print(f"rbf: {safe_text(exc)}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("rbf: interrupted; scan incomplete.", file=sys.stderr)
        return 130
