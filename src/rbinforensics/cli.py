"""Command-line boundary: validate options and keep output outside evidence."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from . import __version__
from .analysis import FilterOptions, validate_filters
from .output import validate_output as _validate_output
from .output import write_report
from .reports import render, safe_text
from .scanner import EvidenceError, ScanOptions, absolute_path, scan


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rbf",
        description="Read Windows Recycle Bin $I metadata without modifying source contents.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("gui", help="Open the local desktop application")
    command = commands.add_parser(
        "scan", help="Analyze a $I file or a folder of collected artifacts"
    )
    command.add_argument("input", type=Path, help="A $I file or evidence directory")
    command.add_argument(
        "--recursive", action="store_true", help="Include nested directories (e.g. SID folders)"
    )
    command.add_argument("--format", choices=("table", "json", "csv", "html"), default="table")
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
    command.add_argument(
        "--query", help="Literal case-insensitive search of original/acquired paths"
    )
    command.add_argument(
        "--extension",
        action="append",
        default=[],
        help="Extension filter; repeat for OR, e.g. .pdf",
    )
    command.add_argument("--sid", help="Exact SID context filter (not authenticated identity)")
    command.add_argument(
        "--deleted-after", help="Inclusive UTC date or ISO timestamp with timezone"
    )
    command.add_argument(
        "--deleted-before", help="Inclusive UTC date or ISO timestamp with timezone"
    )
    command.add_argument("--min-size", type=int, help="Minimum recorded original size in bytes")
    command.add_argument("--max-size", type=int, help="Maximum recorded original size in bytes")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command == "gui":
        from .gui import main as gui_main

        return gui_main([])
    source = absolute_path(args.input)
    output = absolute_path(args.output) if args.output else None
    try:
        filters = FilterOptions(
            query=args.query,
            extensions=tuple(args.extension),
            sid=args.sid,
            deleted_after=args.deleted_after,
            deleted_before=args.deleted_before,
            min_size=args.min_size,
            max_size=args.max_size,
        )
        validate_filters(filters)
        if args.timezone != "UTC":
            ZoneInfo(args.timezone)
        if output:
            _validate_output(source, output)
        options = ScanOptions(
            args.recursive, args.hash_payload, args.timezone, args.case_id, args.examiner
        )
        report = scan(source, options, filters)
        if output:
            write_report(report, output, args.format)
            print(f"Report saved: {safe_text(output)}", file=sys.stderr)
        else:
            sys.stdout.write(render(report, args.format))
        summary = report["summary"]
        if summary["errors"] or summary["skipped"]:
            return 1
        return 0 if summary["candidates"] or summary["orphan_payloads"] else 2
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
