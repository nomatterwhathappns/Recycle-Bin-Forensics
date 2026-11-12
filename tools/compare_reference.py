"""Compare supplied $I bytes with an independently implemented rifiuti2 parser.

Run from a source checkout after installing this project. The reference program
is supplied separately; it is never downloaded or executed implicitly. XML is
used because rifiuti2 0.8.2's JSON renderer emits trailing commas. Each input is
processed independently, preserving malformed-record diagnostics.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path, PurePosixPath, PureWindowsPath
from xml.etree import ElementTree

from rbinforensics import __version__
from rbinforensics.output import validate_output
from rbinforensics.parser import ParseError, parse_metadata
from rbinforensics.scanner import ensure_no_symlinks

PINNED_ARCHIVE_URL = "https://deb.debian.org/debian/pool/main/r/rifiuti2/rifiuti2_0.8.2-1_amd64.deb"
PINNED_ARCHIVE_SHA256 = "00c273928431c14ab315886964690c26fc68762f40443ea69a9de334037ae83f"
PINNED_EXECUTABLE_SHA256 = "d3e87d37d2adf99e4788261aff1ae8e5bf63c4abac2864c9ea4dd9e018507c44"
MAX_METADATA_BYTES = 1_048_576
COMPARED_FIELDS = ("format_version", "original_path", "original_size", "deleted_at_utc")
METADATA_FIELDS = {*COMPARED_FIELDS, "deletion_filetime"}


class ReferenceError(ValueError):
    """The supplied data or reference protocol could not be checked."""


def _integer(value: object, *, maximum: int = (1 << 64) - 1) -> bool:
    return type(value) is int and 0 <= value <= maximum


def _digest(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _relative(value: object) -> PurePosixPath:
    if not isinstance(value, str) or not value or value == ".":
        raise ReferenceError("Corpus source must be a safe relative POSIX path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or ".." in path.parts
        or "\\" in value
        or ":" in value
        or value != path.as_posix()
    ):
        raise ReferenceError("Corpus source must be a safe relative POSIX path")
    return path


def _safe_bytes(path: Path) -> bytes:
    ensure_no_symlinks(path)
    information = path.stat()
    if not stat.S_ISREG(information.st_mode):
        raise ReferenceError(f"Input must be a regular file: {path}")
    if information.st_size > MAX_METADATA_BYTES:
        raise ReferenceError(f"Input exceeds {MAX_METADATA_BYTES} bytes: {path}")
    return path.read_bytes()


def parse_rifiuti_xml(text: str, source_name: str) -> dict:
    """Decode exactly one reference record, retaining integer sizes exactly."""
    try:
        root = ElementTree.fromstring(text)
        records = root.findall("record")
        if root.tag != "recyclebin" or root.get("format") != "dir" or len(records) != 1:
            raise ReferenceError("Reference output must contain exactly one Vista-style record")
        record = records[0]
        if record.get("index") != source_name:
            raise ReferenceError("Reference record does not identify the requested input")
        path = record.find("path")
        if path is None:
            raise ReferenceError("Reference output has no original path")
        timestamp = record.attrib["time"]
        if not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", timestamp):
            raise ReferenceError("Reference timestamp is not whole-second UTC")
        return {
            "format_version": int(root.attrib["version"]),
            "original_path": path.text or "",
            "original_size": int(record.attrib["size"]),
            "deleted_at_utc": timestamp,
        }
    except (ElementTree.ParseError, KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, ReferenceError):
            raise
        raise ReferenceError(f"Invalid rifiuti2 XML: {exc}") from exc


def _whole_second(value: str | None) -> str | None:
    return value.split(".", 1)[0] + "Z" if value and "." in value else value


def _known_difference(field: str, actual: object, reference: object, version: str) -> str | None:
    if version != "0.8.2":
        return None
    if (
        field == "original_size"
        and isinstance(actual, int)
        and actual == (1 << 64) - 1
        and reference == -1
    ):
        return "rifiuti2 0.8.2 formats unsigned QWORD sizes through a signed 64-bit value"
    return None


def compare_values(rbf: dict, reference: dict, version: str) -> list[dict]:
    """Report differences without rounding numeric values or concealing limits."""
    differences = []
    for field in COMPARED_FIELDS:
        actual = _whole_second(rbf.get(field)) if field == "deleted_at_utc" else rbf.get(field)
        other = reference.get(field)
        if actual != other:
            reason = _known_difference(field, actual, other, version)
            # This exception is intentionally tied to the raw zero sentinel,
            # rather than accepting every missing/out-of-range RBF timestamp.
            if (
                version == "0.8.2"
                and field == "deleted_at_utc"
                and rbf.get("deletion_filetime") == 0
                and actual is None
                and other == "1601-01-01T00:00:00Z"
            ):
                reason = (
                    "RBF treats zero FILETIME as unknown; rifiuti2 0.8.2 renders the epoch "
                    "and flags a suspicious deletion time"
                )
            differences.append(
                {
                    "field": field,
                    "rbf": actual,
                    "reference": other,
                    "classification": "documented_reference_difference"
                    if reason
                    else "unexplained",
                    "reason": reason,
                }
            )
    return differences


def reference_identity(executable: Path) -> dict:
    ensure_no_symlinks(executable)
    if not executable.is_file():
        raise ReferenceError("Reference executable does not exist or is not a regular file")
    run = subprocess.run(
        [str(executable), "--version"], capture_output=True, timeout=15, check=True
    )
    output = run.stdout.decode("utf-8", errors="strict")
    match = re.match(r"rifiuti2 ([0-9]+\.[0-9]+\.[0-9]+)(?:\s|$)", output)
    if match is None:
        raise ReferenceError("Reference executable did not identify itself as rifiuti2")
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    return {
        "name": "rifiuti2/rifiuti-vista",
        "version": match.group(1),
        "executable_sha256": digest,
        "matches_pinned_debian_executable": digest == PINNED_EXECUTABLE_SHA256,
        "output_format": "XML",
        "timestamp_precision": "whole UTC seconds; fractional FILETIME ticks are not compared",
    }


def _reference_output(source: Path, executable: Path, expected_digest: str) -> tuple[int, str, str]:
    run = subprocess.run(
        [str(executable), "--format=xml", str(source)],
        capture_output=True,
        timeout=30,
        check=False,
        env={**os.environ, "LC_ALL": "C.UTF-8", "TZ": "UTC"},
    )
    if hashlib.sha256(_safe_bytes(source)).hexdigest() != expected_digest:
        raise ReferenceError("Input changed between RBF and reference reads")
    return (
        run.returncode,
        run.stdout.decode("utf-8", errors="strict"),
        run.stderr.decode("utf-8", errors="replace").strip(),
    )


def _malformed_diagnostic(source: Path, executable: Path, expected_digest: str) -> dict:
    code, output, diagnostics = _reference_output(source, executable, expected_digest)
    try:
        root = ElementTree.fromstring(output)
        decoded = len(root.findall("record")) if root.tag == "recyclebin" else None
    except ElementTree.ParseError:
        decoded = None
    return {
        "reference_exit_code": code,
        "reference_diagnostics": diagnostics,
        "reference_records_emitted": decoded,
        "reference_output_sha256": hashlib.sha256(output.encode("utf-8")).hexdigest(),
        "interpretation": "Diagnostic only; malformed-input behavior is not a field agreement",
    }


def compare_file(
    source: Path, executable: Path, version: str, *, expected: dict | None = None
) -> dict:
    data = _safe_bytes(source)
    result = {
        "source": str(source),
        "source_sha256": hashlib.sha256(data).hexdigest(),
        "source_bytes": len(data),
        "compared_fields": list(COMPARED_FIELDS),
        "differences": [],
        "ground_truth_differences": [],
    }
    try:
        metadata = asdict(parse_metadata(data))
    except ParseError as exc:
        result.update(status="not_comparable", rbf_error_code=exc.code, compared_fields=[])
        result.update(_malformed_diagnostic(source, executable, result["source_sha256"]))
        return result
    result["rbf"] = metadata
    if expected is not None:
        result["ground_truth_differences"] = [
            {"field": field, "expected": value, "rbf": metadata.get(field)}
            for field, value in expected.items()
            if metadata.get(field) != value
        ]
    code, output, diagnostics = _reference_output(source, executable, result["source_sha256"])
    result["reference_exit_code"] = code
    result["reference_diagnostics"] = diagnostics
    # rifiuti2 returns 5 when a decoded record carries warnings. Its record is
    # still compared and every diagnostic is retained. Other failures are fatal.
    if code not in (0, 5):
        raise ReferenceError(f"Reference failed for {source.name}: exit {code}")
    reference = parse_rifiuti_xml(output, source.name)
    result["reference"] = reference
    result["differences"] = compare_values(metadata, reference, version)
    result["status"] = (
        "different"
        if result["differences"] or result["ground_truth_differences"]
        else "match_with_reference_warning"
        if code == 5
        else "match"
    )
    return result


def corpus_inputs(directory: Path) -> tuple[list[dict], dict]:
    """Check the supplied manifest's source digests before comparing its cases."""
    manifest_bytes = _safe_bytes(directory / "manifest.json")
    manifest = json.loads(manifest_bytes)
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema_version") != "1.0"
        or manifest.get("corpus_id") != "rbf-synthetic-v1"
    ):
        raise ReferenceError("Unsupported synthetic corpus manifest")
    if not isinstance(manifest.get("files"), list) or not isinstance(manifest.get("cases"), list):
        raise ReferenceError("Corpus manifest files/cases must be lists")
    files = {}
    for entry in manifest["files"]:
        if (
            not isinstance(entry, dict)
            or not _integer(entry.get("size"))
            or not _digest(entry.get("sha256"))
        ):
            raise ReferenceError("Invalid corpus file entry")
        key = str(_relative(entry.get("path")))
        if key in files:
            raise ReferenceError("Duplicate corpus file entry")
        files[key] = entry
    cases = []
    seen = set()
    for case in manifest["cases"]:
        if (
            not isinstance(case, dict)
            or not isinstance(case.get("id"), str)
            or not case["id"]
            or case["id"] in seen
            or case.get("record_type") not in ("metadata", "orphan_payload")
            or not isinstance(case.get("expected"), dict)
        ):
            raise ReferenceError("Invalid or duplicate corpus case entry")
        seen.add(case["id"])
        path = _relative(case.get("source"))
        if case["record_type"] != "metadata":
            cases.append({"id": case["id"], "skip": "Orphan payload has no $I metadata to compare"})
            continue
        source = directory.joinpath(*path.parts)
        data = _safe_bytes(source)
        if case["source"] not in files or "metadata" not in case["expected"]:
            raise ReferenceError("Corpus metadata source/expected fields are missing")
        recorded = files[case["source"]]
        if hashlib.sha256(data).hexdigest() != recorded["sha256"] or len(data) != recorded["size"]:
            raise ReferenceError(f"Corpus input digest/size differs from manifest: {case['id']}")
        if case["expected"].get("metadata") is None:
            cases.append(
                {
                    "id": case["id"],
                    "source": source,
                    "relative_source": case["source"],
                    "malformed": True,
                    "expected_sha256": recorded["sha256"],
                }
            )
            continue
        expected = case["expected"]["metadata"]
        if (
            not isinstance(expected, dict)
            or not METADATA_FIELDS.issubset(expected)
            or expected.get("format_version") not in (1, 2)
            or type(expected.get("format_version")) is not int
            or not isinstance(expected.get("original_path"), str)
            or not _integer(expected.get("original_size"))
            or not _integer(expected.get("deletion_filetime"))
            or (
                expected.get("deleted_at_utc") is not None
                and not isinstance(expected["deleted_at_utc"], str)
            )
        ):
            raise ReferenceError("Invalid corpus expected metadata fields")
        cases.append(
            {
                "id": case["id"],
                "source": source,
                "relative_source": case["source"],
                "expected": case["expected"]["metadata"],
                "expected_sha256": recorded["sha256"],
                "ground_truth_kind": "synthetic_manifest",
            }
        )
    return cases, {
        "corpus_id": manifest["corpus_id"],
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "kind": "synthetic; not a Windows acquisition",
    }


def windows_samples_inputs(directory: Path, *, expected_count: int = 2) -> tuple[list[dict], dict]:
    """Bind copied Shell samples to independent, pre-recycle sample facts."""
    if type(expected_count) is not int or expected_count < 1:
        raise ReferenceError("Expected Windows sample count must be a positive integer")
    ensure_no_symlinks(directory)
    if not directory.is_dir():
        raise ReferenceError("Windows sample root must be an existing directory")
    entries = sorted(directory.iterdir())
    if len(entries) != expected_count:
        raise ReferenceError(
            f"Expected {expected_count} Windows sample cases, found {len(entries)}"
        )
    inputs = []
    for case in entries:
        ensure_no_symlinks(case)
        if not case.is_dir():
            raise ReferenceError("Each Windows sample case must be a directory")
        provenance_bytes = _safe_bytes(case / "provenance.json")
        provenance = json.loads(provenance_bytes)
        if not isinstance(provenance, dict):
            raise ReferenceError("Windows sample provenance must be an object")
        name = provenance.get("metadata_name")
        original_path = provenance.get("original_path")
        lower = provenance.get("deletion_lower_bound_filetime")
        upper = provenance.get("deletion_upper_bound_filetime")
        if (
            provenance.get("sample_kind") != "controlled_windows_shell"
            or not isinstance(name, str)
            or not name.startswith("$I")
            or len(name) <= 2
            or any(character in name for character in "/\\:\0")
            or not _digest(provenance.get("metadata_sha256"))
            or not _digest(provenance.get("payload_sha256"))
            or not isinstance(provenance.get("windows_build"), str)
            or not provenance["windows_build"]
            or not isinstance(original_path, str)
            or not PureWindowsPath(original_path).is_absolute()
            or not _integer(provenance.get("original_size"))
            or not _integer(lower)
            or not _integer(upper)
            or lower > upper
        ):
            raise ReferenceError("Invalid controlled Windows sample provenance")
        if {item.name for item in case.iterdir()} != {name, "provenance.json"}:
            raise ReferenceError("Windows case contains missing or unbound sample files")
        source = case / name
        digest = hashlib.sha256(_safe_bytes(source)).hexdigest()
        if digest != provenance["metadata_sha256"]:
            raise ReferenceError("Windows sample metadata digest differs from provenance")
        inputs.append(
            {
                "id": case.name,
                "source": source,
                "relative_source": source.relative_to(directory).as_posix(),
                "expected": {
                    "original_path": original_path,
                    "original_size": provenance["original_size"],
                },
                "expected_sha256": digest,
                "expected_time_window": {"lower": lower, "upper": upper},
                "ground_truth_kind": "controlled_windows_shell",
                "provenance": provenance,
                "provenance_sha256": hashlib.sha256(provenance_bytes).hexdigest(),
            }
        )
    return inputs, {
        "kind": "controlled_windows_shell",
        "expected_sample_count": expected_count,
        "scope": "Independently known original path, size, and pre/post-recycle clock interval",
    }


def run_comparison(
    executable: Path,
    inputs: list[dict],
    *,
    corpus: dict | None = None,
    windows_samples: dict | None = None,
    allow_known_differences: bool = False,
) -> dict:
    identity = reference_identity(executable)
    results, excluded = [], []
    for entry in inputs:
        if "skip" in entry:
            excluded.append({"id": entry["id"], "reason": entry["skip"]})
            continue
        result = compare_file(
            entry["source"], executable, identity["version"], expected=entry.get("expected")
        )
        result["id"] = entry["id"]
        result["source"] = entry.get("relative_source", str(entry["source"]))
        if entry.get("expected_sha256") not in (None, result["source_sha256"]):
            raise ReferenceError("Compared input bytes differ from their bound manifest/provenance")
        result["ground_truth_checked"] = entry.get("expected") is not None
        if result["ground_truth_checked"]:
            result["ground_truth"] = {
                "kind": entry.get("ground_truth_kind", "supplied_expected_values"),
                "expected_fields": entry["expected"],
                "deletion_filetime_interval": entry.get("expected_time_window"),
            }
        if "provenance" in entry:
            result["provenance"] = entry["provenance"]
            result["provenance_sha256"] = entry["provenance_sha256"]
        if result["status"] == "not_comparable":
            if entry.get("expected") is not None:
                raise ReferenceError("Known-valid expected metadata was rejected by the RBF parser")
            excluded.append(result)
        else:
            if entry.get("malformed"):
                raise ReferenceError(
                    "A deliberately malformed corpus input was unexpectedly decoded"
                )
            window = entry.get("expected_time_window")
            if window is not None:
                tick = result["rbf"]["deletion_filetime"]
                if not window["lower"] <= tick <= window["upper"]:
                    result["ground_truth_differences"].append(
                        {
                            "field": "deletion_filetime",
                            "expected_interval": window,
                            "rbf": tick,
                        }
                    )
                    result["status"] = "different"
            results.append(result)
    if not results:
        raise ReferenceError(
            "No decoded metadata records were compared; refusing an empty validation"
        )
    differences = [item for result in results for item in result["differences"]]
    unexplained = sum(item["classification"] == "unexplained" for item in differences)
    known = len(differences) - unexplained
    ground_truth = sum(len(result["ground_truth_differences"]) for result in results)
    success = not unexplained and not ground_truth and (not known or allow_known_differences)
    return {
        "schema_version": "1.0",
        "report_kind": "reference_validation",
        "status": "passed" if success else "different",
        "application_version": __version__,
        "commit": os.environ.get("GITHUB_SHA"),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "reference": identity,
        "corpus": corpus,
        "windows_samples": windows_samples,
        "scope": {
            "fields": list(COMPARED_FIELDS),
            "time_comparison": "whole UTC seconds only",
            "not_cross_validated": [
                "subsecond FILETIME precision and raw ticks",
                "payload pairing, hashing, inventory, filters, or exports",
                "malformed input acceptance or complete Windows-version compatibility",
            ],
            "allow_documented_reference_differences": allow_known_differences,
            "ground_truth": (
                "independent expected fields checked for every decoded record"
                if all(result["ground_truth_checked"] for result in results)
                else "not checked for raw --input records; agreement between parsers only"
            ),
        },
        "summary": {
            "compared_records": len(results),
            "matching_records": sum(
                not result["differences"] and not result["ground_truth_differences"]
                for result in results
            ),
            "excluded_records": len(excluded),
            "documented_reference_differences": known,
            "unexplained_differences": unexplained,
            "ground_truth_differences": ground_truth,
            "ground_truth_checked_records": sum(
                result["ground_truth_checked"] for result in results
            ),
            "reference_warning_records": sum(
                result["reference_exit_code"] == 5 for result in results
            ),
        },
        "results": results,
        "excluded": excluded,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--corpus", type=Path, help="Generated synthetic corpus root")
    group.add_argument("--input", action="append", type=Path, help="One $I file; repeat as needed")
    group.add_argument(
        "--windows-samples", type=Path, help="Copied controlled Windows cases with provenance.json"
    )
    parser.add_argument(
        "--expected-samples", type=int, help="Expected Windows case count (positive; default 2)"
    )
    parser.add_argument("--reference", type=Path, help="Existing rifiuti-vista executable")
    parser.add_argument(
        "--output", type=Path, help="New JSON output file outside all input directories"
    )
    parser.add_argument(
        "--allow-known-differences",
        action="store_true",
        help="Permit only explicitly documented rifiuti2 0.8.2 size/zero-time differences",
    )
    args = parser.parse_args(argv)
    if args.expected_samples is not None and (
        args.windows_samples is None or args.expected_samples < 1
    ):
        parser.error("--expected-samples requires --windows-samples and a positive count")
    try:
        supplied = (
            str(args.reference) if args.reference is not None else shutil.which("rifiuti-vista")
        )
        if supplied is None:
            raise ReferenceError("Supply --reference or install rifiuti-vista on PATH")
        executable = Path(supplied).absolute()
        windows_samples = None
        if args.corpus is not None:
            inputs, corpus = corpus_inputs(args.corpus)
            sources = [args.corpus]
        elif args.windows_samples is not None:
            inputs, windows_samples = windows_samples_inputs(
                args.windows_samples,
                expected_count=args.expected_samples if args.expected_samples is not None else 2,
            )
            corpus = None
            sources = [args.windows_samples]
        else:
            inputs = [{"id": f"input-{i + 1}", "source": path} for i, path in enumerate(args.input)]
            corpus = None
            sources = args.input
        if args.output is not None:
            for source in sources:
                validate_output(
                    source,
                    args.output,
                    source_was_file=args.corpus is None and args.windows_samples is None,
                )
        report = run_comparison(
            executable,
            inputs,
            corpus=corpus,
            windows_samples=windows_samples,
            allow_known_differences=args.allow_known_differences,
        )
        rendered = json.dumps(report, ensure_ascii=True, indent=2) + "\n"
        if args.output is not None:
            with args.output.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(rendered)
        else:
            print(rendered, end="")
        return 0 if report["status"] == "passed" else 1
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        subprocess.SubprocessError,
    ) as exc:
        print(f"Reference comparison could not complete: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
