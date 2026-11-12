"""Stage verified release assets without replacing earlier output.

The Windows executable must already have been built and exercised on Windows.
This helper checks that supplied build's identity; it does not execute an EXE
on a different platform or turn a recorded smoke test into new validation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import stat
import tarfile
import tempfile
import zipfile
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

from rbinforensics import __version__
from rbinforensics.scanner import ensure_no_symlinks

REPOSITORY = "nomatterwhathappns/Recycle-Bin-Forensics"
MAX_UNPACKED = 512 * 1024 * 1024


class ReleaseError(RuntimeError):
    """An asset is incomplete, inconsistent, or unsafe to publish."""


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def regular_file(path: Path) -> None:
    ensure_no_symlinks(path)
    if not path.is_file():
        raise ReleaseError(f"Required regular file is absent: {path.name}")


def safe_member(name: str) -> bool:
    path = PurePosixPath(name)
    return bool(name) and not (
        path.is_absolute()
        or ".." in path.parts
        or "\\" in name
        or ":" in name
        or "\x00" in name
        or any(ord(character) < 32 for character in name)
    )


def check_zip(bundle: zipfile.ZipFile) -> None:
    names = set()
    size = 0
    for entry in bundle.infolist():
        key = entry.filename.casefold()
        mode = entry.external_attr >> 16
        if (
            not safe_member(entry.filename)
            or key in names
            or stat.S_ISLNK(mode)
            or stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR)
            or (entry.create_system == 0 and entry.external_attr & 0x400)
            or entry.flag_bits & 1
        ):
            raise ReleaseError("An archive contains an unsafe or duplicate member.")
        names.add(key)
        size += entry.file_size
        if size > MAX_UNPACKED:
            raise ReleaseError("An archive exceeds the release verification size limit.")
    if bundle.testzip() is not None:
        raise ReleaseError("An archive failed its CRC check.")


def read_checksums(path: Path) -> dict[str, str]:
    regular_file(path)
    entries = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)", line)
        if match is None or match[2] in entries or match[2] == "SHA256SUMS.txt":
            raise ReleaseError("Checksum entries must be unique safe filenames and SHA-256 values.")
        entries[match[2]] = match[1]
    if not entries:
        raise ReleaseError("The checksum file is empty.")
    return entries


def verify_checksums(directory: Path) -> None:
    ensure_no_symlinks(directory)
    expected = read_checksums(directory / "SHA256SUMS.txt")
    actual = {path.name for path in directory.iterdir()}
    if actual != set(expected) | {"SHA256SUMS.txt"}:
        raise ReleaseError("The release directory has missing or unlisted assets.")
    for name, value in expected.items():
        path = directory / name
        regular_file(path)
        if digest(path) != value:
            raise ReleaseError(f"Checksum mismatch: {name}")


def verify_windows(archive: Path, checksum: Path, commit: str) -> dict:
    regular_file(archive)
    expected_name = f"RecycleBinForensics-{__version__}-windows-x64.zip"
    if archive.name != expected_name:
        raise ReleaseError("Windows archive name does not match the application version.")
    expected = read_checksums(checksum)
    if expected != {expected_name: digest(archive)}:
        raise ReleaseError("Windows archive checksum does not match its build checksum file.")
    with zipfile.ZipFile(archive) as bundle:
        check_zip(bundle)
        base = "RecycleBinForensics/"
        names = bundle.namelist()
        if any(not name.startswith(base) for name in names):
            raise ReleaseError("Windows archive has files outside its application folder.")
        if not any(name.startswith(base + "_internal/") for name in names):
            raise ReleaseError("Windows archive lacks its bundled runtime.")
        information = json.loads(bundle.read(base + "BUILD-INFO.json"))
        if not isinstance(information, dict) or (
            information.get("version") != __version__
            or information.get("commit") != commit
            or information.get("platform") != "windows-x64"
        ):
            raise ReleaseError("Windows build version, platform, or source commit differs.")
        smoke = information.get("smoke_test")
        if not isinstance(smoke, dict) or (
            smoke.get("status") != "ok"
            or smoke.get("version") != __version__
            or not isinstance(smoke.get("tk_version"), str)
            or not smoke["tk_version"]
            or not isinstance(smoke.get("checks"), dict)
            or not all(
                smoke["checks"].get(key) is True
                for key in ("tk", "parser", "widgets", "timezone", "export")
            )
        ):
            raise ReleaseError("Windows build does not record the complete successful smoke test.")
        with bundle.open(base + "RecycleBinForensics.exe") as executable:
            if executable.read(2) != b"MZ":
                raise ReleaseError("Windows executable does not contain its expected PE header.")
        for license_name in ("LICENSE", "THIRD_PARTY_LICENSES.txt", "START_HERE.txt"):
            if not bundle.read(base + license_name).strip():
                raise ReleaseError("Windows distribution is missing a license or startup notice.")
    return information


def source_assets(directory: Path) -> list[Path]:
    wheel = directory / f"rbinforensics-{__version__}-py3-none-any.whl"
    source = directory / f"rbinforensics-{__version__}.tar.gz"
    for path in (wheel, source):
        regular_file(path)
    with zipfile.ZipFile(wheel) as bundle:
        check_zip(bundle)
        metadata = bundle.read(f"rbinforensics-{__version__}.dist-info/METADATA")
        if BytesParser().parsebytes(metadata)["Version"] != __version__:
            raise ReleaseError("Wheel metadata version differs from the release.")
    with tarfile.open(source, "r:gz") as bundle:
        entries = bundle.getmembers()
        names = [entry.name.casefold() for entry in entries]
        if (
            sum(entry.size for entry in entries) > MAX_UNPACKED
            or any(
                not safe_member(entry.name)
                or not entry.name.startswith(f"rbinforensics-{__version__}/")
                and entry.name != f"rbinforensics-{__version__}"
                or not (entry.isfile() or entry.isdir())
                for entry in entries
            )
            or len(names) != len(set(names))
        ):
            raise ReleaseError("Source distribution contains unsafe archive members.")
        metadata_stream = bundle.extractfile(f"rbinforensics-{__version__}/PKG-INFO")
        if metadata_stream is None:
            raise ReleaseError("Source distribution has no package metadata.")
        with metadata_stream:
            if BytesParser().parsebytes(metadata_stream.read())["Version"] != __version__:
                raise ReleaseError("Source distribution version differs from the release.")
    return [wheel, source]


def demo_archive(destination: Path) -> None:
    # The examples namespace belongs to the source checkout, not the wheel.
    from examples.corpus import generate_corpus, verify_corpus

    with tempfile.TemporaryDirectory(prefix="rbf-release-demo-") as temporary:
        corpus = Path(temporary) / "synthetic-corpus"
        generate_corpus(corpus)
        if verify_corpus(corpus).get("status") != "passed":
            raise ReleaseError("Synthetic corpus verification failed before packaging.")
        with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED) as bundle:
            for path in sorted(corpus.rglob("*")):
                ensure_no_symlinks(path)
                name = "synthetic-corpus/" + path.relative_to(corpus).as_posix()
                entry = zipfile.ZipInfo(
                    name + ("/" if path.is_dir() else ""), date_time=(2026, 1, 1, 0, 0, 0)
                )
                entry.compress_type = zipfile.ZIP_DEFLATED
                entry.create_system = 3
                entry.external_attr = (
                    (stat.S_IFDIR | 0o755) if path.is_dir() else (stat.S_IFREG | 0o644)
                ) << 16
                bundle.writestr(entry, b"" if path.is_dir() else path.read_bytes())


def read_report(path: Path) -> dict:
    regular_file(path)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*\.json", path.name):
        raise ReleaseError("Report assets require safe JSON filenames.")
    if path.stat().st_size > 32 * 1024 * 1024:
        raise ReleaseError("Report asset exceeds the 32 MiB publication limit.")
    report = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(report, dict) or (
        report.get("schema_version") != "1.0"
        or report.get("application_version") != __version__
        or report.get("report_kind") not in ("benchmark", "reference_validation")
    ):
        raise ReleaseError("Report schema, kind, or application version differs from this release.")
    if report["report_kind"] == "reference_validation":
        summary = report.get("summary")
        if not isinstance(summary, dict) or (
            report.get("status") != "passed"
            or summary.get("unexplained_differences") != 0
            or summary.get("ground_truth_differences") != 0
            or not isinstance(summary.get("compared_records"), int)
            or summary["compared_records"] <= 0
        ):
            raise ReleaseError(
                "Reference report must have actual comparisons and no unexplained differences."
            )
    elif report.get("status") != "completed":
        raise ReleaseError("Benchmark report must record a completed measurement run.")
    return report


def prepare_release(
    windows_zip: Path,
    windows_checksum: Path,
    dist_dir: Path,
    output: Path,
    commit: str,
    *,
    tag: str | None = None,
    reports: list[Path] | None = None,
) -> list[str]:
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ReleaseError("Supply the full lowercase 40-character source commit SHA.")
    if tag is not None and tag != "v" + __version__:
        raise ReleaseError("Release tag differs from the application version.")
    ensure_no_symlinks(output)
    if output.exists():
        raise ReleaseError("Release output already exists; choose a new directory.")
    if not output.parent.is_dir():
        raise ReleaseError("The release output parent directory must already exist.")
    verify_windows(windows_zip, windows_checksum, commit)
    inputs = [windows_zip, *source_assets(dist_dir)]
    reports = reports or []
    report_values = [read_report(path) for path in reports]
    inputs.extend(reports)
    reserved = {"RELEASE-NOTES.md", "SHA256SUMS.txt", f"RecycleBinForensics-{__version__}-demo.zip"}
    names = [path.name.casefold() for path in inputs]
    if len(names) != len(set(names)) or any(
        name in reserved for name in (path.name for path in inputs)
    ):
        raise ReleaseError("Release inputs have duplicate or reserved asset names.")
    with tempfile.TemporaryDirectory(prefix="rbf-release-stage-", dir=output.parent) as temporary:
        staging = Path(temporary)
        for path in inputs:
            shutil.copyfile(path, staging / path.name)
        # Recheck copied bytes: changes during copying must not acquire new
        # release checksums without passing the same publication gates.
        verify_windows(staging / windows_zip.name, windows_checksum, commit)
        source_assets(staging)
        for path, value in zip(reports, report_values, strict=True):
            if read_report(staging / path.name) != value:
                raise ReleaseError("A measurement report changed while release assets were staged.")
        demo_archive(staging / f"RecycleBinForensics-{__version__}-demo.zip")
        notes = (
            f"Recycle Bin Forensics {__version__}\n\n"
            f"Source commit: `{commit}`. JSON reports retain schema 2.0.\n\n"
            "This release includes the Windows x64 portable application, Python wheel/source "
            "distribution, and a deterministic synthetic validation/demo corpus. Extract the "
            "complete Windows ZIP before launching its executable.\n\n"
            "The corpus contains deliberate malformed/missing-payload cases; verification "
            "checks their expected outcomes. It is synthetic and contains no acquired user data. "
            "The corpus verifier's successful result differs from a clean scan of every item.\n\n"
            "SHA256SUMS.txt identifies every downloadable asset. It is not a publisher signature. "
            "The Windows build records successful native startup, parser, widget, timezone, "
            "and export checks in BUILD-INFO.json.\n\n"
            f"[Desktop instructions](https://github.com/{REPOSITORY}/blob/v{__version__}/docs/DESKTOP.md) "
            f"· [Dataset](https://github.com/{REPOSITORY}/blob/v{__version__}/docs/DATASET.md) "
            f"· [Reference validation](https://github.com/{REPOSITORY}/blob/v{__version__}/docs/VALIDATION_REFERENCE.md) "
            f"· [Benchmarks](https://github.com/{REPOSITORY}/blob/v{__version__}/docs/BENCHMARKS.md)\n"
        )
        if report_values:
            notes += "\nIncluded measurement reports:\n"
            for path, report in zip(reports, report_values, strict=True):
                notes += f"\n- `{path.name}`: {report['report_kind']}."
                if report["report_kind"] == "reference_validation":
                    summary = report["summary"]
                    notes += (
                        f" {summary['compared_records']} records compared; "
                        f"{summary.get('documented_reference_differences', 0)} documented "
                        "reference differences; zero unexplained or ground-truth differences. "
                        "Timestamp cross-comparison is limited to whole UTC seconds. "
                        "rifiuti2 0.8.2 represents uint64-max size as -1 and zero FILETIME "
                        "as the 1601 epoch; these documented edge differences are retained "
                        "in the detailed report, not counted as exact matches."
                    )
            notes += "\n"
        (staging / "RELEASE-NOTES.md").write_text(notes, encoding="utf-8", newline="\n")
        checksums = "".join(f"{digest(path)}  {path.name}\n" for path in sorted(staging.iterdir()))
        (staging / "SHA256SUMS.txt").write_text(checksums, encoding="utf-8", newline="\n")
        verify_checksums(staging)
        output.mkdir(exist_ok=False)
        created = []
        try:
            for path in sorted(staging.iterdir()):
                target = output / path.name
                with target.open("xb") as stream, path.open("rb") as source:
                    created.append(target)
                    shutil.copyfileobj(source, stream)
            verify_checksums(output)
        except BaseException:
            for path in created:
                path.unlink(missing_ok=True)
            output.rmdir()
            raise
    return sorted(path.name for path in output.iterdir())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--windows-zip", type=Path, required=True)
    parser.add_argument("--windows-checksum", type=Path, required=True)
    parser.add_argument("--dist-dir", type=Path, default=Path("dist"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tag")
    parser.add_argument("--report", action="append", default=[], type=Path)
    args = parser.parse_args(argv)
    try:
        assets = prepare_release(
            args.windows_zip,
            args.windows_checksum,
            args.dist_dir,
            args.output,
            args.commit,
            tag=args.tag,
            reports=args.report,
        )
    except (
        ReleaseError,
        OSError,
        ValueError,
        KeyError,
        zipfile.BadZipFile,
        tarfile.TarError,
    ) as exc:
        parser.exit(1, f"Release preparation failed: {exc}\n")
    print("Verified release assets:\n" + "\n".join(assets))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
