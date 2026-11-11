"""Actual CLI boundaries, exclusive output, and machine-readable stdout."""

from __future__ import annotations

import json
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from rbinforensics import __version__, cli


@pytest.fixture
def evidence(tmp_path: Path) -> Path:
    directory = tmp_path.resolve() / "evidence"
    directory.mkdir()
    encoded = (r"C:\Users\Analyst\report.txt" + "\0").encode("utf-16-le")
    (directory / "$IABC.txt").write_bytes(
        struct.pack("<QQQI", 2, 7, 133485408001234567, len(encoded) // 2) + encoded
    )
    (directory / "$RABC.txt").write_bytes(b"payload")
    return directory


@pytest.mark.parametrize("arguments", [["--help"], ["scan", "--help"], ["--version"]])
def test_help_and_version(arguments: list[str], capsys: pytest.CaptureFixture) -> None:
    with pytest.raises(SystemExit) as stopped:
        cli.main(arguments)
    assert stopped.value.code == 0
    assert capsys.readouterr().out


def test_module_entrypoint_smoke() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "rbinforensics", "--version"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert completed.stdout.strip() == f"rbf {__version__}"


def test_default_table_scan(evidence: Path, capsys: pytest.CaptureFixture) -> None:
    assert cli.main(["scan", str(evidence)]) == 0
    captured = capsys.readouterr()
    assert "Original path" in captured.out
    assert "[OK]" in captured.out
    assert captured.err == ""


def test_json_stdout_has_no_progress_noise(evidence: Path, capsys: pytest.CaptureFixture) -> None:
    assert (
        cli.main(
            [
                "scan",
                str(evidence),
                "--format",
                "json",
                "--hash-payload",
                "--case-id",
                "CASE-5",
                "--examiner",
                "Analyst",
            ]
        )
        == 0
    )
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert captured.err == ""
    assert report["summary"]["payloads_hashed"] == 1
    assert report["options"]["case_id"] == "CASE-5"


def test_csv_stdout(evidence: Path, capsys: pytest.CaptureFixture) -> None:
    assert cli.main(["scan", str(evidence), "--format", "csv"]) == 0
    assert capsys.readouterr().out.startswith("source_path,source_sha256,")


def test_report_file_is_new_utf8_and_stdout_empty(
    evidence: Path, capsys: pytest.CaptureFixture
) -> None:
    target = evidence.parent / "report.json"
    assert cli.main(["scan", str(evidence), "--format", "json", "--output", str(target)]) == 0
    assert json.loads(target.read_text("utf-8"))["summary"]["parsed"] == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Report saved:" in captured.err


def test_existing_report_never_overwritten(evidence: Path, capsys: pytest.CaptureFixture) -> None:
    target = evidence.parent / "report.json"
    target.write_text("original")
    assert cli.main(["scan", str(evidence), "--output", str(target)]) == 2
    assert target.read_text() == "original"
    assert "already exists" in capsys.readouterr().err


@pytest.mark.parametrize("single_file", [False, True])
def test_output_cannot_be_written_among_evidence(
    evidence: Path, capsys: pytest.CaptureFixture, single_file: bool
) -> None:
    source = evidence / "$IABC.txt" if single_file else evidence
    target = evidence / "report.json"
    assert cli.main(["scan", str(source), "--output", str(target)]) == 2
    assert not target.exists()
    assert "outside the evidence directory" in capsys.readouterr().err


def test_output_parent_must_exist(evidence: Path, capsys: pytest.CaptureFixture) -> None:
    target = evidence.parent / "missing" / "report.json"
    assert cli.main(["scan", str(evidence), "--output", str(target)]) == 2
    assert "parent directory must already exist" in capsys.readouterr().err


def test_symlink_output_parent_cannot_redirect_into_evidence(
    evidence: Path, capsys: pytest.CaptureFixture
) -> None:
    alias = evidence.parent / "alias"
    try:
        alias.symlink_to(evidence, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Creating symlinks unavailable for this OS/user.")
    assert cli.main(["scan", str(evidence), "--output", str(alias / "report.json")]) == 2
    assert not (evidence / "report.json").exists()
    assert "Symlink" in capsys.readouterr().err


def test_symlink_skip_makes_cli_report_incomplete(
    evidence: Path, capsys: pytest.CaptureFixture
) -> None:
    try:
        (evidence / "$ILINK.txt").symlink_to(evidence / "$IABC.txt")
    except (OSError, NotImplementedError):
        pytest.skip("Creating symlinks unavailable for this OS/user.")
    assert cli.main(["scan", str(evidence), "--format", "json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["skipped"] == 1
    assert report["summary"]["parsed"] == 1


def test_unknown_timezone_is_friendly_usage_error(
    evidence: Path, capsys: pytest.CaptureFixture
) -> None:
    assert cli.main(["scan", str(evidence), "--timezone", "NoSuch/Zone"]) == 2
    assert "timezone" in capsys.readouterr().err


def test_missing_input_is_friendly_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    assert cli.main(["scan", str(tmp_path.resolve() / "missing")]) == 2
    assert "rbf:" in capsys.readouterr().err


def test_empty_scan_returns_two_with_report(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    assert cli.main(["scan", str(tmp_path.resolve()), "--format", "json"]) == 2
    assert json.loads(capsys.readouterr().out)["summary"]["candidates"] == 0


def test_corrupt_file_returns_one_and_preserves_good_result(
    evidence: Path, capsys: pytest.CaptureFixture
) -> None:
    (evidence / "$IBAD").write_bytes(b"bad")
    assert cli.main(["scan", str(evidence), "--format", "json"]) == 1
    summary = json.loads(capsys.readouterr().out)["summary"]
    assert summary["errors"] == 1
    assert summary["parsed"] == 1


def test_warning_only_scan_returns_zero(evidence: Path, capsys: pytest.CaptureFixture) -> None:
    (evidence / "$RABC.txt").write_bytes(b"mismatch")
    assert cli.main(["scan", str(evidence), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["summary"]["warnings"] == 1


def test_recursive_option_passed_to_scanner(evidence: Path, capsys: pytest.CaptureFixture) -> None:
    child = evidence / "nested"
    child.mkdir()
    (evidence / "$IABC.txt").rename(child / "$IABC.txt")
    assert cli.main(["scan", str(evidence), "--recursive", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["summary"]["parsed"] == 1


def test_failed_report_write_removes_partial_file(
    evidence: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    target = evidence.parent / "report.json"

    def fail_sync(_: int) -> None:
        raise OSError("disk failure")

    monkeypatch.setattr(cli.os, "fsync", fail_sync)
    assert cli.main(["scan", str(evidence), "--output", str(target)]) == 2
    assert not target.exists()
    assert "disk failure" in capsys.readouterr().err


def test_interrupted_scan_returns_130(
    evidence: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    def interrupt(*_):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "scan", interrupt)
    assert cli.main(["scan", str(evidence)]) == 130
    assert "scan incomplete" in capsys.readouterr().err


@pytest.mark.parametrize("arguments", [[], ["scan"], ["scan", ".", "--format", "xml"]])
def test_argparse_usage_errors(arguments: list[str]) -> None:
    with pytest.raises(SystemExit) as stopped:
        cli.main(arguments)
    assert stopped.value.code == 2
