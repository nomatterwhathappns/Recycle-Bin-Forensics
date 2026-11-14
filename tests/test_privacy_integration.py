"""Explicit sharing exports scrub report/manifest pairs without acknowledging an audit save."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import stat
import struct
from pathlib import Path
from queue import Empty

import pytest

from rbinforensics import cli, output
from rbinforensics.analysis import FilterOptions
from rbinforensics.desktop import DesktopSession
from rbinforensics.limits import WorkLimitExceeded, WorkLimits
from rbinforensics.manifest import verify_export
from rbinforensics.scanner import EvidenceError, ScanOptions

PRIVATE_SOURCE = "PRIVATE_SOURCE_SENTINEL"
PRIVATE_ARTIFACT = "PRIVATE_ARTIFACT_SENTINEL"
PRIVATE_USER = "PRIVATE_USER_SENTINEL"
PRIVATE_FILENAME = "PRIVATE_FILENAME_SENTINEL"
PRIVATE_CASE = "PRIVATE_CASE_SENTINEL"
PRIVATE_EXAMINER = "PRIVATE_EXAMINER_SENTINEL"
PRIVATE_SID = "S-1-5-21-424242424-313131313-727272727-1001"
PRIVATE_VALUES = (
    PRIVATE_SOURCE,
    PRIVATE_ARTIFACT,
    PRIVATE_USER,
    PRIVATE_FILENAME,
    PRIVATE_CASE,
    PRIVATE_EXAMINER,
    PRIVATE_SID,
)


@pytest.fixture
def evidence(tmp_path: Path) -> Path:
    source = tmp_path.resolve() / PRIVATE_SOURCE
    directory = source / PRIVATE_SID
    directory.mkdir(parents=True)
    for suffix, extension, content in (("ONE", "pdf", b"report"), ("TWO", "txt", b"notes")):
        original = rf"C:\Users\{PRIVATE_USER}\{PRIVATE_FILENAME}_{suffix}.{extension}"
        encoded = (original + "\0").encode("utf-16-le")
        acquired = PRIVATE_ARTIFACT + "_" + suffix + "." + extension
        (directory / ("$I" + acquired)).write_bytes(
            struct.pack("<QQQI", 2, len(content), 133485408001234567, len(encoded) // 2) + encoded
        )
        (directory / ("$R" + acquired)).write_bytes(content)
    return source


def _sidecar(report: Path) -> Path:
    return Path(str(report) + ".manifest.json")


def _scan_args(evidence: Path, format_name: str) -> list[str]:
    return [
        "scan",
        str(evidence),
        "--recursive",
        "--hash-payload",
        "--format",
        format_name,
        "--case-id",
        PRIVATE_CASE,
        "--examiner",
        PRIVATE_EXAMINER,
        "--query",
        PRIVATE_USER,
        "--sid",
        PRIVATE_SID,
        "--extension",
        "pdf",
    ]


def _join(session: DesktopSession) -> None:
    assert session.worker is not None
    session.worker.join(timeout=5)
    assert not session.worker.is_alive(), "Desktop operation did not finish"


def _events(session: DesktopSession) -> list[tuple[str, object]]:
    result = []
    while True:
        try:
            result.append(session.events.get_nowait())
        except Empty:
            return result


def _complete(evidence: Path) -> DesktopSession:
    session = DesktopSession()
    session.start_scan(
        evidence,
        ScanOptions(
            recursive=True,
            hash_payload=True,
            case_id=PRIVATE_CASE,
            examiner=PRIVATE_EXAMINER,
        ),
    )
    _join(session)
    assert session.state == "complete", session.error
    return session


def _assert_private_values_absent(text: str) -> None:
    for value in PRIVATE_VALUES:
        assert value not in text


def _assert_derivative_label(text: str, format_name: str) -> None:
    if format_name == "json":
        result = json.loads(text)
        assert result["schema_version"] == "sharing-1.0"
        assert result["report_kind"] == "redacted-sharing"
        assert result["derived_from_schema_version"] == "2.0"
    elif format_name == "csv":
        reader = csv.DictReader(io.StringIO(text))
        assert reader.fieldnames[0] == "redacted_sharing_report_kind"
        assert all(row["redacted_sharing_report_kind"] == "redacted-sharing" for row in reader)
    else:
        assert "redacted" in text.casefold()
        assert "sharing" in text.casefold()


@pytest.mark.parametrize("format_name", ["json", "csv", "html", "table"])
def test_cli_redacted_pair_omits_private_values_and_remains_verifiable(
    evidence: Path, capsys: pytest.CaptureFixture, format_name: str
) -> None:
    target = evidence.parent / ("sharing." + format_name)
    args = _scan_args(evidence, format_name) + ["--redact", "--output", str(target)]
    assert cli.main(args) == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    text = target.read_text("utf-8")
    manifest_text = _sidecar(target).read_text("utf-8")
    _assert_private_values_absent(text)
    _assert_private_values_absent(manifest_text)
    _assert_derivative_label(text, format_name)
    manifest = verify_export(target)
    assert manifest["forensic_schema_version"] == "sharing-1.0"
    assert manifest["report_kind"] == "redacted-sharing"
    assert manifest["inventory"] == {"total_records": 2, "selected_records": 1}
    assert manifest["report"]["sha256"] == hashlib.sha256(target.read_bytes()).hexdigest()
    assert cli.main(["verify-export", str(target)]) == 0
    assert capsys.readouterr().err == ""
    for source in evidence.rglob("$I*"):
        assert hashlib.sha256(source.read_bytes()).hexdigest() not in text + manifest_text
    for payload in evidence.rglob("$R*"):
        assert hashlib.sha256(payload.read_bytes()).hexdigest() not in text + manifest_text
    if format_name == "json":
        report = json.loads(text)
        assert report["options"]["case_id"] is None
        assert report["options"]["examiner"] is None
        assert report["selection"]["filters"]["query"] == "[withheld]"
        assert report["selection"]["filters"]["sid"] == "[withheld]"
        assert report["selection"]["filters"]["extensions"] == [".withheld"]
        assert len(report["records"]) == 2
        assert report["selection"]["matched"] == 1
        assert len(report["timeline"]["events"]) == 1
        assert report["timeline"]["events"][0]["deletion_filetime"] == 133485408001234567


@pytest.mark.parametrize("format_name", ["json", "csv", "html", "table"])
def test_cli_redacted_stdout_is_labeled_and_creates_no_files(
    evidence: Path, capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch, format_name: str
) -> None:
    monkeypatch.chdir(evidence.parent)
    before = {path: path.read_bytes() for path in evidence.rglob("*") if path.is_file()}
    assert cli.main(_scan_args(evidence, format_name) + ["--redact"]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    _assert_private_values_absent(captured.out)
    _assert_derivative_label(captured.out, format_name)
    assert {path: path.read_bytes() for path in evidence.rglob("*") if path.is_file()} == before
    assert not tuple(evidence.parent.glob("*.manifest.json"))


@pytest.mark.parametrize("format_name", ["json", "csv", "html", "table"])
@pytest.mark.parametrize("kind", ["empty_selection", "empty_inventory"])
def test_empty_redacted_stdout_keeps_an_explicit_derivative_label(
    evidence: Path, capsys: pytest.CaptureFixture, format_name: str, kind: str
) -> None:
    source = evidence
    if kind == "empty_inventory":
        source = evidence.parent / "empty"
        source.mkdir()
    args = _scan_args(source, format_name) + ["--query", "matches-no-artifact", "--redact"]
    assert cli.main(args) == (2 if kind == "empty_inventory" else 0)
    captured = capsys.readouterr()
    assert captured.err == ""
    _assert_private_values_absent(captured.out)
    _assert_derivative_label(captured.out, format_name)
    if format_name == "json":
        report = json.loads(captured.out)
        assert report["selection"]["matched"] == 0
        assert len(report["records"]) == (0 if kind == "empty_inventory" else 2)
    elif format_name == "csv":
        assert len(captured.out.splitlines()) == 1


@pytest.mark.parametrize("format_name", ["json", "csv", "html", "table"])
def test_cli_ordinary_export_keeps_original_information_without_derivative_labels(
    evidence: Path, capsys: pytest.CaptureFixture, format_name: str
) -> None:
    target = evidence.parent / ("audit." + format_name)
    assert cli.main(_scan_args(evidence, format_name) + ["--output", str(target)]) == 0
    assert capsys.readouterr().out == ""
    text = target.read_text("utf-8")
    assert PRIVATE_ARTIFACT in text
    assert PRIVATE_FILENAME in text
    manifest = verify_export(target)
    assert manifest["forensic_schema_version"] == "2.0"
    assert manifest["case"] == {"case_id": PRIVATE_CASE, "examiner": PRIVATE_EXAMINER}
    assert manifest["scan"]["input"] == str(evidence)
    if format_name == "json":
        report = json.loads(text)
        assert report["schema_version"] == "2.0"
        assert "report_kind" not in report
        assert "redaction" not in report
        assert report["records"][0]["source_sha256"]
    elif format_name == "csv":
        assert next(csv.reader(io.StringIO(text)))[0] == "source_path"
    else:
        assert "REDACTED SHARING DERIVATIVE" not in text


@pytest.mark.parametrize(("value", "exit_code"), [("0", 2), ("64", 3)])
@pytest.mark.parametrize("to_file", [False, True])
def test_cli_redacted_invalid_or_exceeded_budget_produces_no_derivative(
    evidence: Path, capsys: pytest.CaptureFixture, value: str, exit_code: int, to_file: bool
) -> None:
    target = evidence.parent / "limited-sharing.json"
    args = _scan_args(evidence, "json") + ["--redact", "--max-export-bytes", value]
    if to_file:
        args += ["--output", str(target)]
    assert cli.main(args) == exit_code
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "max_export_bytes" in captured.err
    assert not target.exists() and not _sidecar(target).exists()


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("previously_saved", [False, True])
@pytest.mark.parametrize("filtered", [False, True])
def test_desktop_redacted_json_never_acknowledges_a_full_inventory_save(
    evidence: Path, asynchronous: bool, previously_saved: bool, filtered: bool
) -> None:
    session = _complete(evidence)
    baseline = session.report
    if filtered:
        session.apply_view(FilterOptions(query=PRIVATE_USER, extensions=("pdf",), sid=PRIVATE_SID))
    view = session.view
    before_report = json.dumps(baseline, sort_keys=True)
    before_view = json.dumps(view, sort_keys=True)
    if previously_saved:
        session.export(evidence.parent / "earlier-audit.json", "json")
    target = evidence.parent / "sharing.json"
    if asynchronous:
        session.start_export(target, "json", redacted=True)
        _join(session)
    else:
        assert session.export(target, "json", redacted=True) == target
    assert session.state == "complete", session.error
    assert session.report is baseline and session.view is view
    assert json.dumps(session.report, sort_keys=True) == before_report
    assert json.dumps(session.view, sort_keys=True) == before_view
    assert session.has_unsaved_report is (not previously_saved)
    assert _events(session)[-1] == ("exported", target)
    _assert_private_values_absent(target.read_text("utf-8"))
    _assert_private_values_absent(_sidecar(target).read_text("utf-8"))
    assert verify_export(target)["forensic_schema_version"] == "sharing-1.0"
    session.export(evidence.parent / "full-audit.json", "json")
    assert not session.has_unsaved_report


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("override", [False, 0, {}, ""])
def test_redacted_export_invalid_limits_preserve_baseline_and_unsaved_state(
    evidence: Path, asynchronous: bool, override
) -> None:
    session = _complete(evidence)
    baseline, view = session.report, session.view
    target = evidence.parent / "invalid-limits.json"
    if asynchronous:
        session.start_export(target, "json", limits=override, redacted=True)
        _join(session)
    else:
        with pytest.raises(TypeError, match="WorkLimits"):
            session.export(target, "json", limits=override, redacted=True)
    assert session.state == "complete"
    assert session.report is baseline and session.view is view
    assert session.has_unsaved_report
    assert _events(session)[-1][0] == "export_error"
    assert not target.exists() and not _sidecar(target).exists()


@pytest.mark.parametrize("asynchronous", [False, True])
def test_redacted_export_budget_failure_preserves_baseline_and_cleans_both_files(
    evidence: Path, asynchronous: bool
) -> None:
    session = _complete(evidence)
    baseline, view = session.report, session.view
    target = evidence.parent / "limited-sharing.json"
    limits = WorkLimits(max_export_bytes=64)
    if asynchronous:
        session.start_export(target, "json", limits=limits, redacted=True)
        _join(session)
    else:
        with pytest.raises(WorkLimitExceeded):
            session.export(target, "json", limits=limits, redacted=True)
    assert session.state == "complete"
    assert session.report is baseline and session.view is view
    assert session.has_unsaved_report
    assert _events(session)[-1][0] == "export_limited"
    assert not target.exists() and not _sidecar(target).exists()


def test_redacted_writer_sanitizes_arbitrary_context_but_retains_valid_phase_budgets(
    evidence: Path,
) -> None:
    session = _complete(evidence)
    before = json.dumps(session.report, sort_keys=True)
    phase_limits = WorkLimits(max_records=2).to_dict()
    context = {
        "scan_limits": phase_limits,
        "filter_limits": phase_limits,
        "examiner": PRIVATE_EXAMINER,
        "evidence_path": str(evidence),
        "nested": {"private": PRIVATE_USER},
    }
    context_before = json.dumps(context, sort_keys=True)
    target = evidence.parent / "sharing-context.json"
    assert (
        output.write_report(session.report, target, "json", redacted=True, context=context)
        == target
    )
    manifest = verify_export(target)
    assert manifest["context"] == {"scan_limits": phase_limits, "filter_limits": phase_limits}
    _assert_private_values_absent(target.read_text("utf-8"))
    _assert_private_values_absent(_sidecar(target).read_text("utf-8"))
    assert json.dumps(session.report, sort_keys=True) == before
    assert json.dumps(context, sort_keys=True) == context_before
    assert session.has_unsaved_report


@pytest.mark.parametrize("budget", [{}, {**WorkLimits().to_dict(), "max_records": False}])
def test_redacted_writer_rejects_malformed_phase_context_before_creating_files(
    evidence: Path, budget
) -> None:
    session = _complete(evidence)
    baseline = session.report
    before = json.dumps(baseline, sort_keys=True)
    target = evidence.parent / "malformed-context.json"
    with pytest.raises(ValueError):
        output.write_report(
            baseline, target, "json", redacted=True, context={"scan_limits": budget}
        )
    assert session.report is baseline and session.has_unsaved_report
    assert json.dumps(session.report, sort_keys=True) == before
    assert not target.exists() and not _sidecar(target).exists()


@pytest.mark.parametrize("scope", ["directory", "single_file"])
def test_redacted_cli_output_is_rejected_inside_the_original_evidence_scope(
    evidence: Path, capsys: pytest.CaptureFixture, scope: str
) -> None:
    source = evidence if scope == "directory" else next(evidence.rglob("$I*"))
    target = source / "sharing.json" if source.is_dir() else source.parent / "sharing.json"
    assert cli.main(["scan", str(source), "--recursive", "--redact", "--output", str(target)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "outside the evidence directory" in captured.err
    assert not target.exists() and not _sidecar(target).exists()


@pytest.mark.parametrize("scope", ["directory", "single_file"])
def test_redacted_desktop_output_uses_original_scope_before_aliases(
    evidence: Path, scope: str
) -> None:
    source = evidence if scope == "directory" else next(evidence.rglob("$I*"))
    session = DesktopSession()
    session.start_scan(source, ScanOptions(recursive=True))
    _join(session)
    assert session.state == "complete", session.error
    baseline = session.report
    target = source / "sharing.json" if source.is_dir() else source.parent / "sharing.json"
    with pytest.raises(EvidenceError, match="outside the evidence directory"):
        session.export(target, "json", redacted=True)
    assert session.report is baseline and session.has_unsaved_report
    assert not target.exists() and not _sidecar(target).exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX file permission bits are not a Windows ACL")
@pytest.mark.parametrize("redacted", [False, True])
def test_report_and_manifest_creation_are_private_even_with_permissive_umask(
    evidence: Path, redacted: bool
) -> None:
    session = _complete(evidence)
    target = evidence.parent / ("sharing.json" if redacted else "audit.json")
    previous_mask = os.umask(0)
    try:
        session.export(target, "json", redacted=redacted)
    finally:
        os.umask(previous_mask)
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert stat.S_IMODE(_sidecar(target).stat().st_mode) == 0o600
    assert verify_export(target)
