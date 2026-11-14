"""CLI and desktop acknowledge a saved report only after its manifest succeeds."""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path
from queue import Empty
from threading import Event

import pytest

from rbinforensics import __version__, cli, output
from rbinforensics.analysis import FilterOptions
from rbinforensics.desktop import DesktopSession
from rbinforensics.limits import WorkLimits
from rbinforensics.manifest import verify_export
from rbinforensics.scanner import ScanOptions


@pytest.fixture
def evidence(tmp_path: Path) -> Path:
    directory = tmp_path.resolve() / "evidence"
    directory.mkdir()
    for suffix, original, content in (
        ("ONE.pdf", r"C:\Case\report.pdf", b"report"),
        ("TWO.txt", r"C:\Case\notes.txt", b"notes"),
    ):
        encoded = (original + "\0").encode("utf-16-le")
        (directory / ("$I" + suffix)).write_bytes(
            struct.pack("<QQQI", 2, len(content), 133485408001234567, len(encoded) // 2) + encoded
        )
        (directory / ("$R" + suffix)).write_bytes(content)
    return directory


def _sidecar(report: Path) -> Path:
    return Path(str(report) + ".manifest.json")


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


def _complete(evidence: Path, limits: WorkLimits | None = None) -> DesktopSession:
    session = DesktopSession()
    session.start_scan(evidence, ScanOptions(hash_payload=True, limits=limits))
    _join(session)
    assert session.state == "complete", session.error
    return session


@pytest.mark.parametrize("format_name", ["json", "csv", "html", "table"])
def test_cli_file_export_creates_verifiable_pair_and_preserves_full_scope(
    evidence: Path, capsys: pytest.CaptureFixture, format_name: str
) -> None:
    target = evidence.parent / ("selected." + format_name)
    assert (
        cli.main(
            [
                "scan",
                str(evidence),
                "--format",
                format_name,
                "--output",
                str(target),
                "--extension",
                "pdf",
                "--case-id",
                "CASE-MANIFEST",
                "--examiner",
                "Examiner",
                "--max-records",
                "3",
                "--max-export-bytes",
                "1000000",
            ]
        )
        == 0
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert target.is_file() and _sidecar(target).is_file()
    manifest = verify_export(target)
    assert manifest == json.loads(_sidecar(target).read_text("utf-8"))
    assert manifest["manifest_schema_version"] == "1.0"
    assert manifest["tool"] == {"name": "rbinforensics", "version": __version__}
    assert manifest["report"] == {
        "filename": target.name,
        "format": format_name,
        "size_bytes": len(target.read_bytes()),
        "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
    }
    assert manifest["forensic_schema_version"] == "2.0"
    assert manifest["inventory"] == {"total_records": 2, "selected_records": 1}
    assert manifest["case"] == {"case_id": "CASE-MANIFEST", "examiner": "Examiner"}
    assert manifest["scan"]["input"] == str(evidence)
    assert set(manifest["scan"]["options"]) == {
        "recursive",
        "hash_payload",
        "timezone",
        "case_id",
        "examiner",
    }
    assert manifest["selection"]["active"] is True
    assert manifest["selection"]["filters"]["extensions"] == [".pdf"]
    assert manifest["selection"]["timezone"] == "UTC"
    expected_limits = WorkLimits(max_records=3, max_export_bytes=1_000_000).to_dict()
    assert manifest["runtime_limits"] == expected_limits
    assert manifest["context"] == {
        "scan_limits": expected_limits,
        "filter_limits": expected_limits,
    }
    assert cli.main(["verify-export", str(target)]) == 0
    captured = capsys.readouterr()
    assert manifest["report"]["sha256"] in captured.out
    assert captured.err == ""


@pytest.mark.parametrize("format_name", ["json", "csv", "html", "table"])
def test_cli_stdout_export_does_not_create_a_report_or_manifest(
    evidence: Path, capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch, format_name: str
) -> None:
    monkeypatch.chdir(evidence.parent)
    before = set(evidence.parent.rglob("*"))
    assert cli.main(["scan", str(evidence), "--format", format_name]) == 0
    captured = capsys.readouterr()
    assert captured.out
    assert captured.err == ""
    assert set(evidence.parent.rglob("*")) == before


@pytest.mark.parametrize(
    ("kind", "exit_code", "record_count"), [("empty", 2, 0), ("corrupt", 1, 1)]
)
def test_cli_completed_diagnostic_and_empty_reports_still_get_verifiable_manifests(
    evidence: Path, capsys: pytest.CaptureFixture, kind: str, exit_code: int, record_count: int
) -> None:
    source = evidence.parent / kind
    source.mkdir()
    if kind == "corrupt":
        (source / "$IBROKEN").write_bytes(b"broken")
    target = evidence.parent / (kind + ".json")
    assert cli.main(["scan", str(source), "--format", "json", "--output", str(target)]) == exit_code
    captured = capsys.readouterr()
    assert captured.out == ""
    manifest = verify_export(target)
    assert manifest["inventory"] == {
        "total_records": record_count,
        "selected_records": record_count,
    }
    assert cli.main(["verify-export", str(target)]) == 0
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize(
    "damage",
    [
        "missing_manifest",
        "missing_report",
        "different_report_size",
        "different_report_hash",
        "invalid_manifest_json",
        "invalid_manifest_format",
        "missing_manifest_hash",
        "different_manifest_hash",
        "unsupported_manifest_version",
    ],
)
def test_cli_verify_rejects_missing_or_changed_pair_members(
    evidence: Path, capsys: pytest.CaptureFixture, damage: str
) -> None:
    target = evidence.parent / "report.json"
    assert cli.main(["scan", str(evidence), "--format", "json", "--output", str(target)]) == 0
    capsys.readouterr()
    sidecar = _sidecar(target)
    if damage == "missing_manifest":
        sidecar.unlink()
    elif damage == "missing_report":
        target.unlink()
    elif damage == "different_report_size":
        target.write_bytes(target.read_bytes() + b" ")
    elif damage == "different_report_hash":
        content = target.read_bytes()
        target.write_bytes(bytes([content[0] ^ 1]) + content[1:])
    elif damage == "invalid_manifest_json":
        sidecar.write_text("{broken", encoding="utf-8")
    else:
        manifest = json.loads(sidecar.read_text("utf-8"))
        if damage == "missing_manifest_hash":
            del manifest["report"]["sha256"]
        elif damage == "invalid_manifest_format":
            manifest["report"]["format"] = []
        elif damage == "different_manifest_hash":
            manifest["report"]["sha256"] = "0" * 64
        else:
            manifest["manifest_schema_version"] = "999.0"
        sidecar.write_text(json.dumps(manifest), encoding="utf-8")
    assert cli.main(["verify-export", str(target)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("rbf:")


def test_cli_sidecar_failure_does_not_announce_or_retain_an_unpaired_report(
    evidence: Path, capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = evidence.parent / "failed-pair.json"
    sidecar = _sidecar(target)
    original_open = Path.open

    def fail_manifest_open(path, mode="r", *args, **kwargs):
        if path == sidecar and mode.startswith("x"):
            raise PermissionError("Manifest creation denied")
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", fail_manifest_open)
    assert cli.main(["scan", str(evidence), "--format", "json", "--output", str(target)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Manifest creation denied" in captured.err
    assert "Report saved" not in captured.err
    assert not target.exists() and not sidecar.exists()


def test_cli_preexisting_manifest_is_preserved_and_prevents_report_creation(
    evidence: Path, capsys: pytest.CaptureFixture
) -> None:
    target = evidence.parent / "occupied-pair.json"
    sidecar = _sidecar(target)
    sidecar.write_bytes(b"Another export's manifest")
    assert cli.main(["scan", str(evidence), "--format", "json", "--output", str(target)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err
    assert not target.exists()
    assert sidecar.read_bytes() == b"Another export's manifest"


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("previously_saved", [False, True])
@pytest.mark.parametrize("failure", ["create", "sync"])
def test_desktop_sidecar_failure_preserves_inventory_view_and_saved_status(
    evidence: Path,
    monkeypatch: pytest.MonkeyPatch,
    asynchronous: bool,
    previously_saved: bool,
    failure: str,
) -> None:
    session = _complete(evidence)
    baseline = session.report
    view = session.apply_view(FilterOptions(extensions=("pdf",)))
    if previously_saved:
        session.export(evidence.parent / "earlier.json", "json")
    target = evidence.parent / "failed-pair.json"
    sidecar = _sidecar(target)
    original_open = Path.open
    original_sync = output.os.fsync
    syncs = []

    def fail_manifest_open(path, mode="r", *args, **kwargs):
        if path == sidecar and mode.startswith("x"):
            raise PermissionError("Manifest creation denied")
        return original_open(path, mode, *args, **kwargs)

    def fail_manifest_sync(descriptor):
        syncs.append(descriptor)
        if len(syncs) == 2:
            raise OSError("Manifest synchronization failed")
        return original_sync(descriptor)

    if failure == "create":
        monkeypatch.setattr(Path, "open", fail_manifest_open)
    else:
        monkeypatch.setattr(output.os, "fsync", fail_manifest_sync)
    if asynchronous:
        session.start_export(target, "json")
        _join(session)
    else:
        with pytest.raises(OSError, match="Manifest"):
            session.export(target, "json")
    emitted = _events(session)
    assert emitted[-1][0] == "export_error"
    assert not any(name == "exported" for name, _ in emitted)
    assert session.state == "complete"
    assert session.report is baseline and session.view is view
    assert session.has_unsaved_report is (not previously_saved)
    assert "Manifest" in session.error
    assert not target.exists() and not sidecar.exists()
    if failure == "sync":
        assert len(syncs) == 2


def test_desktop_json_acknowledges_save_only_after_manifest_worker_finishes(
    evidence: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = _complete(evidence)
    baseline = session.report
    target = evidence.parent / "complete-pair.json"
    sidecar = _sidecar(target)
    entered, release = Event(), Event()
    original_open = Path.open

    def pause_manifest_open(path, mode="r", *args, **kwargs):
        if path == sidecar and mode.startswith("x"):
            entered.set()
            assert release.wait(5), "Manifest worker was not released"
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", pause_manifest_open)
    session.start_export(target, "json")
    try:
        assert entered.wait(2), "Export did not reach manifest creation"
        assert target.is_file() and not sidecar.exists()
        assert session.state == "exporting"
        assert session.report is baseline
        assert session.has_unsaved_report
        assert not any(name == "exported" for name, _ in _events(session))
        with pytest.raises(RuntimeError, match="already running"):
            session.start_scan(evidence, ScanOptions())
    finally:
        release.set()
        _join(session)
    assert session.state == "complete", session.error
    assert session.report is baseline
    assert not session.has_unsaved_report
    assert _events(session)[-1] == ("exported", target)
    manifest = verify_export(target)
    assert manifest["inventory"] == {"total_records": 2, "selected_records": 2}
    assert json.loads(target.read_text("utf-8"))["schema_version"] == "2.0"


def test_desktop_manifest_records_independent_scan_filter_and_export_limits(
    evidence: Path,
) -> None:
    scan_limits = WorkLimits(max_records=2, max_export_bytes=1_000_000)
    filter_limits = WorkLimits(max_records=3, max_export_bytes=2_000_000)
    export_limits = WorkLimits(max_records=4, max_export_bytes=3_000_000)
    session = _complete(evidence, scan_limits)
    session.apply_view(FilterOptions(extensions=("txt",)), limits=filter_limits)
    target = evidence.parent / "phase-context.json"
    assert session.export(target, "json", limits=export_limits) == target
    manifest = verify_export(target)
    assert manifest["runtime_limits"] == export_limits.to_dict()
    assert manifest["context"] == {
        "scan_limits": scan_limits.to_dict(),
        "filter_limits": filter_limits.to_dict(),
    }
    assert manifest["inventory"] == {"total_records": 2, "selected_records": 1}
    assert session.scan_limits is scan_limits and session.view_limits is filter_limits
