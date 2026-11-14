"""Export pairs are private from creation and failed stream wrapping owns nothing."""

from __future__ import annotations

import errno
import os
import stat
from pathlib import Path

import pytest

from rbinforensics import output
from rbinforensics.manifest import manifest_path, verify_export
from rbinforensics.reports import render
from rbinforensics.scanner import scan


@pytest.fixture
def report(tmp_path: Path) -> dict:
    source = tmp_path / "evidence"
    source.mkdir()
    (source / "$IBAD").write_bytes(b"bad")
    return scan(source)


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions; Windows inherits directory ACLs")
@pytest.mark.parametrize("redacted", [False, True])
def test_both_files_are_private_at_creation_even_with_permissive_umask(
    report: dict, tmp_path: Path, monkeypatch, redacted: bool
) -> None:
    destination = tmp_path / "report.json"
    sidecar = manifest_path(destination)
    original_open = os.open
    observed = {}

    def inspect_create(path, flags, mode=0o777, *, dir_fd=None):
        descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
        if Path(path) in (destination, sidecar) and flags & os.O_CREAT:
            observed[Path(path)] = stat.S_IMODE(os.fstat(descriptor).st_mode)
            assert os.fstat(descriptor).st_size == 0
            assert flags & os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                assert flags & os.O_NOFOLLOW
        return descriptor

    monkeypatch.setattr(output.os, "open", inspect_create)
    previous_umask = os.umask(0)
    try:
        output.write_report(report, destination, "json", redacted=redacted)
    finally:
        os.umask(previous_umask)
    assert observed == {destination: 0o600, sidecar: 0o600}
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert stat.S_IMODE(sidecar.stat().st_mode) == 0o600
    assert verify_export(destination)["report"]["filename"] == destination.name


@pytest.mark.parametrize("stage", ["report", "manifest"])
def test_fdopen_failure_closes_raw_descriptor_and_removes_the_owned_pair(
    report: dict, tmp_path: Path, monkeypatch, stage: str
) -> None:
    destination = tmp_path / "report.json"
    original_fdopen = output.os.fdopen
    failed_descriptors = []
    calls = [0]

    def fail_stream_wrap(descriptor, *args, **kwargs):
        calls[0] += 1
        if calls[0] == (1 if stage == "report" else 2):
            failed_descriptors.append(descriptor)
            raise OSError("cannot wrap private descriptor")
        return original_fdopen(descriptor, *args, **kwargs)

    monkeypatch.setattr(output.os, "fdopen", fail_stream_wrap)
    with pytest.raises(OSError, match="cannot wrap private descriptor"):
        output.write_report(report, destination, "json")
    assert not destination.exists()
    assert not manifest_path(destination).exists()
    assert failed_descriptors
    for descriptor in failed_descriptors:
        with pytest.raises(OSError) as failure:
            os.fstat(descriptor)
        assert failure.value.errno == errno.EBADF


@pytest.mark.skipif(os.name == "nt", reason="Windows prevents replacing open output handles")
def test_fdopen_failure_preserves_a_concurrent_replacement(tmp_path: Path, monkeypatch) -> None:
    destination = tmp_path / "report.json"

    def replace_then_fail(descriptor, *args, **kwargs):
        destination.unlink()
        destination.write_text("another writer's file", encoding="utf-8")
        raise OSError("cannot wrap private descriptor")

    monkeypatch.setattr(output.os, "fdopen", replace_then_fail)
    with pytest.raises(OSError, match="cannot wrap private descriptor"):
        with output._open_private(destination):
            pytest.fail("Failed descriptor wrapping must not yield a stream.")
    assert destination.read_text("utf-8") == "another writer's file"


@pytest.mark.parametrize("format_name", ["json", "csv", "table", "html"])
def test_private_creation_preserves_ordinary_report_bytes(
    report: dict, tmp_path: Path, format_name: str
) -> None:
    expected = render(report, format_name).encode("utf-8")
    destination = tmp_path / ("ordinary." + format_name)
    output.write_report(report, destination, format_name)
    assert destination.read_bytes() == expected
    assert "report_kind" not in verify_export(destination)


@pytest.mark.parametrize("redacted", [None, 0, 1, "", "false", [], {}])
def test_invalid_redacted_flag_never_creates_either_file(
    report: dict, tmp_path: Path, redacted
) -> None:
    destination = tmp_path / "report.json"
    with pytest.raises(ValueError, match="redacted must be a boolean"):
        output.write_report(report, destination, "json", redacted=redacted)
    assert not destination.exists()
    assert not manifest_path(destination).exists()
