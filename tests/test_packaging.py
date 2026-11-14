"""Portable distribution contracts; native freezing is validated on Windows CI."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import subprocess
import zipfile
from pathlib import Path

import pytest

from rbinforensics import __version__
from tools import build_windows


def smoke_result() -> dict:
    return {
        "status": "ok",
        "version": __version__,
        "checks": {"tk": True, "parser": True, "widgets": True},
        "tk_version": "8.6.15",
    }


def test_installed_distribution_and_cli_module_use_same_version() -> None:
    assert importlib.metadata.version("rbinforensics") == __version__
    assert __version__ == "1.4.0"


def test_runtime_licenses_preserve_installed_timezone_notices():
    notices = build_windows.runtime_licenses()
    assert "Python, Tcl/Tk, tzdata" in notices
    assert "=== tzdata:" in notices
    assert "Apache License" in notices


@pytest.mark.parametrize("version", ["1.1.0", "0.0.0", "65535.1.2"])
def test_windows_version_resource_preserves_release_number(version: str) -> None:
    resource = build_windows.version_resource(version)
    assert f"StringStruct('FileVersion', '{version}')" in resource
    assert f"StringStruct('ProductVersion', '{version}')" in resource
    assert str((*map(int, version.split(".")), 0)) in resource


@pytest.mark.parametrize("version", ["1.1", "1.1.0-beta", "65536.0.0", "1.1.0');evil("])
def test_invalid_windows_version_cannot_be_embedded_as_python(version: str) -> None:
    with pytest.raises(build_windows.BuildError):
        build_windows.version_resource(version)


def test_frozen_smoke_executes_the_executable_and_requires_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "RecycleBinForensics.exe"
    output = tmp_path / "smoke.json"
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        output.write_text(json.dumps(smoke_result()), encoding="utf-8")

    monkeypatch.setattr(build_windows.subprocess, "run", fake_run)
    result = build_windows.verify_smoke(executable, output, __version__)
    assert result["checks"]["widgets"] is True
    assert len(calls) == 1
    command, options = calls[0]
    assert command == [str(executable), "--smoke-test", "--smoke-output", str(output)]
    assert options["check"] is True
    assert options["timeout"] == 90
    assert options["cwd"] == output.parent
    assert all(
        name not in options["env"]
        for name in ("PYTHONHOME", "PYTHONPATH", "TCL_LIBRARY", "TK_LIBRARY")
    )


@pytest.mark.parametrize(
    "result",
    [
        {},
        {"status": "error", "version": __version__},
        {**smoke_result(), "version": "1.0.0"},
        {**smoke_result(), "checks": {"tk": True, "widgets": True, "parser": False}},
        {**smoke_result(), "checks": {"tk": True, "widgets": True, "parser": "true"}},
        {**smoke_result(), "tk_version": ""},
    ],
)
def test_incomplete_or_wrong_frozen_application_is_not_released(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, result: dict
) -> None:
    output = tmp_path / "smoke.json"
    output.write_text(json.dumps(result), encoding="utf-8")
    monkeypatch.setattr(build_windows.subprocess, "run", lambda *_args, **_kwargs: None)
    with pytest.raises(build_windows.BuildError):
        build_windows.verify_smoke(tmp_path / "app.exe", output, __version__)


def test_malformed_smoke_result_is_a_build_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "smoke.json"
    output.write_text("not JSON", encoding="utf-8")
    monkeypatch.setattr(build_windows.subprocess, "run", lambda *_args, **_kwargs: None)
    with pytest.raises(build_windows.BuildError, match="valid smoke-test result"):
        build_windows.verify_smoke(tmp_path / "app.exe", output, __version__)


def test_failed_executable_does_not_pass_even_with_stale_success_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "smoke.json"
    output.write_text(json.dumps(smoke_result()), encoding="utf-8")

    def fail_run(*_args, **_kwargs):
        raise subprocess.CalledProcessError(1, ["app.exe"])

    monkeypatch.setattr(build_windows.subprocess, "run", fail_run)
    with pytest.raises(subprocess.CalledProcessError):
        build_windows.verify_smoke(tmp_path / "app.exe", output, __version__)


def test_linux_host_cannot_claim_to_produce_native_windows_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(build_windows.platform, "system", lambda: "Linux")
    with pytest.raises(build_windows.BuildError, match="native 64-bit Windows"):
        build_windows.build(tmp_path / "distribution")


def _mock_native_builder(monkeypatch: pytest.MonkeyPatch, before_smoke=None) -> list:
    monkeypatch.setattr(build_windows.platform, "system", lambda: "Windows")
    monkeypatch.setattr(build_windows.platform, "machine", lambda: "AMD64")
    # Keep mocked build metadata independent of host-specific platform probes
    # (Python 3.10 on Windows may otherwise call subprocess to run `ver`).
    monkeypatch.setattr(build_windows.platform, "version", lambda: "10.0.26100")
    monkeypatch.setattr(build_windows.platform, "python_version", lambda: "3.13.0")
    original_version = importlib.metadata.version
    monkeypatch.setattr(
        build_windows.importlib.metadata,
        "version",
        lambda name: "6.19.0" if name == "pyinstaller" else original_version(name),
    )
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        if command[1:3] == ["-m", "PyInstaller"]:
            destination = Path(command[command.index("--distpath") + 1]) / build_windows.APP_NAME
            destination.mkdir(parents=True)
            (destination / f"{build_windows.APP_NAME}.exe").write_bytes(b"fake-native-executable")
            runtime = destination / "_internal" / "tzdata"
            runtime.mkdir(parents=True)
            (runtime / "zoneinfo").write_bytes(b"test-timezone-runtime")
        else:
            if before_smoke:
                before_smoke()
            destination = Path(command[command.index("--smoke-output") + 1])
            destination.write_text(json.dumps(smoke_result()), encoding="utf-8")

    monkeypatch.setattr(build_windows.subprocess, "run", fake_run)
    return calls


def test_portable_archive_contains_whole_runtime_and_a_matching_checksum(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _mock_native_builder(monkeypatch)
    output = tmp_path / "distribution"
    archive, checksum = build_windows.build(output)
    with zipfile.ZipFile(archive) as bundle:
        names = set(bundle.namelist())
        assert f"{build_windows.APP_NAME}/{build_windows.APP_NAME}.exe" in names
        assert f"{build_windows.APP_NAME}/_internal/tzdata/zoneinfo" in names
        assert f"{build_windows.APP_NAME}/LICENSE" in names
        assert f"{build_windows.APP_NAME}/THIRD_PARTY_LICENSES.txt" in names
        information = json.loads(bundle.read(f"{build_windows.APP_NAME}/BUILD-INFO.json"))
        assert information["version"] == __version__
        assert information["smoke_test"]["checks"]["parser"] is True
        assert "Extract the entire ZIP" in bundle.read(
            f"{build_windows.APP_NAME}/START_HERE.txt"
        ).decode("utf-8")
    expected = hashlib.sha256(archive.read_bytes()).hexdigest()
    assert checksum.read_text("utf-8") == f"{expected}  {archive.name}\n"
    assert "--windowed" in calls[0][0]
    assert "--onedir" in calls[0][0]
    assert calls[0][0][calls[0][0].index("--collect-data") + 1] == "tzdata"
    assert calls[0][0][calls[0][0].index("--collect-submodules") + 1] == "tzdata"
    assert len(calls) == 3  # Freeze, staged startup, extracted-archive startup.
    assert Path(calls[-1][0][0]).parent.parent != output
    assert calls[-1][1]["cwd"] == Path(calls[-1][0][0]).parent.parent
    assert len(list(output.iterdir())) == 2


def test_existing_completed_distribution_is_never_overwritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _mock_native_builder(monkeypatch)
    output = tmp_path / "distribution"
    output.mkdir()
    archive = output / f"{build_windows.APP_NAME}-{__version__}-windows-x64.zip"
    archive.write_bytes(b"earlier-build")
    with pytest.raises(build_windows.BuildError, match="already exists"):
        build_windows.build(output)
    assert archive.read_bytes() == b"earlier-build"
    assert calls == []


def test_checksum_race_cleans_only_owned_archive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "distribution"

    def create_external_checksum():
        (output / "SHA256SUMS.txt").write_text("earlier external checksum\n", encoding="utf-8")

    _mock_native_builder(monkeypatch, create_external_checksum)
    with pytest.raises(FileExistsError):
        build_windows.build(output)
    assert (output / "SHA256SUMS.txt").read_text("utf-8") == "earlier external checksum\n"
    assert list(output.glob("*.zip")) == []
