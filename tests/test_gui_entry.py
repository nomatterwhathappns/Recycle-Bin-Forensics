"""Startup diagnostics must fail cleanly, including a windowless executable."""

from __future__ import annotations

import ctypes
import json
import os

import pytest

from rbinforensics import __version__, cli, gui


def test_cli_gui_command_dispatches_without_scan_arguments(monkeypatch):
    calls = []
    monkeypatch.setattr(gui, "main", lambda args: calls.append(args) or 0)
    assert cli.main(["gui"]) == 0
    assert calls == [[]]


def test_gui_main_runs_its_event_loop(monkeypatch):
    calls = []

    class Application:
        def mainloop(self):
            calls.append("mainloop")

    monkeypatch.setattr(gui, "ForensicsApp", Application)
    assert gui.main([]) == 0
    assert calls == ["mainloop"]


def test_gui_version_is_available_without_starting_tk(capsys):
    with pytest.raises(SystemExit) as stopped:
        gui.main(["--version"])
    assert stopped.value.code == 0
    assert capsys.readouterr().out.strip() == __version__


def test_missing_tk_has_actionable_error(monkeypatch):
    monkeypatch.setattr(gui, "tk", None)
    with pytest.raises(RuntimeError, match="Tkinter tidak tersedia"):
        gui.ForensicsApp()


@pytest.mark.parametrize("arguments", [["--smoke-test"], ["--smoke-output", "unused.json"]])
def test_incomplete_smoke_arguments_are_usage_error(arguments):
    with pytest.raises(SystemExit) as stopped:
        gui.main(arguments)
    assert stopped.value.code == 2


def test_smoke_failure_writes_diagnostic_without_modal_dialog(tmp_path, monkeypatch):
    destination = tmp_path / "smoke.json"
    modal_calls = []
    if os.name == "nt":
        monkeypatch.setattr(
            ctypes.windll.user32, "MessageBoxW", lambda *args: modal_calls.append(args)
        )

    def fail(_destination):
        raise RuntimeError("bundled runtime missing")

    monkeypatch.setattr(gui, "_smoke_test", fail)
    assert gui.main(["--smoke-test", "--smoke-output", str(destination)]) == 2
    result = json.loads(destination.read_text("utf-8"))
    assert result["status"] == "error"
    assert "bundled runtime missing" in result["error"]
    assert modal_calls == []


def test_smoke_failure_never_overwrites_existing_output(tmp_path, monkeypatch):
    destination = tmp_path / "smoke.json"
    destination.write_text("existing report", encoding="utf-8")

    def fail(_destination):
        raise RuntimeError("failed")

    monkeypatch.setattr(gui, "_smoke_test", fail)
    assert gui.main(["--smoke-test", "--smoke-output", str(destination)]) == 2
    assert destination.read_text("utf-8") == "existing report"


@pytest.mark.skipif(os.environ.get("RBF_RUN_GUI") != "1", reason="Requires a native Tk display")
def test_actual_gui_smoke_renders_and_exports(tmp_path):
    destination = tmp_path.resolve() / "smoke.json"
    assert gui.main(["--smoke-test", "--smoke-output", str(destination)]) == 0
    result = json.loads(destination.read_text("utf-8"))
    assert result["version"] == __version__
    assert result["checks"] == {
        "tk": True,
        "parser": True,
        "widgets": True,
        "timezone": True,
        "export": True,
    }
