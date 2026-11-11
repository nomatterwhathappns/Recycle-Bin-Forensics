"""Native Tk integration: real jobs, safe views/export, and cancellation.

Enable with RBF_RUN_GUI=1 on Windows or under xvfb-run on Linux. The default
CLI test suite must not require importing Tk or connecting to a display.
"""

from __future__ import annotations

import gc
import hashlib
import json
import os
import struct
import time
from pathlib import Path
from threading import Event

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("RBF_RUN_GUI") != "1", reason="Set RBF_RUN_GUI=1 for native desktop tests"
)
TICKS = 133_485_408_001_234_567


def _item(
    directory: Path, suffix="ABC.pdf", original=r"C:\Users\Analyst\report.pdf", *, ticks=TICKS
):
    content = b"payload"
    encoded = (original + "\0").encode("utf-16-le")
    source = directory / ("$I" + suffix)
    source.write_bytes(struct.pack("<QQQI", 2, len(content), ticks, len(encoded) // 2) + encoded)
    (directory / ("$R" + suffix)).write_bytes(content)
    return source


def _pump(app, predicate, *, timeout=8.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        app.update()
        assert not app._test_callback_errors, app._test_callback_errors
        time.sleep(0.005)
    pytest.fail(f"Desktop did not reach expected state; session={app.session.state}")


@pytest.fixture
def evidence(tmp_path):
    directory = tmp_path.resolve() / "evidence"
    directory.mkdir()
    _item(directory)
    return directory


@pytest.fixture
def app(monkeypatch):
    # Tk roots/StringVars form cycles. Collect retired roots on the Tk thread
    # before a later worker can trigger GC; Tcl finalizers are thread-affine.
    gc.collect()
    from rbinforensics import gui

    dialogs = []
    for name in ("showerror", "showinfo"):
        monkeypatch.setattr(
            gui.messagebox,
            name,
            lambda title, message, **_: dialogs.append((str(title), str(message))),
        )
    monkeypatch.setattr(gui.messagebox, "askyesno", lambda *_, **__: True)
    root = gui.ForensicsApp()
    root._test_dialogs = dialogs
    root._test_callback_errors = []
    root.report_callback_exception = lambda kind, value, _tb: root._test_callback_errors.append(
        f"{kind.__name__}: {value}"
    )
    destroyed = Event()
    root.bind("<Destroy>", lambda event: destroyed.set() if event.widget == root else None, add="+")
    root._test_destroyed = destroyed
    root.update()
    try:
        yield root
    finally:
        if root.session.state == "scanning":
            root.session.cancel()
        if root.session.worker is not None:
            root.session.worker.join(timeout=3)
        if not destroyed.is_set():
            root.destroy()
        assert not root._test_callback_errors, root._test_callback_errors


def _scan(app, source, *, count=1):
    app.source_var.set(str(source))
    app.hash_var.set(True)
    app.start_scan()
    _pump(
        app, lambda: app.session.state == "complete" and len(app.inventory.get_children()) == count
    )
    assert app.session.report is not None


def test_empty_input_shows_error_without_starting_job(app):
    app.source_var.set("")
    app.start_scan()
    assert app.session.state == "idle"
    assert app.session.worker is None
    assert app._test_dialogs
    assert not app.inventory.get_children()


def test_small_window_preserves_progress_cancel_and_report_actions(app, evidence):
    app.geometry("1000x700")
    app.case_visible.set(True)
    app._toggle_case()
    app.update()
    assert app.progress.winfo_ismapped()
    assert app.cancel_button.winfo_ismapped()
    examiner = next(
        widget
        for widget, _ in app._inputs
        if widget.winfo_class() == "TEntry" and widget.cget("textvariable") == str(app.examiner_var)
    )
    examiner.focus_force()
    app.update()
    assert examiner.winfo_rooty() >= app.scan_viewport.winfo_rooty()
    assert examiner.winfo_rooty() + examiner.winfo_height() <= app.progress.winfo_rooty()
    app.scan_viewport.yview_moveto(1)
    app.update()
    assert app.start_button.winfo_rooty() < app.progress.winfo_rooty()
    _scan(app, evidence)
    app.update()
    assert app.location_button.winfo_ismapped()
    assert app.open_button.winfo_ismapped()
    assert app.cancel_button.winfo_ismapped()
    assert app.location_button.winfo_rooty() < app.progress.winfo_rooty()


def test_native_source_pickers_set_selected_path(app, evidence, monkeypatch):
    from rbinforensics import gui

    monkeypatch.setattr(gui.filedialog, "askdirectory", lambda **_: str(evidence))
    app.choose_folder()
    assert app.source_var.get() == str(evidence)
    source = evidence / "$IABC.pdf"
    monkeypatch.setattr(gui.filedialog, "askopenfilename", lambda **_: str(source))
    app.choose_file()
    assert app.source_var.get() == str(source)
    monkeypatch.setattr(gui.filedialog, "askopenfilename", lambda **_: "")
    app.choose_file()
    assert app.source_var.get() == str(source)


def test_invalid_timezone_and_missing_source_fail_without_exportable_result(app, evidence):
    app.source_var.set(str(evidence))
    app.timezone_var.set("NoSuch/Timezone")
    app.start_scan()
    assert app.session.state == "idle"
    assert app._test_dialogs
    app.timezone_var.set("UTC")
    app.source_var.set(str(evidence / "missing"))
    before = len(app._test_dialogs)
    app.start_scan()
    _pump(app, lambda: app.session.state == "error" and len(app._test_dialogs) > before)
    assert app.session.report is None
    assert not app.inventory.get_children()
    assert all(button.instate(("disabled",)) for button in app.export_buttons)


def test_real_scan_populates_inventory_timeline_and_exact_details(app, evidence):
    _scan(app, evidence)
    assert len(app.timeline.get_children()) == 1
    assert app.session.report["summary"]["payloads_hashed"] == 1
    assert not app.review.get_children()
    row = app.inventory.get_children()[0]
    app.inventory.selection_set(row)
    app.inventory.focus(row)
    app.inventory.event_generate("<<TreeviewSelect>>")
    app.update()
    details = app.details.get("1.0", "end")
    assert r"C:\Users\Analyst\report.pdf" in details
    assert str(TICKS) in details
    assert "2024-01-01T00:00:00.1234567Z" in details
    assert hashlib.sha256(b"payload").hexdigest() in details
    app.copy_hash()
    app.update()
    assert app.clipboard_get() == hashlib.sha256(b"payload").hexdigest()
    app.copy_details()
    app.update()
    assert str(TICKS) in app.clipboard_get()


def test_filter_and_clear_use_full_baseline_not_previous_subset(app, evidence):
    _item(evidence, "NOTE.txt", r"C:\Users\Analyst\note.txt", ticks=TICKS + 864_000_000_000)
    _scan(app, evidence, count=2)
    app.extension_var.set(".pdf")
    app.apply_filters()
    _pump(app, lambda: len(app.inventory.get_children()) == 1)
    assert app.session.view["selection"]["matched"] == 1
    assert len(app.session.view["records"]) == 2
    app.extension_var.set(".txt")
    app.apply_filters()
    _pump(
        app,
        lambda: (
            app.session.state == "complete"
            and app.session.view["selection"]["filters"]["extensions"] == [".txt"]
            and any(
                "note.txt" in str(app.inventory.item(row)).lower()
                for row in app.inventory.get_children()
            )
        ),
    )
    indexes = app.session.view["selection"]["record_indexes"]
    assert app.session.view["records"][indexes[0]]["source_name"] == "$INOTE.txt"
    row = app.inventory.get_children()[0]
    app.inventory.selection_set(row)
    app.inventory.focus(row)
    app.inventory.event_generate("<<TreeviewSelect>>")
    app.update()
    assert r"C:\Users\Analyst\note.txt" in app.details.get("1.0", "end")
    app.extension_var.set("")
    app.apply_filters()
    _pump(app, lambda: len(app.inventory.get_children()) == 2)
    assert app.session.report["selection"]["matched"] == 2


def test_unicode_path_and_full_uint64_remain_exact_in_details(app, evidence):
    source = _item(evidence, "UNICODE.txt", "C:\\資料\\📄.txt")
    raw = bytearray(source.read_bytes())
    maximum = (1 << 64) - 1
    struct.pack_into("<Q", raw, 8, maximum)
    source.write_bytes(raw)
    _scan(app, source)
    row = app.inventory.get_children()[0]
    app.inventory.selection_set(row)
    app.inventory.focus(row)
    app.inventory.event_generate("<<TreeviewSelect>>")
    app.update()
    details = app.details.get("1.0", "end")
    assert "資料" in details
    assert "📄" in details
    assert str(maximum) in details
    assert app.session.report["records"][0]["metadata"]["original_size"] == maximum


def test_query_cannot_hide_failed_evidence_or_review(app, evidence):
    (evidence / "$IBROKEN.bin").write_bytes(b"broken")
    _scan(app, evidence, count=2)
    assert app.session.report["summary"]["errors"] == 1
    assert app.review.get_children()
    app.query_var.set("definitely-no-valid-match")
    app.apply_filters()
    _pump(app, lambda: len(app.inventory.get_children()) == 1)
    index = app.session.view["selection"]["record_indexes"][0]
    assert app.session.view["records"][index]["status"] == "error"
    assert app.review.get_children()


def test_invalid_filter_retains_previous_view_and_reports_problem(app, evidence):
    _scan(app, evidence)
    previous = app.session.view
    app.min_size_var.set("invalid-size")
    app.apply_filters()
    _pump(app, lambda: bool(app._test_dialogs) and app.session.state == "complete")
    assert app._test_dialogs
    assert app.session.view is previous
    assert len(app.inventory.get_children()) == 1


def test_end_date_includes_entire_utc_day(app, evidence):
    _scan(app, evidence)
    app.after_var.set("2024-01-01")
    app.before_var.set("2024-01-01")
    app.apply_filters()
    _pump(
        app,
        lambda: (
            app.session.state == "complete"
            and (app.session.view["selection"]["filters"]["deleted_before"] or "").endswith(
                "23:59:59.9999999Z"
            )
        ),
    )
    assert app.session.view["selection"]["matched"] == 1
    assert app.session.view["selection"]["filters"]["deleted_before"].endswith("23:59:59.9999999Z")


def test_calendar_selects_leap_day_and_stops_at_supported_year_boundaries(app):
    from rbinforensics.gui import DatePicker

    app.after_var.set("2024-02-01")
    picker = DatePicker(app, app.after_var)
    picker._choose(29)
    assert app.after_var.get() == "2024-02-29"
    for value, delta in (("0001-01-01", -1), ("9999-12-01", 1)):
        app.after_var.set(value)
        picker = DatePicker(app, app.after_var)
        try:
            before = (picker.year, picker.month)
            picker._move(delta)
            assert (picker.year, picker.month) == before
        finally:
            picker.destroy()


@pytest.mark.parametrize("format_name", ["json", "csv", "html"])
def test_export_writes_real_report_outside_evidence(app, evidence, tmp_path, format_name):
    _scan(app, evidence)
    target = tmp_path.resolve() / f"report.{format_name}"
    app.export_report(format_name, target)
    _pump(app, lambda: app.session.state == "complete" and target.exists())
    content = target.read_text("utf-8")
    assert "report.pdf" in content
    if format_name == "json":
        report = json.loads(content)
        assert report["summary"]["parsed"] == 1
        assert report["records"][0]["metadata"]["deletion_filetime"] == TICKS
    elif format_name == "html":
        assert "Content-Security-Policy" in content
    else:
        assert "source_sha256" in content


def test_export_rejects_overwrite_and_writing_among_evidence(app, evidence, tmp_path):
    _scan(app, evidence)
    existing = tmp_path.resolve() / "existing.json"
    existing.write_text("preserve", encoding="utf-8")
    before = len(app._test_dialogs)
    app.export_report("json", existing)
    _pump(app, lambda: app.session.state == "complete" and len(app._test_dialogs) > before)
    assert existing.read_text("utf-8") == "preserve"
    count = len(app._test_dialogs)
    unsafe = evidence / "report.json"
    app.export_report("json", unsafe)
    _pump(app, lambda: app.session.state == "complete" and len(app._test_dialogs) > count)
    assert not unsafe.exists()
    assert app.session.report is not None


def test_open_actions_use_only_the_successfully_exported_report(
    app, evidence, tmp_path, monkeypatch
):
    from rbinforensics import gui

    _scan(app, evidence)
    opened, locations = [], []
    monkeypatch.setattr(gui.webbrowser, "open", lambda url: opened.append(url) or True)
    if gui.sys.platform == "win32":
        monkeypatch.setattr(gui.os, "startfile", lambda path: locations.append(path))
    else:
        monkeypatch.setattr(gui.subprocess, "Popen", lambda args: locations.append(args))
    app.open_report()
    app.open_report_location()
    assert not opened and not locations
    target = tmp_path.resolve() / "review ; literal.html"
    app.export_report("html", target)
    _pump(app, lambda: app._last_export == target and app.session.state == "complete")
    app.open_report()
    app.open_report_location()
    assert opened == [target.as_uri()]
    if gui.sys.platform == "win32":
        assert locations == [str(target.parent)]
    else:
        assert locations[0][-1] == str(target.parent)
        assert len(locations[0]) == 2


def test_editing_next_run_inputs_cannot_relabel_or_weaken_completed_export(app, evidence, tmp_path):
    app.case_var.set("CASE-ORIGINAL")
    app.examiner_var.set("Original examiner")
    _scan(app, evidence)
    next_source = tmp_path.resolve() / "next-evidence"
    next_source.mkdir()
    _item(next_source, "NEW.txt", r"D:\Other\new.txt")
    app.source_var.set(str(next_source))
    app.case_var.set("CASE-NEXT")
    app.examiner_var.set("Next examiner")

    unsafe = evidence / "must-not-write.json"
    before = len(app._test_dialogs)
    app.export_report("json", unsafe)
    _pump(app, lambda: app.session.state == "complete" and len(app._test_dialogs) > before)
    assert not unsafe.exists()

    target = tmp_path.resolve() / "original-run.json"
    app.export_report("json", target)
    _pump(app, lambda: app.session.state == "complete" and target.exists())
    report = json.loads(target.read_text("utf-8"))
    assert report["input"] == str(evidence)
    assert report["options"]["case_id"] == "CASE-ORIGINAL"
    assert report["options"]["examiner"] == "Original examiner"
    assert report["records"][0]["source_name"] == "$IABC.pdf"


def _block_hash(monkeypatch):
    from rbinforensics import scanner

    entered, release = Event(), Event()
    original = scanner._hash_payload

    def delayed(path):
        entered.set()
        assert release.wait(5), "Controlled hashing checkpoint was not released"
        return original(path)

    monkeypatch.setattr(scanner, "_hash_payload", delayed)
    return entered, release


def test_cancel_during_hash_keeps_ui_responsive_and_disables_export(
    app, evidence, tmp_path, monkeypatch
):
    entered, release = _block_hash(monkeypatch)
    app.source_var.set(str(evidence))
    app.hash_var.set(True)
    app.start_scan()
    try:
        _pump(app, entered.is_set)
        heartbeat = []
        app.after(0, lambda: heartbeat.append(True))
        _pump(app, lambda: bool(heartbeat))
        app.cancel_scan()
        polled = Event()
        app.after(120, polled.set)
        _pump(app, polled.is_set)
        assert app.cancel_button.instate(("disabled",))
        assert "Pembatalan" in app.status_var.get() or "Menunggu" in app.status_var.get()
    finally:
        release.set()
    _pump(app, lambda: app.session.state == "cancelled")
    assert app.session.report is None
    assert app.session.view is None
    assert not app.inventory.get_children()
    target = tmp_path.resolve() / "cancelled.json"
    app.export_report("json", target)
    assert not target.exists()
    assert app._test_dialogs


def test_second_scan_clears_old_result_before_worker_completion(
    app, evidence, tmp_path, monkeypatch
):
    _scan(app, evidence)
    second = tmp_path.resolve() / "second-evidence"
    second.mkdir()
    _item(second, "NEW.txt", r"D:\Other\new.txt")
    entered, release = _block_hash(monkeypatch)
    app.source_var.set(str(second))
    app.start_scan()
    try:
        _pump(app, entered.is_set)
        assert app.session.report is None
        assert not app.inventory.get_children()
        placeholder = app.details.get("1.0", "end")
        assert "report.pdf" not in placeholder
        assert hashlib.sha256(b"payload").hexdigest() not in placeholder
    finally:
        release.set()
    _pump(app, lambda: app.session.state == "complete" and bool(app.inventory.get_children()))
    assert app.session.report["records"][0]["source_name"] == "$INEW.txt"


def test_close_requests_cancel_and_waits_for_worker(app, evidence, monkeypatch):
    entered, release = _block_hash(monkeypatch)
    app.source_var.set(str(evidence))
    app.hash_var.set(True)
    app.start_scan()
    try:
        _pump(app, entered.is_set)
        app._on_close()
        assert not app._test_destroyed.is_set()
    finally:
        release.set()
    _pump(app, app._test_destroyed.is_set)
    assert app.session.state == "cancelled"
    assert app.session.worker is not None
    app.session.worker.join(timeout=1)
    assert not app.session.worker.is_alive()


def test_pagination_and_each_tree_keep_details_bound_to_current_row(app, tmp_path):
    from rbinforensics.gui import PAGE_SIZE

    evidence = tmp_path.resolve() / "paged-evidence"
    evidence.mkdir()
    for index in range(PAGE_SIZE + 1):
        _item(
            evidence,
            f"PAGE{index:04d}.txt",
            rf"C:\Users\Analyst\page-{index:04d}.txt",
            ticks=TICKS + index,
        )
    (evidence / "$RPAGE0001.txt").write_bytes(b"mismatch")
    (evidence / f"$RPAGE{PAGE_SIZE:04d}.txt").write_bytes(b"mismatch")
    _scan(app, evidence, count=PAGE_SIZE)
    first = app.inventory.get_children()[0]
    app.inventory.selection_set(first)
    app.inventory.event_generate("<<TreeviewSelect>>")
    app.update()
    assert "page-0000.txt" in app.details.get("1.0", "end")

    app._page_buttons[app.inventory][1].invoke()
    app.update()
    assert len(app.inventory.get_children()) == 1
    assert getattr(app, "_selected_record", None) is None
    assert "page-0000.txt" not in app.details.get("1.0", "end")
    last = app.inventory.get_children()[0]
    app.inventory.selection_set(last)
    app.inventory.event_generate("<<TreeviewSelect>>")
    app.update()
    assert f"page-{PAGE_SIZE:04d}.txt" in app.details.get("1.0", "end")

    for tree, expected in ((app.timeline, "page-0000.txt"), (app.review, "page-0001.txt")):
        first = tree.get_children()[0]
        tree.selection_set(first)
        tree.event_generate("<<TreeviewSelect>>")
        app.update()
        assert expected in app.details.get("1.0", "end")
