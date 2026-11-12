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


def _activate_tree(app, tree):
    child = tree
    while child.master is not None:
        parent = child.master
        if parent.winfo_class() == "TNotebook":
            parent.select(child)
            app.update()
            return
        child = parent
    pytest.fail("Result table is not attached to a notebook tab")


def _select(app, tree, row=None):
    _activate_tree(app, tree)
    row = row or tree.get_children()[0]
    tree.selection_set(row)
    tree.focus(row)
    tree.event_generate("<<TreeviewSelect>>")
    app.update()
    assert not app._test_callback_errors, app._test_callback_errors
    return app._row_objects[tree][row]


def _visible_records(app, tree):
    return [app._row_objects[tree][row] for row in tree.get_children()]


def _click_heading(app, tree, column):
    callback = tree.heading(column, "command")
    assert callback, f"Column {column} has no interactive sorting command"
    tree.tk.call(callback)
    app.update()
    assert not app._test_callback_errors, app._test_callback_errors


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
    details = app.detail_panel.get_text()
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


def test_metadata_and_missing_payload_have_separate_clear_statuses(app, evidence):
    (evidence / "$RABC.pdf").unlink()
    _scan(app, evidence)
    _select(app, app.inventory)
    assert app.detail_panel.get_value("metadata_status") == "Berhasil dibaca"
    assert app.detail_panel.get_value("payload_status") == "Tidak ditemukan"
    assert "Payload hilang" in app.inventory.item(app.inventory.get_children()[0], "values")
    assert app.session.report["records"][0]["status"] == "ok"


def test_empty_scope_can_be_reviewed_sorted_and_exported_without_invented_findings(app, tmp_path):
    directory = tmp_path.resolve() / "empty-evidence"
    directory.mkdir()
    app.source_var.set(str(directory))
    app.start_scan()
    _pump(app, lambda: app.session.state == "complete" and not app._awaiting_terminal)
    assert app.session.report["records"] == []
    assert not app.inventory.get_children()
    assert app.detail_panel.record is None
    assert app.detail_button.instate(("disabled",))
    _click_heading(app, app.inventory, "size")
    assert not app.inventory.get_children()
    target = tmp_path.resolve() / "empty-scope.json"
    app.export_report("json", target)
    _pump(app, lambda: app.session.state == "complete" and app._last_export == target)
    report = json.loads(target.read_text("utf-8"))
    assert report["summary"]["candidates"] == 0
    assert report["summary"]["orphan_payloads"] == 0
    assert report["records"] == []


def test_advanced_filters_collapse_preserves_values_and_recovers_workspace(app, evidence):
    _scan(app, evidence)
    app.geometry("1366x768")
    app.update()
    assert not app.filters_visible.get()
    assert not app.advanced_filters.winfo_ismapped()
    assert app.filter_toggle.winfo_ismapped()
    collapsed_height = app.results_split.winfo_height()
    app.filter_toggle.invoke()
    app.update()
    assert app.filters_visible.get()
    assert app.advanced_filters.winfo_ismapped()
    expanded_height = app.results_split.winfo_height()
    assert collapsed_height >= expanded_height + 40
    app.after_var.set("2024-01-01")
    app.before_var.set("2024-01-01")
    app.extension_var.set(".pdf")
    app.min_size_var.set("1")
    app.filter_toggle.invoke()
    app.update()
    assert not app.advanced_filters.winfo_ismapped()
    assert (
        app.after_var.get(),
        app.before_var.get(),
        app.extension_var.get(),
        app.min_size_var.get(),
    ) == ("2024-01-01", "2024-01-01", ".pdf", "1")
    app.apply_filters()
    _pump(app, lambda: not app._awaiting_terminal and app.session.state == "complete")
    assert app.session.view["selection"]["matched"] == 1
    assert app.session.view["selection"]["filters"]["extensions"] == [".pdf"]


def test_vertical_workspace_keeps_wide_detail_and_adjustable_split(app, evidence):
    _scan(app, evidence)
    for geometry in ("1366x768", "1000x700"):
        app.geometry(geometry)
        app.update()
        assert str(app.results_split.cget("orient")) == "vertical"
        assert app.inventory.winfo_height() >= 100
        assert app.detail_panel.winfo_height() >= 150
        assert app.detail_panel.winfo_width() >= app.results_split.winfo_width() - 20
        assert app.progress.winfo_ismapped()
        assert app.cancel_button.winfo_ismapped()
        assert app.detail_button.winfo_ismapped()
        assert (
            app.detail_button.winfo_rooty() + app.detail_button.winfo_height()
            <= app.progress.winfo_rooty()
        )
    app.geometry("1366x900")
    app.update()
    original = app.results_split.sash_coord(0)[1]
    app.results_split.sash_place(0, 0, original + 20)
    app.update()
    assert app.results_split.sash_coord(0)[1] >= original + 15


def test_popout_follows_selection_and_clears_without_stale_evidence(app, evidence):
    _item(evidence, "NOTE.txt", r"C:\Users\Analyst\note.txt")
    _scan(app, evidence, count=2)
    _select(app, app.inventory)
    app.detail_button.invoke()
    app.update()
    window = app.detail_window
    assert window.winfo_exists()
    assert window.winfo_toplevel() is window
    assert window is not app
    assert window.tk is app.tk
    assert window.detail_view.get_value("original_path") == r"C:\Users\Analyst\report.pdf"
    window.detail_view.notebook.select(3)
    app.update()
    window.detail_view.copy_buttons[("Hash & sumber", "payload_sha256")].invoke()
    app.update()
    assert app.clipboard_get() == hashlib.sha256(b"payload").hexdigest()
    app.open_details()
    assert app.detail_window is window
    _select(app, app.inventory, app.inventory.get_children()[1])
    assert window.detail_view.get_value("original_path") == r"C:\Users\Analyst\note.txt"
    app.query_var.set("no-artifact-can-match")
    app.apply_filters()
    _pump(app, lambda: not app._awaiting_terminal and not app.inventory.get_children())
    assert app.detail_panel.record is None
    assert window.detail_view.record is None
    assert "note.txt" not in window.detail_view.get_text()
    app.reset_filters()
    _pump(app, lambda: not app._awaiting_terminal and len(app.inventory.get_children()) == 2)
    _select(app, app.inventory)
    assert window.detail_view.get_value("original_path") == r"C:\Users\Analyst\report.pdf"
    window.destroy()
    app.open_details()
    app.update()
    assert app.detail_window.winfo_exists()
    assert app.detail_window is not window
    assert not app._test_destroyed.is_set()


def test_detail_popout_requires_selected_evidence(app, evidence):
    app.open_details()
    assert getattr(app, "detail_window", None) is None
    _scan(app, evidence)
    _select(app, app.inventory)
    assert app.detail_button.instate(("!disabled",))
    app.inventory.selection_remove(*app.inventory.selection())
    app.inventory.event_generate("<<TreeviewSelect>>")
    app.update()
    assert app.detail_panel.record is None
    assert app.detail_button.instate(("disabled",))
    app.open_details()
    assert getattr(app, "detail_window", None) is None


def test_active_result_tab_never_displays_a_hidden_other_tab_record(app, evidence):
    (evidence / "$RLONE.bin").write_bytes(b"orphan")
    _scan(app, evidence, count=2)
    orphan = next(
        row
        for row in app.inventory.get_children()
        if app._row_objects[app.inventory][row]["record_type"] == "orphan_payload"
    )
    _select(app, app.inventory, orphan)
    app.open_details()
    window = app.detail_window
    assert window.detail_view.record["source_name"] == "$RLONE.bin"
    _activate_tree(app, app.timeline)
    assert app.detail_panel.record is None
    assert window.detail_view.record is None
    _select(app, app.timeline)
    assert app.detail_panel.get_value("original_path") == r"C:\Users\Analyst\report.pdf"
    _activate_tree(app, app.inventory)
    # A returning tab may restore its own selected row, but must never retain
    # an unrelated row from the previously active table.
    selected = app.inventory.selection()
    if selected:
        assert app.detail_panel.record is app._row_objects[app.inventory][selected[0]]
        assert window.detail_view.record is app.detail_panel.record
    else:
        assert app.detail_panel.record is None


def test_font_controls_preserve_current_evidence_view_and_detail_window(app, evidence):
    from tkinter import font

    _scan(app, evidence)
    record = _select(app, app.inventory)
    app.open_details()
    app.update()
    window = app.detail_window
    baseline = json.dumps(app.session.report, sort_keys=True)
    app.query_var.set("report")
    app.detail_panel.notebook.select(3)
    selected_tab = app.detail_panel.notebook.select()
    selected_row = app.inventory.selection()
    query_entry = next(
        widget
        for widget in app.filter_inputs
        if widget.winfo_class() == "TEntry" and widget.cget("textvariable") == str(app.query_var)
    )
    assert (
        font.Font(root=app, font=query_entry.cget("font")).actual("size") == app.font_size_var.get()
    )
    path_widget = app.detail_panel.field_widgets[("Ringkasan", "original_path")]
    previous_size = font.Font(root=app, font=path_widget.cget("font")).actual("size")
    app.change_font_size(2)
    app.update()
    assert app.font_size_var.get() == 13
    assert font.Font(root=app, font=query_entry.cget("font")).actual("size") == 13
    assert font.Font(root=app, font=path_widget.cget("font")).actual("size") > previous_size
    popup_path = window.detail_view.field_widgets[("Ringkasan", "original_path")]
    assert font.Font(root=app, font=popup_path.cget("font")).actual("size") == 13
    assert app.inventory.selection() == selected_row
    assert app._selected_record is record
    assert app.detail_panel.notebook.select() == selected_tab
    assert window.detail_view.get_value("original_path") == r"C:\Users\Analyst\report.pdf"
    assert app.query_var.get() == "report"
    for _ in range(12):
        app.change_font_size(1)
    assert app.font_size_var.get() == 16
    assert app.font_larger.instate(("disabled",))
    for _ in range(12):
        app.change_font_size(-1)
    assert app.font_size_var.get() == 9
    assert app.font_smaller.instate(("disabled",))
    assert json.dumps(app.session.report, sort_keys=True) == baseline


def test_small_window_keeps_toolbar_controls_usable_at_every_font_size(app, evidence):
    _scan(app, evidence)
    app.geometry("1000x700")
    app.toggle_filters()
    for size in range(9, 17):
        app.change_font_size(size - app.font_size_var.get())
        app.update()
        calendars = [widget for widget in app.filter_inputs if widget.winfo_class() == "TButton"]
        controls = [app.font_smaller, app.font_larger, *app.export_buttons, *calendars]
        for control in controls:
            assert control.winfo_ismapped(), (size, control)
            assert control.winfo_width() >= control.winfo_reqwidth(), (size, control)
            assert control.winfo_rootx() >= app.winfo_rootx()
            assert (
                control.winfo_rootx() + control.winfo_width()
                <= app.winfo_rootx() + app.winfo_width()
            ), (size, control)
        assert app.progress.winfo_ismapped()
        assert app.detail_button.winfo_ismapped()


def test_heading_sorting_is_exact_and_keeps_unknown_values_last(app, tmp_path):
    directory = tmp_path.resolve() / "sort-evidence"
    directory.mkdir()
    sizes = {"A.txt": 2**53 + 1, "B.txt": 2**53, "C.txt": 2**64 - 1}
    for suffix, size in sizes.items():
        source = _item(
            directory,
            suffix,
            rf"C:\Sort\{suffix}",
            ticks=TICKS + (0 if suffix == "B.txt" else 1 if suffix == "A.txt" else 2),
        )
        raw = bytearray(source.read_bytes())
        struct.pack_into("<Q", raw, 8, size)
        source.write_bytes(raw)
    (directory / "$RUNKNOWN").mkdir()
    _scan(app, directory, count=4)
    baseline = json.dumps(app.session.view, sort_keys=True)
    for column in ("size", "time"):
        _click_heading(app, app.inventory, column)
        assert [r["source_name"] for r in _visible_records(app, app.inventory)] == [
            "$IB.txt",
            "$IA.txt",
            "$IC.txt",
            "$RUNKNOWN",
        ]
        _click_heading(app, app.inventory, column)
        assert [r["source_name"] for r in _visible_records(app, app.inventory)] == [
            "$IC.txt",
            "$IA.txt",
            "$IB.txt",
            "$RUNKNOWN",
        ]
    assert json.dumps(app.session.view, sort_keys=True) == baseline


def test_sorting_orders_the_full_selection_before_pagination(app, tmp_path):
    from rbinforensics.gui import PAGE_SIZE

    directory = tmp_path.resolve() / "global-sort-evidence"
    directory.mkdir()
    for index in range(PAGE_SIZE + 1):
        source = _item(directory, f"SIZE{index:04d}.txt", rf"C:\Sort\file-{index:04d}.txt")
        raw = bytearray(source.read_bytes())
        struct.pack_into("<Q", raw, 8, index)
        source.write_bytes(raw)
    _scan(app, directory, count=PAGE_SIZE)
    baseline = json.dumps(app.session.report, sort_keys=True)
    _click_heading(app, app.inventory, "size")
    _click_heading(app, app.inventory, "size")
    assert _visible_records(app, app.inventory)[0]["metadata"]["original_size"] == PAGE_SIZE
    assert app._pages[app.inventory] == 0
    app._page_buttons[app.inventory][1].invoke()
    app.update()
    assert len(app.inventory.get_children()) == 1
    assert _visible_records(app, app.inventory)[0]["metadata"]["original_size"] == 0
    assert json.dumps(app.session.report, sort_keys=True) == baseline


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
    assert r"C:\Users\Analyst\note.txt" in app.detail_panel.get_text()
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
    details = app.detail_panel.get_text()
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
    _select(app, app.inventory)
    app.open_details()
    popup = app.detail_window
    assert popup.detail_view.record is not None
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
        placeholder = app.detail_panel.get_text()
        assert "report.pdf" not in placeholder
        assert hashlib.sha256(b"payload").hexdigest() not in placeholder
        assert popup.detail_view.record is None
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
    assert "page-0000.txt" in app.detail_panel.get_text()
    app.open_details()
    popup = app.detail_window

    app._page_buttons[app.inventory][1].invoke()
    app.update()
    assert len(app.inventory.get_children()) == 1
    assert getattr(app, "_selected_record", None) is None
    assert "page-0000.txt" not in app.detail_panel.get_text()
    assert popup.detail_view.record is None
    last = app.inventory.get_children()[0]
    app.inventory.selection_set(last)
    app.inventory.event_generate("<<TreeviewSelect>>")
    app.update()
    assert f"page-{PAGE_SIZE:04d}.txt" in app.detail_panel.get_text()

    for tree, expected in ((app.timeline, "page-0000.txt"), (app.review, "page-0001.txt")):
        _activate_tree(app, tree)
        first = tree.get_children()[0]
        tree.selection_set(first)
        tree.event_generate("<<TreeviewSelect>>")
        app.update()
        assert expected in app.detail_panel.get_text()
