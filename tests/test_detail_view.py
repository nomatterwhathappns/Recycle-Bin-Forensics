"""Real Tk detail rendering keeps provenance and selection state legible."""

from __future__ import annotations

import copy
import gc
import os
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("RBF_RUN_GUI") != "1", reason="Set RBF_RUN_GUI=1 for native detail tests"
)


def record() -> dict:
    return {
        "record_type": "metadata",
        "source_path": "/case/$IABC.txt",
        "source_name": "$IABC.txt",
        "source_size": 544,
        "source_sha256": "a" * 64,
        "sid": "S-1-5-21-1001",
        "status": "ok",
        "issues": [],
        "metadata": {
            "format_version": 1,
            "original_path": "C:\\Users\\資料\\📄.txt",
            "original_size": 7,
            "deletion_filetime": 133485408001234567,
            "deleted_at_utc": "2024-01-01T00:00:00.1234567Z",
            "deleted_at_display": "2024-01-01T07:00:00.1234567+07:00",
        },
        "payload": {
            "path": None,
            "status": "missing",
            "size": None,
            "sha256": None,
            "hash_status": "not_requested",
            "size_matches_metadata": None,
        },
    }


@pytest.fixture
def view():
    gc.collect()
    import tkinter as tk
    from tkinter import font

    from rbinforensics.detail_view import DetailView

    root = tk.Tk()
    root.geometry("1000x380")
    messages = []
    errors = []
    root.report_callback_exception = lambda kind, value, tb: errors.append(
        f"{kind.__name__}: {value}"
    )
    widget = DetailView(
        root,
        ui_font=font.nametofont("TkDefaultFont").actual("family"),
        mono_font=font.nametofont("TkFixedFont").actual("family"),
        on_status=messages.append,
    )
    widget.pack(fill="both", expand=True)
    widget._test_root = root
    widget._test_messages = messages
    root.update()
    try:
        yield widget
    finally:
        root.destroy()
        assert errors == []


def test_summary_separates_decoded_metadata_from_missing_payload(view):
    source = record()
    before = copy.deepcopy(source)
    view.set_record(source)
    view._test_root.update()
    assert view.get_value("metadata_status") == "Berhasil dibaca"
    assert view.get_value("payload_status") == "Tidak ditemukan"
    assert (
        view.field_widgets["Ringkasan", "metadata_status"].get("1.0", "end-1c") == "Berhasil dibaca"
    )
    assert (
        view.field_widgets["Ringkasan", "payload_status"].get("1.0", "end-1c") == "Tidak ditemukan"
    )
    assert source == before
    assert len(view.notebook.tabs()) == 4


def test_full_details_preserve_unicode_uint64_and_separate_sizes(view):
    source = record()
    source["metadata"]["original_size"] = (1 << 64) - 1
    view.set_record(source)
    assert view.get_value("original_path") == source["metadata"]["original_path"]
    assert view.get_value("original_size") == str((1 << 64) - 1)
    assert view.get_value("source_size") == "544"
    assert view.get_value("deletion_filetime") == "133485408001234567"
    assert source["metadata"]["original_path"] in view.get_text()
    assert "133485408001234567" in view.get_text()
    assert "a" * 64 in view.get_text()


def test_control_text_is_visible_and_issue_separators_remain_real_newlines(view):
    source = record()
    source["metadata"]["original_path"] = "C:\\x\x1b[2J\n\u202efile.txt"
    source["issues"] = [
        {"code": "first", "severity": "warning", "message": "line\ncontrol"},
        {"code": "second", "severity": "error", "message": "\0value"},
    ]
    view.set_record(source)
    assert "\x1b" not in view.get_value("original_path")
    assert "\\u001b" in view.get_value("original_path")
    assert "\\u202e" in view.get_value("original_path")
    issues = view.get_value("issues")
    assert issues.count("\n") == 1
    assert "line\\u000acontrol" in issues
    assert "\\u0000value" in issues


def test_hashing_failure_does_not_relabel_successful_metadata_decode(view):
    source = record()
    source["status"] = "error"
    source["payload"]["status"] = "unreadable"
    source["payload"]["hash_status"] = "unavailable"
    view.set_record(source)
    assert view.get_value("metadata_status") == "Berhasil dibaca"
    assert view.get_value("payload_status") == "Gagal diperiksa"


def test_orphan_has_no_invented_original_metadata_and_copy_context_is_clear(view):
    source = record()
    source.update(
        record_type="orphan_payload",
        source_name="$RABC.txt",
        metadata=None,
        source_path="/case/$RABC.txt",
        source_sha256="b" * 64,
    )
    source["payload"].update(status="available_file", sha256="b" * 64, hash_status="computed")
    view.set_record(source)
    assert view.get_value("metadata_status") == "Tidak ditemukan"
    assert view.get_value("original_path") == "Tidak diketahui / tidak tersedia"
    assert view.get_value("deleted_at_utc") == "Tidak diketahui / tidak tersedia"
    assert "payload $R" in view.get_value("hash_context")
    assert view.copy_hash()
    assert view.clipboard_get() == "b" * 64
    assert "payload $R" in view._test_messages[-1]


def test_discovery_does_not_claim_redirected_source_bytes_were_hashed(view):
    source = record()
    source.update(record_type="discovery", status="skipped", metadata=None, source_sha256=None)
    source["payload"].update(status="available_file", sha256="b" * 64)
    view.set_record(source)
    assert view.get_value("metadata_status") == "Dilewati"
    assert "Hash sumber tidak tersedia" in view.get_value("hash_context")
    assert view.copy_hash()
    assert view.clipboard_get() == "b" * 64


def test_actual_per_field_buttons_copy_the_correct_source_or_payload_hash(view):
    source = record()
    source["payload"].update(status="available_file", sha256="b" * 64)
    view.set_record(source)
    view.copy_buttons["Ringkasan", "original_path"].invoke()
    assert view.clipboard_get() == source["metadata"]["original_path"]
    view.copy_buttons["Hash & sumber", "source_sha256"].invoke()
    assert view.clipboard_get() == "a" * 64
    view.copy_buttons["Hash & sumber", "payload_sha256"].invoke()
    assert view.clipboard_get() == "b" * 64
    view.copy_details()
    assert view.clipboard_get() == view.get_text()


def test_clear_selection_removes_old_values_and_disables_copy(view):
    view.set_record(record())
    view.copy_hash()
    view.set_record(None)
    view._test_root.update()
    assert view.record is None
    assert view.get_value("original_path") == ""
    assert "a" * 64 not in view.get_text()
    assert all(widget.get("1.0", "end-1c") == "" for widget in view.field_widgets.values())
    assert str(view.copy_all_button.cget("state")) == "disabled"
    assert not view.copy_hash()
    assert not view.copy_value("source_sha256")
    assert view.clipboard_get() == "a" * 64


def test_font_change_keeps_active_tab_selection_and_record(view):
    source = record()
    view.set_record(source)
    view.notebook.select(3)
    selected = view.notebook.select()
    view.set_font_size(16)
    view._test_root.update()
    assert view.font_size == 16
    assert view.notebook.select() == selected
    assert view.record is source
    view.set_font_size(9)
    assert view.font_size == 9


@pytest.mark.parametrize("size", [8, 17, True, 11.5])
def test_invalid_font_sizes_fail_before_changing_current_view(view, size):
    view.set_record(record())
    with pytest.raises(ValueError):
        view.set_font_size(size)
    assert view.font_size == 11
    assert view.get_value("metadata_status") == "Berhasil dibaca"


def test_word_wrapped_path_uses_actual_display_lines_without_hidden_tail(view):
    view._test_root.geometry("650x450")
    source = record()
    source["metadata"]["original_path"] = "12345678901234567 " * 30
    view.set_record(source)
    view._test_root.update()
    field = view.field_widgets["Ringkasan", "original_path"]
    actual = int(field.tk.call(field._w, "count", "-update", "-displaylines", "1.0", "end-1c")) + 1
    assert int(field.cget("height")) >= actual
    assert field.yview() == (0.0, 1.0)


def test_closing_popup_keeps_embedded_page_scroll_bindings(view):
    import tkinter as tk

    from rbinforensics.detail_view import DetailView

    source = record()
    source["metadata"]["original_path"] = "C:\\" + "long-directory\\" * 30
    view.set_record(source)
    root = view._test_root
    before_binding = root.bind_all("<MouseWheel>")
    popup = tk.Toplevel(root)
    popup_view = DetailView(popup, ui_font=view.ui_font, mono_font=view.mono_font)
    popup_view.pack(fill="both", expand=True)
    popup_view.set_record(source)
    root.update()
    popup.destroy()
    root.update()
    assert root.bind_all("<MouseWheel>") == before_binding
    canvas = view._canvases[0]
    canvas.yview_moveto(0)
    view._labels[0].event_generate("<MouseWheel>", delta=-120)
    root.update()
    assert canvas.yview()[0] > 0
    before = canvas.yview()
    view._scroll_page(canvas, SimpleNamespace(delta=0))
    assert canvas.yview() == before
