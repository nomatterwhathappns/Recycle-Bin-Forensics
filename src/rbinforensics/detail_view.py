"""Readable, selectable evidence details shared by the main pane and popup.

The widget presents separate metadata and payload states. Display strings never
replace or mutate the raw record used by JSON exports and forensic comparisons.
"""

from __future__ import annotations

import math
from collections.abc import Callable

try:
    import tkinter as tk
    from tkinter import font as tkfont
    from tkinter import ttk
except ImportError:
    tk = None

from .presentation import display_statuses
from .reports import safe_text

MIN_FONT_SIZE = 9
MAX_FONT_SIZE = 16
_UNKNOWN = "Tidak diketahui / tidak tersedia"

# key, human label, offer a per-field copy button, use a monospaced value.
_SECTIONS = {
    "Ringkasan": (
        ("metadata_status", "Metadata", False, False),
        ("payload_status", "Payload", False, False),
        ("original_path", "Path asli", True, True),
        ("original_size", "Ukuran asli (byte)", False, True),
        ("deleted_at_utc", "Dihapus UTC", True, True),
        ("deleted_at_display", "Waktu tampilan", True, True),
        ("source_path", "Path bukti", True, True),
        ("issues", "Catatan", True, False),
    ),
    "Metadata": (
        ("metadata_status", "Metadata", False, False),
        ("format_version", "Versi format", False, True),
        ("original_path", "Path asli", True, True),
        ("original_size", "Ukuran asli (byte)", False, True),
        ("deletion_filetime", "FILETIME mentah", True, True),
        ("deleted_at_utc", "Dihapus UTC", True, True),
        ("deleted_at_display", "Waktu tampilan", True, True),
        ("sid", "SID (konteks)", True, True),
        ("source_size", "Ukuran sumber (byte)", False, True),
    ),
    "Payload": (
        ("payload_status", "Payload", False, False),
        ("payload_path", "Path payload", True, True),
        ("payload_size", "Ukuran payload (byte)", False, True),
        ("size_matches_metadata", "Ukuran vs metadata", False, False),
        ("hash_status", "Pemeriksaan hash", False, False),
        ("payload_sha256", "SHA-256 payload $R", True, True),
    ),
    "Hash & sumber": (
        ("record_type", "Jenis record", False, True),
        ("source_path", "Path bukti", True, True),
        ("source_size", "Ukuran sumber (byte)", False, True),
        ("source_sha256", "SHA-256 sumber", True, True),
        ("payload_path", "Path payload", True, True),
        ("payload_sha256", "SHA-256 payload $R", True, True),
        ("hash_context", "Arti hash sumber", False, False),
        ("issues", "Catatan", True, False),
    ),
}


def _display(value: object | None) -> str:
    return _UNKNOWN if value is None else safe_text(value)


class DetailView(ttk.Frame if tk is not None else object):
    """A compact detail notebook with selectable values and explicit copies."""

    def __init__(
        self,
        parent,
        *,
        ui_font: str,
        mono_font: str,
        font_size: int = 11,
        on_status: Callable[[str], None] | None = None,
    ) -> None:
        if tk is None:
            raise RuntimeError("Tkinter diperlukan untuk menampilkan detail temuan.")
        self._validate_size(font_size)
        super().__init__(parent)
        self.record: dict | None = None
        self.ui_font = ui_font
        self.mono_font = mono_font
        self.font_size = font_size
        self.on_status = on_status
        self.values: dict[str, str] = {}
        self.field_widgets: dict[tuple[str, str], object] = {}
        self.copy_buttons: dict[tuple[str, str], object] = {}
        self._labels: list[object] = []
        self._canvases: list[object] = []
        self._bodies: list[object] = []
        self._field_mono: dict[tuple[str, str], bool] = {}
        toolbar = ttk.Frame(self, padding=(0, 6, 0, 0))
        toolbar.pack(side="bottom", fill="x")
        self.copy_all_button = ttk.Button(
            toolbar, text="Salin seluruh detail", command=self.copy_details
        )
        self.copy_all_button.pack(side="left")
        self.copy_hash_button = ttk.Button(toolbar, text="Salin hash", command=self.copy_hash)
        self.copy_hash_button.pack(side="left", padx=6)
        self.notebook = ttk.Notebook(self)
        for title, fields in _SECTIONS.items():
            page = ttk.Frame(self.notebook)
            self.notebook.add(page, text=title)
            canvas = tk.Canvas(page, highlightthickness=0, background="white")
            scrollbar = ttk.Scrollbar(page, orient="vertical", command=canvas.yview)
            canvas.configure(yscrollcommand=scrollbar.set)
            scrollbar.pack(side="right", fill="y")
            canvas.pack(fill="both", expand=True)
            body = ttk.Frame(canvas, padding=(10, 6))
            body.columnconfigure(1, weight=1)
            window = canvas.create_window((0, 0), window=body, anchor="nw")
            body.bind("<Configure>", lambda _, c=canvas: c.configure(scrollregion=c.bbox("all")))
            canvas.bind(
                "<Configure>",
                lambda event, c=canvas, w=window: self._resize_page(c, w, event.width),
            )
            canvas.bind("<MouseWheel>", lambda event, c=canvas: self._scroll_page(c, event))
            canvas.bind("<Button-4>", lambda _, c=canvas: c.yview_scroll(-2, "units"))
            canvas.bind("<Button-5>", lambda _, c=canvas: c.yview_scroll(2, "units"))
            self._canvases.append(canvas)
            self._bodies.append(body)
            for row, (key, label, copy, mono) in enumerate(fields):
                name = ttk.Label(body, text=label, font=(self.ui_font, self.font_size))
                name.grid(row=row, column=0, sticky="nw", padx=(0, 14), pady=4)
                self._labels.append(name)
                self._bind_page_scroll(name, canvas)
                value = tk.Text(
                    body,
                    width=1,
                    height=1,
                    wrap="word",
                    borderwidth=0,
                    background="white",
                    foreground="#172630",
                    padx=4,
                    pady=2,
                    font=(self.mono_font if mono else self.ui_font, self.font_size),
                    state="disabled",
                    exportselection=False,
                    takefocus=True,
                )
                value.grid(row=row, column=1, sticky="ew", pady=3)
                value.bind("<Configure>", lambda _, widget=value: self._fit_value(widget))
                value.bind("<Control-a>", lambda _, widget=value: self._select_all(widget))
                # The page scrollbar remains useful even when the pointer is
                # over a readonly value rather than the canvas background.
                value.bind(
                    "<MouseWheel>",
                    lambda event, c=canvas, w=value: self._scroll_value(
                        w, c, -2 if event.delta > 0 else 2
                    ),
                )
                value.bind("<Button-4>", lambda _, c=canvas, w=value: self._scroll_value(w, c, -2))
                value.bind("<Button-5>", lambda _, c=canvas, w=value: self._scroll_value(w, c, 2))
                self.field_widgets[(title, key)] = value
                self._field_mono[(title, key)] = mono
                if copy:
                    button = ttk.Button(
                        body, text="Salin", width=6, command=lambda name=key: self.copy_value(name)
                    )
                    button.grid(row=row, column=2, sticky="ne", padx=(8, 0), pady=2)
                    self.copy_buttons[(title, key)] = button
                    self._bind_page_scroll(button, canvas)
        self.empty = ttk.Label(
            self,
            text="Pilih baris hasil untuk melihat detail.",
            anchor="center",
            font=(self.ui_font, self.font_size),
        )
        self.set_record(None)

    @staticmethod
    def _validate_size(size: int) -> None:
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or not MIN_FONT_SIZE <= size <= MAX_FONT_SIZE
        ):
            raise ValueError(f"Ukuran teks harus berupa angka {MIN_FONT_SIZE}–{MAX_FONT_SIZE}.")

    @staticmethod
    def _select_all(widget) -> str:
        widget.tag_add("sel", "1.0", "end-1c")
        widget.mark_set("insert", "1.0")
        return "break"

    @staticmethod
    def _scroll_units(canvas, units: int) -> str:
        canvas.yview_scroll(units, "units")
        return "break"

    def _scroll_page(self, canvas, event) -> str:
        if not event.delta:
            return "break"
        delta = -1 if event.delta > 0 else 1
        return self._scroll_units(canvas, delta * 2)

    def _bind_page_scroll(self, widget, canvas) -> None:
        widget.bind("<MouseWheel>", lambda event, c=canvas: self._scroll_page(c, event))
        widget.bind("<Button-4>", lambda _, c=canvas: self._scroll_units(c, -2))
        widget.bind("<Button-5>", lambda _, c=canvas: self._scroll_units(c, 2))

    def _scroll_value(self, widget, canvas, units: int) -> str:
        first, last = widget.yview()
        if (units < 0 and first > 0) or (units > 0 and last < 1):
            widget.yview_scroll(units, "units")
            return "break"
        return self._scroll_units(canvas, units)

    def _resize_page(self, canvas, window, width: int) -> None:
        canvas.itemconfigure(window, width=max(1, width))

    @staticmethod
    def _fit_value(widget) -> None:
        text = widget.get("1.0", "end-1c")
        # Keep the complete value visible; the page, rather than a tiny nested
        # viewport, scrolls when a path or warning has many wrapped lines.
        if widget.winfo_ismapped():
            # Text wraps at word boundaries, not at the average line width.
            # Ask Tk for the real display-line count, including its last line.
            lines = (
                int(widget.tk.call(widget._w, "count", "-update", "-displaylines", "1.0", "end-1c"))
                + 1
            )
        else:
            width = max(60, widget.winfo_width() - 12)
            font = tkfont.Font(root=widget, font=widget.cget("font"))
            lines = sum(max(1, math.ceil(font.measure(line) / width)) for line in text.split("\n"))
        height = min(512, max(1, lines))
        if int(widget.cget("height")) != height:
            widget.configure(height=height)

    def set_font_size(self, size: int) -> None:
        self._validate_size(size)
        self.font_size = size
        self.empty.configure(font=(self.ui_font, size))
        for label in self._labels:
            label.configure(font=(self.ui_font, size))
        for position, widget in self.field_widgets.items():
            widget.configure(
                font=(self.mono_font if self._field_mono[position] else self.ui_font, size)
            )
            self._fit_value(widget)

    def set_record(self, record: dict | None) -> None:
        self.record = record
        self.values = self._values(record) if record is not None else {}
        for (section, key), widget in self.field_widgets.items():
            widget.configure(state="normal")
            widget.delete("1.0", "end")
            widget.insert("1.0", self.values.get(key, ""))
            widget.configure(state="disabled")
            self._fit_value(widget)
            button = self.copy_buttons.get((section, key))
            if button is not None:
                button.configure(
                    state="normal"
                    if record is not None and self.values.get(key) != _UNKNOWN
                    else "disabled"
                )
        for canvas in self._canvases:
            canvas.yview_moveto(0)
        if record is None:
            self.notebook.pack_forget()
            self.empty.pack(fill="both", expand=True)
        else:
            self.empty.pack_forget()
            self.notebook.pack(fill="both", expand=True)
        self.copy_all_button.configure(state="normal" if record is not None else "disabled")
        has_hash = record is not None and bool(
            (record.get("payload") or {}).get("sha256") or record.get("source_sha256")
        )
        self.copy_hash_button.configure(state="normal" if has_hash else "disabled")

    @staticmethod
    def _values(record: dict) -> dict[str, str]:
        metadata = record.get("metadata") or {}
        payload = record.get("payload") or {}
        metadata_status, payload_status = display_statuses(record)
        size_match = payload.get("size_matches_metadata")
        issues = record.get("issues") or []
        values = {
            "metadata_status": metadata_status,
            "payload_status": payload_status,
            "record_type": record.get("record_type"),
            "source_path": record.get("source_path"),
            "source_size": record.get("source_size"),
            "source_sha256": record.get("source_sha256"),
            "sid": record.get("sid"),
            "original_path": metadata.get("original_path"),
            "original_size": metadata.get("original_size"),
            "format_version": metadata.get("format_version"),
            "deletion_filetime": metadata.get("deletion_filetime"),
            "deleted_at_utc": metadata.get("deleted_at_utc"),
            "deleted_at_display": metadata.get("deleted_at_display"),
            "payload_path": payload.get("path"),
            "payload_size": payload.get("size"),
            "payload_sha256": payload.get("sha256"),
            "size_matches_metadata": "Sesuai"
            if size_match is True
            else "Berbeda"
            if size_match is False
            else "Tidak dapat dibandingkan",
            "hash_status": {
                "computed": "Dihitung",
                "not_requested": "Tidak diminta",
                "unavailable": "Tidak tersedia",
                "not_applicable": "Tidak berlaku untuk folder",
            }.get(payload.get("hash_status"), "Tidak tersedia"),
            "hash_context": (
                "Sumber adalah payload $R untuk record orphan; bukan metadata $I."
                if record.get("record_type") == "orphan_payload"
                else "Hash sumber tidak tersedia untuk item penemuan/dilewati. Hash payload, jika tersedia, berasal dari pasangan $R yang dibaca dengan aman."
                if record.get("record_type") == "discovery"
                else "Hash sumber mengacu pada byte artefak $I; hash payload mengacu pada isi $R."
            ),
            "issues": "\n".join(
                f"[{issue.get('severity', 'warning')}] {issue.get('code', '')}: {issue.get('message', '')}"
                for issue in issues
            )
            if issues
            else "Tidak ada catatan pada record ini.",
        }
        rendered = {key: _display(value) for key, value in values.items()}
        # Newlines below are our issue separators. Escape only evidence text,
        # otherwise several warnings become one unreadable literal-escape line.
        if issues:
            rendered["issues"] = "\n".join(
                f"[{safe_text(issue.get('severity', 'warning'))}] {safe_text(issue.get('code', ''))}: {safe_text(issue.get('message', ''))}"
                for issue in issues
            )
        return rendered

    def get_value(self, key: str) -> str:
        return self.values.get(key, "")

    def get_text(self) -> str:
        if self.record is None:
            return "Pilih baris hasil untuk melihat detail."
        return "\n\n".join(
            section
            + "\n"
            + "\n".join(label + ": " + self.values[key] for key, label, _, _ in fields)
            for section, fields in _SECTIONS.items()
        )

    def _copy(self, value: str, description: str) -> bool:
        if self.record is None:
            return False
        self.clipboard_clear()
        self.clipboard_append(value)
        if self.on_status is not None:
            self.on_status(description + " disalin.")
        return True

    def copy_value(self, key: str) -> bool:
        if self.record is None or self.values.get(key) in (None, _UNKNOWN):
            return False
        label = next(
            (label for fields in _SECTIONS.values() for name, label, _, _ in fields if name == key),
            key,
        )
        return self._copy(self.values[key], label)

    def copy_details(self) -> bool:
        return self._copy(self.get_text(), "Seluruh detail")

    def copy_hash(self) -> bool:
        if self.record is None:
            return False
        payload = self.record.get("payload") or {}
        if payload.get("sha256"):
            return self._copy(safe_text(payload["sha256"]), "SHA-256 payload $R")
        if self.record.get("source_sha256"):
            return self._copy(safe_text(self.record["source_sha256"]), "SHA-256 sumber")
        return False
