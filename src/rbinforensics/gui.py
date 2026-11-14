"""Local desktop presentation. Only the Tk thread ever updates widgets."""

from __future__ import annotations

import argparse
import calendar
import gc
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import time
import webbrowser
from datetime import date
from pathlib import Path
from queue import Empty
from zoneinfo import ZoneInfo

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
    from tkinter import font as tkfont
except ImportError:
    tk = None

from . import __version__
from .analysis import FilterOptions, selected_records
from .desktop import DesktopSession
from .detail_view import DetailView
from .limits import WorkLimitExceeded, WorkLimits, operation_budget
from .presentation import record_label, sort_records
from .reports import safe_text
from .scan_control import ScanProgress
from .scanner import ScanOptions

PAGE_SIZE = 200
BG = "#f4f6f8"
INK = "#172630"
TEAL = "#087e83"
MUTED = "#5d6c76"


class DatePicker(tk.Toplevel if tk is not None else object):
    def __init__(self, parent, variable) -> None:
        super().__init__(parent)
        self.title("Pilih tanggal UTC")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.bind("<Escape>", lambda _: self.destroy())
        self.variable = variable
        try:
            initial = date.fromisoformat(variable.get()[:10])
        except ValueError:
            initial = date.today()
        self.year, self.month = initial.year, initial.month
        self.panel = ttk.Frame(self, padding=14)
        self.panel.pack()
        self._draw()

    def _move(self, delta: int) -> None:
        absolute = self.year * 12 + self.month - 1 + delta
        year, month = divmod(absolute, 12)
        if 1 <= year <= 9999:
            self.year, self.month = year, month + 1
            self._draw()

    def _choose(self, day: int) -> None:
        self.variable.set(date(self.year, self.month, day).isoformat())
        self.destroy()

    def _draw(self) -> None:
        for child in self.panel.winfo_children():
            child.destroy()
        ttk.Button(self.panel, text="<", width=3, command=lambda: self._move(-1)).grid(
            row=0, column=0
        )
        ttk.Label(self.panel, text=f"{self.year:04d}-{self.month:02d}", anchor="center").grid(
            row=0, column=1, columnspan=5
        )
        ttk.Button(self.panel, text=">", width=3, command=lambda: self._move(1)).grid(
            row=0, column=6
        )
        for column, day in enumerate(("Sen", "Sel", "Rab", "Kam", "Jum", "Sab", "Min")):
            ttk.Label(self.panel, text=day, anchor="center").grid(row=1, column=column, pady=8)
        for row, week in enumerate(calendar.Calendar().monthdayscalendar(self.year, self.month), 2):
            for column, day in enumerate(week):
                if day:
                    ttk.Button(
                        self.panel, text=str(day), width=4, command=lambda d=day: self._choose(d)
                    ).grid(row=row, column=column, padx=1, pady=1)


class WorkspacePane(tk.PanedWindow if tk is not None else object):
    """Visible native resize handle, with a vertical sash position helper."""

    def sashpos(self, index: int, position: int | None = None) -> int:
        if position is not None:
            self.sash_place(index, 0, position)
        return self.sash_coord(index)[1]


class UnsavedReportDialog(tk.Toplevel if tk is not None else object):
    """Explicit save/discard/cancel choices for the complete scan inventory."""

    def __init__(self, parent) -> None:
        super().__init__(parent)
        self.choice = "cancel"
        self.title("Hasil belum disimpan")
        self.resizable(False, False)
        self.transient(parent)
        panel = ttk.Frame(self, padding=20)
        panel.pack(fill="both", expand=True)
        ttk.Label(
            panel,
            text=(
                "Hasil analisis belum disimpan sebagai JSON. Simpan seluruh inventaris "
                "sebelum melanjutkan?\n\nEkspor CSV atau HTML tidak menggantikan simpan JSON."
            ),
            wraplength=440,
            justify="left",
        ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 18))
        self.buttons = {}
        for column, (choice, label) in enumerate(
            (("save", "Simpan JSON"), ("discard", "Buang hasil"), ("cancel", "Batal"))
        ):
            button = ttk.Button(panel, text=label, command=lambda value=choice: self._choose(value))
            button.grid(row=1, column=column, padx=(0 if column == 0 else 8, 0))
            self.buttons[choice] = button
        self.protocol("WM_DELETE_WINDOW", lambda: self._choose("cancel"))
        self.bind("<Escape>", lambda _: self._choose("cancel"))
        self.update_idletasks()
        x = parent.winfo_rootx() + (parent.winfo_width() - self.winfo_reqwidth()) // 2
        y = parent.winfo_rooty() + (parent.winfo_height() - self.winfo_reqheight()) // 2
        self.geometry(f"+{max(0, x)}+{max(0, y)}")
        self.grab_set()
        self.buttons["cancel"].focus_set()

    def _choose(self, choice: str) -> None:
        self.choice = choice
        self.destroy()


class ForensicsApp(tk.Tk if tk is not None else object):
    """A responsive scan/view/export workflow over one DesktopSession."""

    def __init__(self, session: DesktopSession | None = None) -> None:
        if tk is None:
            raise RuntimeError(
                "Tkinter tidak tersedia. Pasang dukungan Tk untuk Python atau gunakan paket Windows."
            )
        # Finalize any previously destroyed Tk roots on this UI thread before
        # a new worker can trigger Python's cyclic garbage collector.
        gc.collect()
        super().__init__()
        self.session = session or DesktopSession()
        self.title(f"Recycle Bin Forensics — {__version__}")
        width = min(1280, max(1000, self.winfo_screenwidth() - 60))
        height = min(840, max(700, self.winfo_screenheight() - 90))
        self.geometry(f"{width}x{height}")
        self.minsize(1000, 700)
        self.configure(background=BG)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._closing = False
        self._cancel_requested = False
        self._awaiting_terminal = False
        self._unsaved_prompt_active = False
        self._deferred_action: tuple[str, tuple[Path, ScanOptions] | None] | None = None
        self._deferred_export_succeeded = False
        self._poll_id = None
        self._last_export: Path | None = None
        self.detail_window = None
        self._sort_state: dict = {}
        self._split_fraction = 0.48
        self._sash_job = None
        self._last_split_size = None
        self._inputs: list[tuple[object, str]] = []
        self._pages: dict[object, int] = {}
        self._datasets: dict[object, list[dict]] = {}
        self._row_objects: dict[object, dict[str, dict]] = {}
        self._page_labels: dict[object, object] = {}
        self._page_buttons: dict[object, tuple[object, object]] = {}
        self._init_variables()
        self._style()
        self._build()
        self._sync_controls()
        self._poll_id = self.after(50, self._poll_events)

    def _init_variables(self) -> None:
        for name, value in {
            "source": "",
            "timezone": "UTC",
            "case": "",
            "examiner": "",
            "query": "",
            "extension": "",
            "sid": "",
            "after": "",
            "before": "",
            "min_size": "",
            "max_size": "",
            "status": "Siap. Pilih salinan bukti untuk mulai.",
            "summary": "Belum ada analisis.",
            "run_context": "Sumber dan label kasus akan ditampilkan dari hasil scan.",
            "selection": "",
            "metadata_count": "—",
            "orphan_count": "—",
            "review_count": "—",
            "export_status": "",
            "stats": "Metadata: - | Orphan: - | Perlu ditinjau: -",
            "detail_title": "Detail temuan",
            "font_label": "11 pt",
            "selection_count": "",
        }.items():
            setattr(self, name + "_var", tk.StringVar(self, value=value))
        self.recursive_var = tk.BooleanVar(self, value=True)
        self.hash_var = tk.BooleanVar(self, value=False)
        self.case_visible = tk.BooleanVar(self, value=False)
        self.filters_visible = tk.BooleanVar(self, value=False)
        self.font_size_var = tk.IntVar(self, value=11)
        self.limits_visible = tk.BooleanVar(self, value=False)
        self.limit_vars = {
            name: tk.StringVar(self, value=str(value))
            for name, value in WorkLimits().to_dict().items()
        }

    def _style(self) -> None:
        size = self.font_size_var.get()
        families = {family.casefold() for family in tkfont.families(self)}
        self._ui_font = (
            "Segoe UI"
            if "segoe ui" in families
            else tkfont.nametofont("TkDefaultFont").actual("family")
        )
        self._mono_font = (
            "Consolas"
            if "consolas" in families
            else tkfont.nametofont("TkFixedFont").actual("family")
        )
        style = ttk.Style(self)
        style.theme_use("clam")
        tkfont.nametofont("TkTextFont", root=self).configure(family=self._ui_font, size=size)
        tkfont.nametofont("TkDefaultFont", root=self).configure(family=self._ui_font, size=size)
        style.configure(".", font=(self._ui_font, size), foreground=INK, background=BG)
        style.configure("TEntry", font=(self._ui_font, size))
        style.configure("TFrame", background=BG)
        style.configure("Card.TFrame", background="white")
        style.configure("TLabel", background=BG)
        style.configure("Muted.TLabel", foreground=MUTED)
        style.configure("Title.TLabel", font=(self._ui_font, size + 10, "bold"))
        style.configure("Brand.TLabel", font=(self._ui_font, size + 3, "bold"))
        style.configure("Count.TLabel", font=(self._ui_font, 23, "bold"), background="white")
        style.configure("Card.TLabel", background="white")
        style.configure("TButton", padding=(10, 5), background="white", bordercolor="#cbd5dc")
        style.map("TButton", background=[("active", "#e8f5f4"), ("disabled", BG)])
        style.configure("Accent.TButton", background=TEAL, foreground="white")
        style.map("Accent.TButton", background=[("disabled", "#a9bfbe"), ("active", "#05676c")])
        style.configure(
            "Treeview", background="white", fieldbackground="white", rowheight=size * 2 + 10
        )
        style.configure(
            "Treeview.Heading",
            padding=(6, 5),
            font=(self._ui_font, size, "bold"),
            background="#edf2f5",
        )
        style.configure("TNotebook", borderwidth=0)
        style.configure("TNotebook.Tab", padding=(12, 5), background="#e7ecef")
        style.map(
            "TNotebook.Tab", background=[("selected", "white")], foreground=[("selected", TEAL)]
        )
        style.configure(
            "Horizontal.TProgressbar", background=TEAL, troughcolor="#dde6e8", thickness=8
        )

    def _input(self, widget, state: str = "normal"):
        self._inputs.append((widget, state))
        return widget

    def _build(self) -> None:
        top = ttk.Frame(self, padding=(18, 5))
        top.pack(fill="x")
        ttk.Label(top, text="RB   Recycle Bin Forensics", style="Brand.TLabel").pack(side="left")
        ttk.Label(top, text=f"v{__version__}   ·   Lokal / offline", foreground=TEAL).pack(
            side="right"
        )
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=24)
        self.scan_page = ttk.Frame(self.notebook, padding=22)
        self.results_page = ttk.Frame(self.notebook, padding=(12, 4))
        self.help_page = ttk.Frame(self.notebook, padding=22)
        for page, label in (
            (self.scan_page, "Analisis baru"),
            (self.results_page, "Hasil analisis"),
            (self.help_page, "Panduan"),
        ):
            self.notebook.add(page, text=label)
        self._build_scan()
        self._build_results()
        self._build_help()
        bottom = ttk.Frame(self, padding=(18, 6))
        bottom.pack(side="bottom", fill="x", before=self.notebook)
        self.progress = ttk.Progressbar(bottom, mode="indeterminate")
        self.progress.pack(fill="x", pady=(0, 5))
        self.cancel_button = ttk.Button(bottom, text="Batalkan", command=self.cancel_scan)
        self.cancel_button.pack(side="right")
        self.status_label = ttk.Label(
            bottom, textvariable=self.status_var, style="Muted.TLabel", wraplength=900
        )
        self.status_label.pack(side="left", fill="x", expand=True)
        bottom.bind(
            "<Configure>",
            lambda event: self.status_label.configure(wraplength=max(200, event.width - 180)),
        )

    def _build_scan(self) -> None:
        viewport = tk.Canvas(self.scan_page, background=BG, highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.scan_page, orient="vertical", command=viewport.yview)
        viewport.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        viewport.pack(fill="both", expand=True)
        parent = ttk.Frame(viewport)
        window = viewport.create_window((0, 0), window=parent, anchor="nw")
        parent.bind("<Configure>", lambda _: viewport.configure(scrollregion=viewport.bbox("all")))
        viewport.bind(
            "<Configure>", lambda event: viewport.itemconfigure(window, width=event.width)
        )
        self.scan_viewport = viewport
        ttk.Label(parent, text="Analisis Recycle Bin", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            parent,
            text="Pilih salinan artefak. Simpan laporan di luar direktori bukti.",
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(8, 22))
        card = ttk.LabelFrame(parent, text=" Sumber bukti ", padding=18)
        card.pack(fill="x")
        self._input(ttk.Entry(card, textvariable=self.source_var)).pack(fill="x", pady=(2, 14))
        buttons = ttk.Frame(card)
        buttons.pack(fill="x")
        self._input(ttk.Button(buttons, text="Pilih folder", command=self.choose_folder)).pack(
            side="left", padx=(0, 8)
        )
        self._input(ttk.Button(buttons, text="Pilih file $I", command=self.choose_file)).pack(
            side="left"
        )
        options = ttk.Frame(parent, padding=(0, 16))
        options.pack(fill="x")
        self._input(
            ttk.Checkbutton(options, text="Sertakan subfolder", variable=self.recursive_var)
        ).pack(anchor="w", pady=4)
        self._input(
            ttk.Checkbutton(options, text="Hitung SHA-256 isi payload $R", variable=self.hash_var)
        ).pack(anchor="w", pady=4)
        ttk.Label(
            options,
            text="Hash payload menambah waktu baca; isi folder $R tidak di-hash secara rekursif.",
            style="Muted.TLabel",
        ).pack(anchor="w", padx=22)
        zone = ttk.Frame(parent)
        zone.pack(fill="x", pady=(0, 14))
        ttk.Label(zone, text="Zona waktu tampilan").pack(side="left", padx=(0, 18))
        self._input(
            ttk.Combobox(
                zone,
                textvariable=self.timezone_var,
                values=("UTC", "Asia/Jakarta", "Asia/Makassar", "Asia/Jayapura"),
                width=24,
            )
        ).pack(side="left")
        ttk.Label(zone, text="UTC selalu dipertahankan di laporan.", style="Muted.TLabel").pack(
            side="left", padx=16
        )
        self.limits_toggle = self._input(
            ttk.Checkbutton(
                parent,
                text="Atur batas beban — batas baku selalu aktif",
                variable=self.limits_visible,
                command=self._toggle_limits,
            )
        )
        self.limits_toggle.pack(anchor="w", pady=(0, 8))
        self.limits_fields = ttk.LabelFrame(parent, text="Batas per operasi", padding=10)
        for index, (name, label) in enumerate(
            (
                ("max_records", "Jumlah record"),
                ("max_payload_hash_bytes", "Total hash payload (byte)"),
                ("max_metadata_bytes", "Total metadata (byte)"),
                ("max_depth", "Kedalaman folder (akar = 0)"),
                ("max_operation_seconds", "Durasi per operasi (detik)"),
                ("max_export_bytes", "Ukuran laporan (byte)"),
                ("max_visited_entries", "Entri folder diperiksa"),
            )
        ):
            frame = ttk.Frame(self.limits_fields)
            frame.grid(row=index // 3, column=index % 3, sticky="ew", padx=5, pady=4)
            self.limits_fields.columnconfigure(index % 3, weight=1)
            ttk.Label(frame, text=label, wraplength=240).pack(anchor="w")
            self._input(ttk.Entry(frame, textvariable=self.limit_vars[name], width=18)).pack(
                fill="x"
            )
        ttk.Label(
            self.limits_fields,
            text="Batas berlaku saat scan, filter, urut, atau ekspor berikutnya. Batas waktu diperiksa berkala.",
            wraplength=850,
            style="Muted.TLabel",
        ).grid(row=3, column=0, columnspan=3, sticky="w", padx=5, pady=4)
        self.case_toggle = self._input(
            ttk.Checkbutton(
                parent,
                text="Informasi kasus — opsional",
                variable=self.case_visible,
                command=self._toggle_case,
            )
        )
        self.case_toggle.pack(anchor="w", pady=(0, 8))
        self.case_fields = ttk.Frame(parent)
        for label, variable in (("ID kasus", self.case_var), ("Nama pemeriksa", self.examiner_var)):
            frame = ttk.Frame(self.case_fields)
            frame.pack(side="left", fill="x", expand=True, padx=(0, 12))
            ttk.Label(frame, text=label).pack(anchor="w")
            self._input(ttk.Entry(frame, textvariable=variable)).pack(fill="x", pady=5)
        action = ttk.Frame(parent)
        action.pack(fill="x", pady=20)
        self.start_button = self._input(
            ttk.Button(
                action, text="Mulai analisis", style="Accent.TButton", command=self.start_scan
            )
        )
        self.start_button.pack(side="right")
        ttk.Label(
            parent,
            text="Gunakan working copy terverifikasi atau media read-only. Tool ini tidak melakukan pemulihan disk.",
            style="Muted.TLabel",
            wraplength=950,
        ).pack(anchor="w", pady=12)
        for widget, _ in self._inputs:
            widget.bind("<FocusIn>", self._reveal_scan_input, add="+")

    def _reveal_scan_input(self, event) -> None:
        viewport = self.scan_viewport
        body = event.widget.master
        while body.master != viewport and body is not self:
            body = body.master
        if body.master != viewport:
            return
        top = viewport.canvasy(0)
        y = event.widget.winfo_rooty() - body.winfo_rooty()
        if y < top or y + event.widget.winfo_height() > top + viewport.winfo_height():
            viewport.yview_moveto(max(0, (y - 20) / max(body.winfo_height(), 1)))

    def _toggle_case(self) -> None:
        if self.case_visible.get():
            self.case_fields.pack(fill="x", after=self.case_toggle)
        else:
            self.case_fields.pack_forget()

    def _toggle_limits(self) -> None:
        if self.limits_visible.get():
            self.limits_fields.pack(fill="x", after=self.limits_toggle, pady=(0, 8))
        else:
            self.limits_fields.pack_forget()

    def _limits(self) -> WorkLimits:
        values = {}
        for name, variable in self.limit_vars.items():
            value = variable.get().strip()
            values[name] = float(value) if name == "max_operation_seconds" else int(value)
        return WorkLimits(**values)

    def _build_results(self) -> None:
        parent = self.results_page
        bar = ttk.Frame(parent)
        bar.pack(fill="x")
        bar.columnconfigure(0, weight=1)
        heading = ttk.Frame(bar)
        heading.grid(row=0, column=0, sticky="w")
        ttk.Label(heading, text="Hasil analisis", style="Brand.TLabel").pack(side="left")
        ttk.Label(heading, textvariable=self.selection_count_var, style="Muted.TLabel").pack(
            side="left", padx=10
        )
        controls = ttk.Frame(bar)
        controls.grid(row=0, column=1, sticky="e")

        def fit_toolbar(_event=None) -> None:
            stacked = heading.winfo_reqwidth() + controls.winfo_reqwidth() > bar.winfo_width()
            controls.grid_configure(row=1 if stacked else 0, column=0 if stacked else 1)

        bar.bind("<Configure>", fit_toolbar)
        heading.bind("<Configure>", fit_toolbar)
        controls.bind("<Configure>", fit_toolbar)
        self.export_buttons = []
        for format_name in ("html", "json", "csv"):
            button = ttk.Button(
                controls,
                text=f"Ekspor {format_name.upper()}",
                command=lambda f=format_name: self.export_report(f),
            )
            button.pack(side="right", padx=(4, 0))
            self.export_buttons.append(button)
        fonts = ttk.Frame(controls)
        fonts.pack(side="right", padx=12)
        self.font_smaller = ttk.Button(
            fonts, text="A-", width=3, command=lambda: self.change_font_size(-1)
        )
        self.font_smaller.pack(side="left")
        ttk.Label(fonts, textvariable=self.font_label_var).pack(side="left", padx=5)
        self.font_larger = ttk.Button(
            fonts, text="A+", width=3, command=lambda: self.change_font_size(1)
        )
        self.font_larger.pack(side="left")
        context_row = ttk.Frame(parent)
        context_row.pack(fill="x", pady=2)
        ttk.Label(context_row, textvariable=self.stats_var, foreground=TEAL).pack(
            side="right", padx=(10, 0)
        )
        context = ttk.Entry(
            context_row, textvariable=self.run_context_var, state="readonly", width=20
        )
        context.pack(side="left", fill="x", expand=True)
        self.run_context_entry = context
        quick = ttk.Frame(parent)
        quick.pack(fill="x", pady=(0, 4))
        ttk.Label(quick, text="Cari path / nama").pack(side="left", padx=(0, 8))
        query = ttk.Entry(quick, textvariable=self.query_var, width=20)
        self.filter_toggle = ttk.Button(quick, text="Filter lanjutan", command=self.toggle_filters)
        self.filter_toggle.pack(side="right")
        self.reset_button = ttk.Button(quick, text="Reset", command=self.reset_filters)
        self.reset_button.pack(side="right", padx=4)
        self.apply_button = ttk.Button(quick, text="Terapkan", command=self.apply_filters)
        self.apply_button.pack(side="right")
        query.pack(side="left", fill="x", expand=True, padx=(0, 8))
        query.bind("<Return>", lambda _: self.apply_filters())
        self.filter_inputs = [query]
        self.advanced_filters = ttk.LabelFrame(
            parent, text="Filter lanjutan - tanggal UTC", padding=8
        )
        self._advanced_anchor = quick
        fields = (
            ("Ekstensi (.pdf,.docx)", self.extension_var, 18),
            ("SID", self.sid_var, 24),
            ("Ukuran min (byte)", self.min_size_var, 12),
            ("Ukuran maks (byte)", self.max_size_var, 12),
        )
        for column, (label, variable, width) in enumerate(fields):
            frame = ttk.Frame(self.advanced_filters)
            frame.grid(row=0, column=column, sticky="ew", padx=4)
            ttk.Label(frame, text=label).pack(anchor="w")
            entry = ttk.Entry(frame, textvariable=variable, width=width)
            entry.pack(fill="x", pady=3)
            entry.bind("<Return>", lambda _: self.apply_filters())
            self.filter_inputs.append(entry)
            self.advanced_filters.columnconfigure(column, weight=1)
        dates = ttk.Frame(self.advanced_filters)
        dates.grid(row=1, column=0, columnspan=4, sticky="ew", pady=(4, 0))
        for column, (label, variable) in enumerate(
            (("Dari", self.after_var), ("Sampai", self.before_var))
        ):
            dates.columnconfigure(column, weight=1, uniform="date")
            field = ttk.Frame(dates)
            field.grid(row=0, column=column, sticky="ew", padx=4)
            ttk.Label(field, text=label).pack(side="left", padx=(0, 6))
            entry = ttk.Entry(field, textvariable=variable, width=23)
            button = ttk.Button(
                field, text="Kalender", command=lambda v=variable: DatePicker(self, v)
            )
            button.pack(side="right", padx=(4, 0))
            entry.pack(side="left", fill="x", expand=True)
            self.filter_inputs.extend((entry, button))
        self.results_split = WorkspacePane(
            parent,
            orient="vertical",
            sashwidth=10,
            showhandle=True,
            handlesize=10,
            sashrelief="raised",
            background=BG,
            borderwidth=0,
            opaqueresize=True,
        )
        self.results_split.pack(fill="both", expand=True)
        self._table_frame = ttk.Frame(self.results_split)
        self._detail_frame = ttk.Frame(self.results_split)
        self.results_split.add(self._table_frame, minsize=100, stretch="always")
        self.results_split.add(self._detail_frame, minsize=150, stretch="always")
        self.results_split.bind("<Configure>", self._queue_split_layout)
        self.results_split.bind("<ButtonRelease-1>", self._remember_split, add="+")
        self.result_tabs = ttk.Notebook(self._table_frame)
        self.result_tabs.pack(fill="both", expand=True)
        self.result_tabs.bind("<<NotebookTabChanged>>", self._result_tab_changed)
        for attr, label in (
            ("inventory", "Inventaris"),
            ("timeline", "Timeline"),
            ("review", "Perlu ditinjau"),
        ):
            page = ttk.Frame(self.result_tabs)
            self.result_tabs.add(page, text=label)
            tree = ttk.Treeview(
                page,
                columns=("path", "time", "size", "status"),
                show="headings",
                selectmode="browse",
                height=5,
            )
            setattr(self, attr, tree)
            self._sort_state[tree] = None
            for key, title, width in (
                ("path", "Path asli / artefak", 500),
                ("time", "Dihapus (UTC)", 245),
                ("size", "Byte", 110),
                ("status", "Status", 150),
            ):
                tree.heading(key, text=title, command=lambda t=tree, c=key: self.sort_table(t, c))
                tree.column(key, width=width, minwidth=65, stretch=key == "path")
            tree.tag_configure("warning", foreground="#8c560b")
            tree.tag_configure("error", foreground="#b52d43")
            tree.tag_configure("skipped", foreground="#65717e")
            tree.bind("<<TreeviewSelect>>", lambda _, t=tree: self._show_details(t))
            scrollbar = ttk.Scrollbar(page, orient="vertical", command=tree.yview)
            horizontal = ttk.Scrollbar(page, orient="horizontal", command=tree.xview)
            tree.configure(yscrollcommand=scrollbar.set, xscrollcommand=horizontal.set)
            tree.grid(row=0, column=0, sticky="nsew")
            scrollbar.grid(row=0, column=1, sticky="ns")
            horizontal.grid(row=1, column=0, sticky="ew")
            footer = ttk.Frame(page)
            footer.grid(row=2, column=0, columnspan=2, sticky="ew", pady=3)
            previous = ttk.Button(
                footer, text="<", width=3, command=lambda t=tree: self._change_page(t, -1)
            )
            previous.pack(side="left")
            label_widget = ttk.Label(footer, text="Belum ada hasil", style="Muted.TLabel")
            label_widget.pack(side="left", padx=8)
            following = ttk.Button(
                footer, text=">", width=3, command=lambda t=tree: self._change_page(t, 1)
            )
            following.pack(side="right")
            self._page_labels[tree] = label_widget
            self._page_buttons[tree] = previous, following
            self._pages[tree] = 0
            self._datasets[tree] = []
            self._row_objects[tree] = {}
            page.columnconfigure(0, weight=1)
            page.rowconfigure(0, weight=1)
        detail_header = ttk.Frame(self._detail_frame)
        self.detail_header = detail_header
        detail_header.pack(fill="x", pady=(0, 2))
        self.detail_button = ttk.Button(
            detail_header, text="Perbesar detail", command=self.open_details
        )
        self.detail_button.pack(side="right")
        ttk.Label(detail_header, textvariable=self.detail_title_var, style="Brand.TLabel").pack(
            side="left"
        )
        ttk.Label(
            detail_header, text="Tarik pembatas untuk mengatur tinggi", style="Muted.TLabel"
        ).pack(side="right", padx=12)
        self.detail_panel = DetailView(
            self._detail_frame,
            ui_font=self._ui_font,
            mono_font=self._mono_font,
            font_size=self.font_size_var.get(),
            on_status=self.status_var.set,
        )
        self.detail_panel.pack(fill="both", expand=True)
        export_bar = ttk.Frame(parent)
        export_bar.pack(side="bottom", fill="x", pady=(4, 0), before=self.results_split)
        self.open_button = ttk.Button(
            export_bar, text="Buka laporan HTML", command=self.open_report
        )
        self.open_button.pack(side="right", padx=4)
        self.location_button = ttk.Button(
            export_bar, text="Buka lokasi laporan", command=self.open_report_location
        )
        self.location_button.pack(side="right")
        ttk.Label(
            export_bar, textvariable=self.export_status_var, style="Muted.TLabel", wraplength=420
        ).pack(side="left", fill="x", expand=True)

    def toggle_filters(self) -> None:
        visible = not self.filters_visible.get()
        self.filters_visible.set(visible)
        if visible:
            self.advanced_filters.pack(fill="x", pady=(0, 6), after=self._advanced_anchor)
        else:
            self.advanced_filters.pack_forget()
        self._update_filter_indicator()

    def _update_filter_indicator(self) -> None:
        filters = (self.session.view or {}).get("selection", {}).get("filters", {})
        count = sum(
            value is not None and value != [] and value != ""
            for key, value in filters.items()
            if key != "query"
        )
        title = "Tutup filter" if self.filters_visible.get() else "Filter lanjutan"
        self.filter_toggle.configure(text=title + (f" ({count} aktif)" if count else ""))

    def _queue_split_layout(self, _event=None) -> None:
        if _event is not None:
            size = (_event.width, _event.height)
            if size == self._last_split_size:
                return
            self._last_split_size = size
        if self._sash_job is not None:
            self.after_cancel(self._sash_job)
        self._sash_job = self.after_idle(self._place_split)

    def _place_split(self) -> None:
        self._sash_job = None
        height = self.results_split.winfo_height()
        if height < 120:
            return
        usable = max(1, height - 10)
        active = self.result_tabs.select()
        tree = next((tree for tree in self._datasets if str(tree.master) == active), self.inventory)
        table_chrome = max(
            self.result_tabs.winfo_reqheight() - tree.winfo_reqheight(),
            0,
        )
        detail_chrome = self.detail_header.winfo_reqheight() + 2
        wanted_table = table_chrome + 100
        wanted_detail = detail_chrome + 150
        if usable >= wanted_table + wanted_detail:
            table_min, detail_min = wanted_table, wanted_detail
        else:
            # Share a genuine shortfall in proportion to the requested space;
            # crossing the threshold by one pixel must not discard a row.
            available = max(1, usable - 2)
            table_min = int(available * wanted_table / (wanted_table + wanted_detail))
            detail_min = available - table_min
        self.results_split.paneconfigure(self._table_frame, minsize=table_min)
        self.results_split.paneconfigure(self._detail_frame, minsize=detail_min)
        position = max(
            table_min + 1, min(int(usable * self._split_fraction), usable - detail_min - 1)
        )
        self.results_split.sash_place(0, 0, position)

    def _remember_split(self, _event=None) -> None:
        height = self.results_split.winfo_height()
        if height > 10:
            self._split_fraction = max(
                0.15, min(0.85, self.results_split.sash_coord(0)[1] / (height - 10))
            )

    def change_font_size(self, delta: int) -> None:
        size = max(9, min(16, self.font_size_var.get() + delta))
        self.font_size_var.set(size)
        self.font_label_var.set(f"{size} pt")
        self._style()
        self._help_text.configure(font=(self._ui_font, size + 1))
        self.detail_panel.set_font_size(size)
        if self.detail_window is not None and self.detail_window.winfo_exists():
            self.detail_window.detail_view.set_font_size(size)
        self._queue_split_layout()
        self._sync_controls()

    def sort_table(self, tree, column: str) -> None:
        if self._closing:
            return
        previous = self._sort_state[tree]
        descending = not previous[1] if previous is not None and previous[0] == column else False
        try:
            with operation_budget(self._limits(), operation="sort") as budget:
                budget.check_record_count(len(self._datasets[tree]))
                ordered = sort_records(self._datasets[tree], column, descending)
        except (ValueError, WorkLimitExceeded) as exc:
            self._dialog_error("Pengurutan belum selesai", exc)
            return
        self._sort_state[tree] = (column, descending)
        self._datasets[tree] = ordered
        self._pages[tree] = 0
        self._update_sort_heading(tree)
        self._display_page(tree)

    def _update_sort_heading(self, tree) -> None:
        state = self._sort_state[tree]
        titles = {
            "path": "Path asli / artefak",
            "time": "Dihapus (UTC)",
            "size": "Byte",
            "status": "Status",
        }
        for column, title in titles.items():
            suffix = (" [turun]" if state[1] else " [naik]") if state and state[0] == column else ""
            tree.heading(column, text=title + suffix)

    def _result_tab_changed(self, _event=None) -> None:
        if not hasattr(self, "detail_panel"):
            return
        active = self.result_tabs.select()
        tree = next((tree for tree in self._datasets if str(tree.master) == active), None)
        if tree is None:
            self._update_detail_views(None)
        else:
            self._show_details(tree)

    def open_details(self) -> None:
        record = getattr(self, "_selected_record", None)
        if record is None:
            return
        if self.detail_window is None or not self.detail_window.winfo_exists():
            window = tk.Toplevel(self)
            window.title("Detail temuan")
            window.geometry(
                f"{min(1100, max(700, self.winfo_screenwidth() - 100))}x{min(760, max(450, self.winfo_screenheight() - 120))}"
            )
            window.minsize(640, 420)
            window.detail_view = DetailView(
                window,
                ui_font=self._ui_font,
                mono_font=self._mono_font,
                font_size=self.font_size_var.get(),
                on_status=self.status_var.set,
            )
            window.detail_view.pack(fill="both", expand=True, padx=16, pady=12)
            window.protocol("WM_DELETE_WINDOW", self._close_details)
            self.detail_window = window
        self.detail_window.detail_view.set_record(record)
        self.detail_window.title("Detail temuan - " + safe_text(record["source_name"]))
        self.detail_window.deiconify()
        self.detail_window.lift()

    def _close_details(self) -> None:
        if self.detail_window is not None:
            self.detail_window.destroy()
            self.detail_window = None

    def _update_detail_views(self, record: dict | None) -> None:
        self._selected_record = record
        self.detail_panel.set_record(record)
        self.detail_title_var.set(
            "Detail: " + safe_text(record["source_name"]) if record else "Detail temuan"
        )
        if self.detail_window is not None and self.detail_window.winfo_exists():
            self.detail_window.detail_view.set_record(record)
            self.detail_window.title(
                "Detail temuan - "
                + (safe_text(record["source_name"]) if record else "Pilih record")
            )
        self._sync_controls()

    def _build_help(self) -> None:
        text = (
            "Mulai analisis\n\n1. Pilih file $I atau direktori salinan bukti. Aktifkan subfolder untuk struktur volume/SID.\n"
            "2. Pilih hashing payload jika perlu membandingkan isi file. File besar membutuhkan waktu baca tambahan.\n"
            "3. Tekan Mulai analisis. Penemuan kandidat belum memiliki persentase; setelah jumlah diketahui, progress menghitung item selesai.\n"
            "4. Periksa Inventaris, Timeline, dan Perlu ditinjau. Pilih baris untuk melihat detail dan hash.\n"
            "5. Ekspor laporan ke direktori terpisah. JSON mempertahankan seluruh inventaris dan pilihan filter.\n\n"
            "Arti status\nOK: metadata berhasil dibaca; tetap perlu interpretasi.\nOrphan: nama $R tidak memiliki counterpart $I dalam scope. Path asli dan waktu tetap tidak diketahui.\n"
            "Payload hilang: metadata tersedia tetapi pasangan konten tidak ditemukan.\nError / dilewati: sebagian scope belum dapat diproses; periksa rincian.\n\n"
            "Filter dan waktu\nTanggal GUI memakai UTC. Tanggal akhir tanpa jam mencakup satu hari penuh sampai 23:59:59.9999999 UTC. "
            "Timestamp ISO dengan offset juga diterima. Zona tampilan tidak mengubah waktu mentah. Error dan item dilewati tetap terlihat.\n\n"
            "Batas pemeriksaan\nTool membaca artefak yang disediakan, tidak mengakuisisi disk atau membuktikan siapa yang menghapus. "
            "Gunakan working copy atau media read-only; pembacaan filesystem writable dapat memperbarui access time.\n\n"
            "Pembatalan\nPembatalan bersifat kooperatif saat scanner mencapai checkpoint. Scan yang dibatalkan tidak mempunyai laporan lengkap dan tidak dapat diekspor. "
            "Tunggu pekerjaan berhenti sebelum menutup aplikasi.\n"
        )
        help_text = tk.Text(
            self.help_page,
            wrap="word",
            background="white",
            foreground=INK,
            borderwidth=0,
            padx=22,
            pady=20,
            font=(self._ui_font, 11),
        )
        self._help_text = help_text
        help_text.pack(fill="both", expand=True)
        help_text.insert("1.0", text)
        help_text.configure(state="disabled")

    def choose_folder(self) -> None:
        path = filedialog.askdirectory(parent=self, title="Pilih direktori salinan bukti")
        if path:
            self.source_var.set(path)

    def choose_file(self) -> None:
        path = filedialog.askopenfilename(
            parent=self,
            title="Pilih metadata $I",
            filetypes=(("Metadata Recycle Bin", "$I*"), ("Semua file", "*")),
        )
        if path:
            self.source_var.set(path)

    def _dialog_error(self, title: str, error: object) -> None:
        messagebox.showerror(title, safe_text(error), parent=self)

    def _prompt_unsaved_report(self) -> str:
        dialog = UnsavedReportDialog(self)
        self.wait_window(dialog)
        return dialog.choice

    def _guard_unsaved_report(self, action: tuple[str, tuple[Path, ScanOptions] | None]) -> bool:
        if not self.session.has_unsaved_report:
            return True
        self._unsaved_prompt_active = True
        try:
            choice = self._prompt_unsaved_report()
        finally:
            self._unsaved_prompt_active = False
        if choice == "discard":
            return True
        if choice == "save":
            self._deferred_action = action
            self._deferred_export_succeeded = False
            if not self.export_report("json"):
                self._deferred_action = None
        return False

    def _worker_running(self) -> bool:
        return self.session.worker is not None and self.session.worker.is_alive()

    def start_scan(self) -> None:
        if (
            self._closing
            or self._unsaved_prompt_active
            or self._deferred_action is not None
            or self._worker_running()
            or self.session.state in ("scanning", "filtering", "exporting")
            or self._awaiting_terminal
        ):
            return
        if not self.source_var.get().strip():
            self._dialog_error(
                "Sumber belum dipilih", "Pilih file $I atau folder bukti terlebih dahulu."
            )
            return
        try:
            zone = self.timezone_var.get().strip() or "UTC"
            if zone != "UTC":
                ZoneInfo(zone)
            options = ScanOptions(
                self.recursive_var.get(),
                self.hash_var.get(),
                zone,
                self.case_var.get().strip() or None,
                self.examiner_var.get().strip() or None,
                self._limits(),
            )
            source = Path(self.source_var.get()).expanduser()
        except Exception as exc:
            self._dialog_error("Analisis tidak dapat dimulai", exc)
            return
        if self._guard_unsaved_report(("scan", (source, options))):
            self._begin_scan(source, options)

    def _begin_scan(self, source: Path, options: ScanOptions) -> None:
        try:
            self.session.start_scan(source, options)
        except Exception as exc:
            self._dialog_error("Analisis tidak dapat dimulai", exc)
            return
        self._clear_results()
        self._awaiting_terminal = True
        self._cancel_requested = False
        self.status_var.set("Mencari kandidat artefak…")
        self.progress.configure(mode="indeterminate", value=0)
        self.progress.start(15)
        self._sync_controls()

    def cancel_scan(self) -> None:
        if self.session.cancel():
            self._cancel_requested = True
            self.status_var.set(
                "Pembatalan diminta. Menunggu pembacaan berhenti; hasil belum lengkap."
            )
            self.cancel_button.configure(state="disabled")

    def _filters(self) -> FilterOptions:
        before = self.before_var.get().strip() or None
        if before is not None and re.fullmatch(r"\d{4}-\d{2}-\d{2}", before):
            before += "T23:59:59.9999999Z"
        return FilterOptions(
            query=self.query_var.get().strip() or None,
            extensions=tuple(
                part.strip() for part in self.extension_var.get().split(",") if part.strip()
            ),
            sid=self.sid_var.get().strip() or None,
            deleted_after=self.after_var.get().strip() or None,
            deleted_before=before,
            min_size=int(self.min_size_var.get()) if self.min_size_var.get().strip() else None,
            max_size=int(self.max_size_var.get()) if self.max_size_var.get().strip() else None,
        )

    def apply_filters(self) -> None:
        if self.session.state != "complete" or self._awaiting_terminal:
            return
        try:
            self.session.start_filter(self._filters(), limits=self._limits())
        except Exception as exc:
            self._dialog_error("Filter tidak valid", exc)
            return
        self.status_var.set("Menerapkan filter…")
        self._awaiting_terminal = True
        self.progress.configure(mode="indeterminate", value=0)
        self.progress.start(15)
        self._sync_controls()

    def reset_filters(self) -> None:
        if self.session.state != "complete":
            return
        for variable in (
            self.query_var,
            self.extension_var,
            self.sid_var,
            self.after_var,
            self.before_var,
            self.min_size_var,
            self.max_size_var,
        ):
            variable.set("")
        self.apply_filters()

    def _clear_results(self) -> None:
        for tree in self._datasets:
            self._datasets[tree] = []
            self._pages[tree] = 0
            self._display_page(tree)
        self.metadata_count_var.set("—")
        self.orphan_count_var.set("—")
        self.review_count_var.set("—")
        self.stats_var.set("Metadata: - | Orphan: - | Perlu ditinjau: -")
        self.selection_count_var.set("")
        self.summary_var.set("Belum ada hasil lengkap untuk scan ini.")
        self.run_context_var.set("Belum ada sumber hasil yang lengkap.")
        self.selection_var.set("")
        self._set_details("Pilih baris hasil untuk melihat detail.")
        self._selected_record = None
        self._last_export = None
        self.export_status_var.set("")

    def _load_report(self, report: dict) -> None:
        records = report["records"]
        summary = report["summary"]
        self.run_context_var.set(
            "Sumber: "
            + safe_text(report["input"])
            + "   ·   Kasus: "
            + safe_text(report["options"]["case_id"] or "—")
            + "   ·   Pemeriksa: "
            + safe_text(report["options"]["examiner"] or "—")
        )
        self.metadata_count_var.set(str(summary["parsed"]))
        self.orphan_count_var.set(str(summary["orphan_payloads"]))
        self.review_count_var.set(str(sum(bool(record["issues"]) for record in records)))
        self.stats_var.set(
            f"Metadata {summary['parsed']} | Orphan {summary['orphan_payloads']} | "
            f"Tinjau {self.review_count_var.get()} | Error {summary['errors']} | "
            f"Skip {summary['skipped']} | Hash {summary['payloads_hashed']}"
        )
        self.summary_var.set(
            f"Seluruh scan: {len(records)} record · {summary['errors']} error · {summary['skipped']} dilewati · {summary['payloads_hashed']} hash payload"
        )
        selection = report["selection"]
        self.selection_count_var.set(f"Pilihan {selection['matched']}/{len(records)}")
        self.selection_var.set(
            f"Pilihan: {selection['matched']} / {len(records)} record. Error/dilewati selalu terlihat; tanggal filter UTC."
        )
        self._datasets[self.inventory] = selected_records(report)
        by_source = {
            record["source_path"]: record
            for record in records
            if record["record_type"] == "metadata"
        }
        self._datasets[self.timeline] = [
            by_source[event["source_path"]] for event in report["timeline"]["events"]
        ]
        self._datasets[self.review] = [record for record in records if record["issues"]]
        for tree in self._datasets:
            state = self._sort_state[tree]
            if state is not None:
                self._datasets[tree] = sort_records(self._datasets[tree], state[0], state[1])
            self._update_sort_heading(tree)
            self._pages[tree] = 0
            self._display_page(tree)
        self._update_filter_indicator()
        self._set_details("Pilih baris hasil untuk melihat detail.")
        self._selected_record = None
        self.notebook.select(self.results_page)

    def _change_page(self, tree, delta: int) -> None:
        self._pages[tree] += delta
        self._display_page(tree)

    def _display_page(self, tree) -> None:
        self._selected_record = None
        if hasattr(self, "detail_panel"):
            self._update_detail_views(None)
        records = self._datasets[tree]
        maximum = max(0, (len(records) - 1) // PAGE_SIZE)
        page = min(max(0, self._pages[tree]), maximum)
        self._pages[tree] = page
        children = tree.get_children()
        if children:
            tree.delete(*children)
        self._row_objects[tree] = {}
        start = page * PAGE_SIZE
        for index, record in enumerate(records[start : start + PAGE_SIZE], start):
            metadata = record["metadata"] or {}
            payload = record["payload"] or {}
            path = metadata.get("original_path") or record["source_name"]
            size = metadata.get("original_size", payload.get("size"))
            values = (
                safe_text(path),
                metadata.get("deleted_at_utc") or "Tidak diketahui",
                str(size) if size is not None else "—",
                self._record_label(record),
            )
            iid = str(index)
            tree.insert("", "end", iid=iid, values=values, tags=(record["status"],))
            self._row_objects[tree][iid] = record
        end = min(start + PAGE_SIZE, len(records))
        self._page_labels[tree].configure(
            text=f"{start + 1 if records else 0}-{end} dari {len(records)}"
        )
        previous, following = self._page_buttons[tree]
        previous.configure(state="normal" if page > 0 else "disabled")
        following.configure(state="normal" if page < maximum else "disabled")

    @staticmethod
    def _record_label(record: dict) -> str:
        return record_label(record)

    def _set_details(self, _text: str) -> None:
        self._update_detail_views(None)

    def _show_details(self, tree) -> None:
        if str(tree.master) != self.result_tabs.select():
            return
        selection = tree.selection()
        record = self._row_objects[tree].get(selection[0]) if selection else None
        self._update_detail_views(record)

    def copy_details(self) -> None:
        self.detail_panel.copy_details()

    def copy_hash(self) -> None:
        self.detail_panel.copy_hash()

    def export_report(self, format_name: str, destination: Path | None = None) -> bool:
        if self.session.state != "complete" or self._awaiting_terminal:
            self._dialog_error(
                "Belum ada hasil lengkap", "Ekspor hanya tersedia setelah analisis selesai."
            )
            return False
        try:
            if destination is None:
                path = filedialog.asksaveasfilename(
                    parent=self,
                    title="Simpan laporan di luar direktori bukti",
                    defaultextension="." + format_name,
                    initialfile="recycle-bin-report." + format_name,
                    filetypes=((format_name.upper(), "*." + format_name),),
                )
                if not path:
                    return False
                destination = Path(path)
            self.session.start_export(destination, format_name, limits=self._limits())
        except Exception as exc:
            self._dialog_error("Ekspor gagal", exc)
            return False
        self.status_var.set("Menyimpan laporan…")
        self._awaiting_terminal = True
        self.progress.configure(mode="indeterminate", value=0)
        self.progress.start(15)
        self._sync_controls()
        return True

    def open_report(self) -> None:
        if self._last_export and self._last_export.suffix.lower() in (".html", ".htm"):
            try:
                webbrowser.open(self._last_export.as_uri())
            except Exception as exc:
                self._dialog_error("Tidak dapat membuka laporan", exc)

    def open_report_location(self) -> None:
        if self._last_export:
            try:
                path = str(self._last_export.parent)
                if sys.platform == "win32":
                    os.startfile(path)
                else:
                    subprocess.Popen(["open" if sys.platform == "darwin" else "xdg-open", path])
            except OSError as exc:
                self._dialog_error("Tidak dapat membuka lokasi", exc)

    def _sync_controls(self) -> None:
        state = self.session.state
        busy = (
            state in ("scanning", "filtering", "exporting")
            or self._closing
            or self._awaiting_terminal
            or self._deferred_action is not None
        )
        ready = state == "complete" and not busy
        for widget, normal in self._inputs:
            widget.configure(state="disabled" if busy else normal)
        for widget in (
            *self.export_buttons,
            *self.filter_inputs,
            self.apply_button,
            self.reset_button,
        ):
            widget.configure(state="normal" if ready else "disabled")
        self.cancel_button.configure(
            state="normal"
            if state == "scanning" and not self._closing and not self._cancel_requested
            else "disabled"
        )
        self.open_button.configure(
            state="normal"
            if self._last_export
            and self._last_export.suffix.lower() in (".html", ".htm")
            and not busy
            else "disabled"
        )
        self.location_button.configure(
            state="normal" if self._last_export and not busy else "disabled"
        )
        self.detail_button.configure(
            state="normal"
            if getattr(self, "_selected_record", None) is not None and not self._closing
            else "disabled"
        )
        self.font_smaller.configure(
            state="normal" if self.font_size_var.get() > 9 and not self._closing else "disabled"
        )
        self.font_larger.configure(
            state="normal" if self.font_size_var.get() < 16 and not self._closing else "disabled"
        )
        self.filter_toggle.configure(state="disabled" if self._closing else "normal")

    def _update_progress(self, event: ScanProgress) -> None:
        if self._closing or self._cancel_requested:
            return
        if event.phase == "discovering":
            self.status_var.set("Mencari kandidat artefak… jumlah belum diketahui.")
        elif event.phase == "hashing":
            self.progress.stop()
            self.progress.configure(
                mode="determinate", value=min(99, 100 * event.processed / max(event.total or 1, 1))
            )
            self.status_var.set(
                f"Hashing payload: {event.bytes_processed:,} / {event.bytes_total or 0:,} byte · {event.processed}/{event.total or '?'} item selesai"
            )
        elif event.phase == "processing":
            self.progress.stop()
            self.progress.configure(
                mode="determinate", value=min(99, 100 * event.processed / max(event.total or 1, 1))
            )
            self.status_var.set(
                f"Memproses artefak: {event.processed}/{event.total or 0} item selesai"
            )
        # A complete progress notification alone cannot publish a result.

    def _poll_events(self) -> None:
        latest = None
        for _ in range(2000):
            try:
                kind, payload = self.session.events.get_nowait()
            except Empty:
                break
            if kind == "progress":
                latest = payload
                continue
            latest = None
            self._awaiting_terminal = False
            self._cancel_requested = False
            self.progress.stop()
            if kind in ("complete", "filtered"):
                self.progress.configure(mode="determinate", value=100)
                self._load_report(payload)
                self.status_var.set(
                    "Analisis selesai." if kind == "complete" else "Filter diterapkan."
                )
                if not payload["records"]:
                    self.status_var.set(
                        "Selesai tanpa kandidat. Periksa sumber atau aktifkan subfolder."
                    )
            elif kind == "limited":
                self._deferred_action = None
                self._deferred_export_succeeded = False
                self.progress.configure(mode="determinate", value=0)
                self._clear_results()
                self.status_var.set("Analisis belum lengkap: " + str(payload))
                if not self._closing:
                    self._dialog_error("Batas beban tercapai", payload)
            elif kind == "cancelled":
                self.progress.configure(mode="determinate", value=0)
                self._clear_results()
                self.status_var.set(
                    "Analisis dibatalkan — belum lengkap, tidak ada laporan yang dapat diekspor."
                )
            elif kind in (
                "error",
                "filter_error",
                "export_error",
                "filter_limited",
                "export_limited",
            ):
                self._deferred_action = None
                self._deferred_export_succeeded = False
                self.progress.configure(mode="determinate", value=0)
                self.status_var.set(
                    (
                        "Operasi belum lengkap: "
                        if kind.endswith("_limited")
                        else "Pekerjaan gagal: "
                    )
                    + str(payload)
                )
                if not self._closing:
                    self._dialog_error("Periksa kembali input atau tujuan laporan", payload)
            elif kind == "exported":
                if self._deferred_action is not None:
                    self._deferred_export_succeeded = True
                self.progress.configure(mode="determinate", value=100)
                self._last_export = Path(payload)
                filename = safe_text(Path(payload).name)
                self.export_status_var.set(
                    "Tersimpan: " + (filename if len(filename) <= 120 else filename[:117] + "…")
                )
                self.status_var.set("Laporan berhasil disimpan.")
        if latest is not None and self.session.state == "scanning":
            self._update_progress(latest)
        if self._closing and not self._worker_running() and not self._awaiting_terminal:
            self._closing = False
            if self._guard_unsaved_report(("close", None)):
                self.destroy()
                return
        if self._deferred_export_succeeded and not self._worker_running():
            action = self._deferred_action
            self._deferred_action = None
            self._deferred_export_succeeded = False
            if action is not None and self.session.state == "complete":
                kind, scan_arguments = action
                if kind == "close":
                    self.destroy()
                    return
                assert scan_arguments is not None
                self._begin_scan(*scan_arguments)
        self._sync_controls()
        self._poll_id = self.after(50, self._poll_events)

    def _on_close(self) -> None:
        if self._closing or self._unsaved_prompt_active or self._deferred_action is not None:
            return
        if self._worker_running():
            if not messagebox.askyesno(
                "Pekerjaan masih berjalan",
                "Hentikan scan bila memungkinkan dan tutup setelah pekerjaan berhenti?",
                parent=self,
            ):
                return
            self._closing = True
            self.session.cancel()
            self.status_var.set("Menunggu pekerjaan berhenti sebelum menutup…")
            self._sync_controls()
        elif self._awaiting_terminal:
            self._closing = True
            self._sync_controls()
        else:
            if self._guard_unsaved_report(("close", None)):
                self.destroy()

    def destroy(self) -> None:
        if self._sash_job is not None:
            self.after_cancel(self._sash_job)
            self._sash_job = None
        self._close_details()
        if self._poll_id is not None:
            self.after_cancel(self._poll_id)
            self._poll_id = None
        super().destroy()


def _smoke_test(destination: Path) -> int:
    """Validate the actual frozen GUI, engine, timezone data, and exports."""
    app = ForensicsApp()
    app.withdraw()
    errors: list[str] = []
    app._dialog_error = lambda title, error: errors.append(f"{title}: {error}")
    app.report_callback_exception = lambda kind, value, tb: errors.append(
        f"{kind.__name__}: {value}"
    )
    try:
        with tempfile.TemporaryDirectory(prefix="rbf-smoke-") as folder:
            root = Path(folder).resolve()
            evidence = root / "evidence"
            evidence.mkdir()
            content = b"payload"
            path = (r"C:\Users\Demo\smoke.txt" + "\0").encode("utf-16-le")
            (evidence / "$ISMOKE.txt").write_bytes(
                struct.pack("<QQQI", 2, len(content), 133485408001234567, len(path) // 2) + path
            )
            (evidence / "$RSMOKE.txt").write_bytes(content)
            app.source_var.set(str(evidence))
            app.hash_var.set(True)
            app.timezone_var.set("Asia/Jakarta")
            app.start_scan()

            def wait_for_job() -> None:
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    app.update()
                    if errors:
                        raise RuntimeError("; ".join(errors))
                    if (
                        app.session.state not in ("scanning", "filtering", "exporting")
                        and not app._awaiting_terminal
                        and not (app.session.worker and app.session.worker.is_alive())
                    ):
                        return
                    time.sleep(0.01)
                raise RuntimeError("GUI smoke operation timed out.")

            wait_for_job()
            if app.session.state != "complete":
                raise RuntimeError(app.session.error or "GUI scan did not complete.")
            report = app.session.report
            assert report is not None and report["summary"]["errors"] == 0
            assert report["records"][0]["metadata"]["deleted_at_display"].endswith("+07:00")
            rows = app.inventory.get_children()
            assert len(rows) == 1
            app.inventory.selection_set(rows[0])
            app.inventory.event_generate("<<TreeviewSelect>>")
            app.update()
            assert "smoke.txt" in app.detail_panel.get_text()
            for format_name in ("json", "html"):
                output = root / ("report." + format_name)
                app.export_report(format_name, output)
                wait_for_job()
                assert output.is_file() and output.stat().st_size > 0, app.session.error
                assert app._last_export == output
            result = {
                "status": "ok",
                "version": __version__,
                "tk_version": str(app.tk.call("package", "provide", "Tk")),
                "checks": {
                    "tk": True,
                    "parser": report["summary"]["parsed"] == 1,
                    "widgets": len(app.inventory.get_children()) == 1,
                    "timezone": True,
                    "export": True,
                },
            }
            assert all(result["checks"].values())
            with destination.open("x", encoding="utf-8") as stream:
                json.dump(result, stream, indent=2)
        return 0
    finally:
        app.session.cancel()
        if app.session.worker is not None:
            app.session.worker.join(timeout=5)
        app.destroy()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Recycle Bin Forensics desktop")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--smoke-test", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--smoke-output", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.smoke_test != bool(args.smoke_output):
        parser.error("--smoke-test requires --smoke-output and vice versa")
    try:
        if args.smoke_test:
            return _smoke_test(args.smoke_output)
        app = ForensicsApp()
        app.mainloop()
        return 0
    except Exception as exc:
        text = "Recycle Bin Forensics tidak dapat dimulai: " + safe_text(exc)
        if sys.stderr is not None:
            print(text, file=sys.stderr)
        if args.smoke_test and args.smoke_output is not None:
            try:
                with args.smoke_output.open("x", encoding="utf-8") as stream:
                    json.dump({"status": "error", "version": __version__, "error": text}, stream)
            except OSError:
                pass
        if os.name == "nt" and not args.smoke_test:
            import ctypes

            ctypes.windll.user32.MessageBoxW(None, text, "Recycle Bin Forensics", 0x10)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
