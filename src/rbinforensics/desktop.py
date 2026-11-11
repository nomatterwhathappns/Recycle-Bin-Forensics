"""Desktop job coordination without importing Tk or touching GUI widgets.

Worker threads communicate through a queue. A cancelled/failed scan never
publishes a report that could be mistaken for a complete analysis. Filters are
views over a complete immutable scan, and export failures keep that scan usable.
"""

from __future__ import annotations

from pathlib import Path
from queue import Empty, SimpleQueue
from threading import Lock, Thread
from time import monotonic

from .analysis import FilterOptions, apply_filters, build_timeline, selected_records
from .output import write_report
from .reports import safe_text
from .scan_control import ScanCancelled, ScanControl, ScanProgress
from .scanner import ScanOptions, scan


class DesktopSession:
    """One desktop session's state, complete results, and background jobs.

    Consume :attr:`events` on the GUI thread with ``get_nowait``. Every terminal
    event is queued only after the matching public state has been updated.
    ``report`` is the full scan; ``view`` has an explicit selection and timeline.
    Neither object should be mutated by a presentation layer.
    """

    def __init__(self) -> None:
        self.report: dict | None = None
        self.view: dict | None = None
        self.state = "idle"
        self.error: str | None = None
        self.events: SimpleQueue[tuple[str, object]] = SimpleQueue()
        self.worker: Thread | None = None
        self._control: ScanControl | None = None
        self._lock = Lock()
        self._job_id = 0
        self._last_progress_at: float | None = None

    def _require_complete(self) -> dict:
        if self.state != "complete" or self.report is None or self.view is None:
            raise RuntimeError("A complete analysis is required before filtering or exporting.")
        return self.view

    def _drain_events(self) -> None:
        while True:
            try:
                self.events.get_nowait()
            except Empty:
                return

    def _launch_worker(self, worker: Thread, failure_state: str, failure_event: str) -> None:
        """Start under the state lock, recovering if the OS rejects a thread."""
        self.worker = worker
        try:
            worker.start()
        except Exception as exc:
            self.worker = None
            self._control = None
            self.state = failure_state
            self.error = safe_text(exc)
            self.events.put((failure_event, self.error))

    def _progress(self, job_id: int, progress: ScanProgress) -> None:
        with self._lock:
            if self._job_id == job_id and self.state == "scanning":
                now = monotonic()
                # Files and hash chunks can finish much faster than the GUI can
                # paint. Bound queue growth without changing scanner callbacks
                # or cancellation checkpoints; phase changes do not bypass the
                # limit. First and complete progress always remain observable.
                if (
                    self._last_progress_at is None
                    or progress.phase == "complete"
                    or now - self._last_progress_at >= 0.05
                ):
                    self._last_progress_at = now
                    self.events.put(("progress", progress))

    def start_scan(self, source: Path, options: ScanOptions) -> None:
        """Start a scan and immediately return, clearing any previous result."""
        with self._lock:
            if self.state in ("scanning", "exporting", "filtering"):
                raise RuntimeError("An analysis, filter, or export is already running.")
            self._drain_events()
            self._job_id += 1
            job_id = self._job_id
            self.report = None
            self.view = None
            self.error = None
            self.state = "scanning"
            self._last_progress_at = None
            control = ScanControl(lambda progress: self._progress(job_id, progress))
            self._control = control
            self._launch_worker(
                Thread(
                    target=self._scan_worker,
                    args=(job_id, Path(source), options, control),
                    name="rbf-analysis",
                    daemon=True,
                ),
                "error",
                "error",
            )

    def _scan_worker(
        self, job_id: int, source: Path, options: ScanOptions, control: ScanControl
    ) -> None:
        try:
            result = scan(source, options, control=control)
            with self._lock:
                # A cancel request that arrived after the last read but before
                # publication still wins over publishing a complete report.
                control.check()
                if self._job_id != job_id:
                    return
                self.report = result
                self.view = result
                self.state = "complete"
                self._control = None
                self.events.put(("complete", result))
        except ScanCancelled:
            with self._lock:
                if self._job_id == job_id:
                    self.report = None
                    self.view = None
                    self.state = "cancelled"
                    self.error = None
                    self._control = None
                    self.events.put(("cancelled", None))
        except Exception as exc:
            with self._lock:
                if self._job_id == job_id:
                    self.report = None
                    self.view = None
                    self.state = "error"
                    self.error = safe_text(exc)
                    self._control = None
                    self.events.put(("error", self.error))

    def cancel(self) -> bool:
        """Request cooperative cancellation; completion is a later queue event."""
        with self._lock:
            if self.state != "scanning" or self._control is None:
                return False
            self._control.cancel()
            return True

    def apply_view(self, filters: FilterOptions) -> dict:
        """Select from the full baseline, never from a previously filtered view."""
        with self._lock:
            self._require_complete()
            assert self.report is not None
            result = apply_filters(self.report, filters)
            result["timeline"] = build_timeline(selected_records(result))
            self.view = result
            self.error = None
            return result

    def start_filter(self, filters: FilterOptions) -> None:
        """Compute a potentially large selected view without blocking the UI."""
        with self._lock:
            self._require_complete()
            assert self.report is not None
            self._drain_events()
            self._job_id += 1
            self.state = "filtering"
            self.error = None
            self._launch_worker(
                Thread(
                    target=self._filter_worker,
                    args=(self._job_id, self.report, filters),
                    name="rbf-filter",
                    daemon=True,
                ),
                "complete",
                "filter_error",
            )

    def _filter_worker(self, job_id: int, report: dict, filters: FilterOptions) -> None:
        try:
            result = apply_filters(report, filters)
            result["timeline"] = build_timeline(selected_records(result))
        except Exception as exc:
            with self._lock:
                if self._job_id == job_id:
                    self.state = "complete"
                    self.error = safe_text(exc)
                    self.events.put(("filter_error", self.error))
            return
        with self._lock:
            if self._job_id == job_id:
                self.view = result
                self.state = "complete"
                self.error = None
                self.events.put(("filtered", result))

    def _prepare_export(self) -> tuple[int, dict]:
        view = self._require_complete()
        self._drain_events()
        self._job_id += 1
        self.state = "exporting"
        self.error = None
        # While exporting, starting another job and changing filters are both
        # rejected. Keeping this reference is therefore a stable export snapshot
        # without a second potentially huge deepcopy on the GUI thread.
        return self._job_id, view

    def _export_worker(
        self,
        job_id: int,
        report: dict,
        destination: Path,
        format_name: str,
        *,
        propagate: bool = False,
    ) -> Path | None:
        try:
            path = write_report(report, destination, format_name)
        except Exception as exc:
            with self._lock:
                if self._job_id == job_id:
                    self.state = "complete"
                    self.error = safe_text(exc)
                    self.events.put(("export_error", self.error))
            if propagate:
                raise
            return None
        with self._lock:
            if self._job_id == job_id:
                self.state = "complete"
                self.error = None
                self.events.put(("exported", path))
        return path

    def start_export(self, destination: Path, format_name: str) -> None:
        """Render and write a complete selected report on a background thread."""
        with self._lock:
            job_id, report = self._prepare_export()
            self._launch_worker(
                Thread(
                    target=self._export_worker,
                    args=(job_id, report, Path(destination), format_name),
                    name="rbf-export",
                    daemon=True,
                ),
                "complete",
                "export_error",
            )

    def export(self, destination: Path, format_name: str) -> Path:
        """Synchronous export for non-GUI callers, with the same state guards."""
        with self._lock:
            job_id, report = self._prepare_export()
        path = self._export_worker(job_id, report, Path(destination), format_name, propagate=True)
        assert path is not None
        return path
