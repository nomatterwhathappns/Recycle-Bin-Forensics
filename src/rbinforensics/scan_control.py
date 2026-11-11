"""Cooperative scan cancellation and immutable progress notifications.

Callbacks run on the scanning thread. GUI clients must enqueue notifications
and update widgets on the UI thread. A cancelled operation never returns a
complete report; callers must label the run incomplete and disable export.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from threading import Event


class ScanCancelled(Exception):
    """The operator cancelled the run; no completed report is available."""


class ProgressCallbackError(Exception):
    """A progress consumer failed, rather than an evidence read failing."""


@dataclass(frozen=True)
class ScanProgress:
    phase: str
    processed: int
    total: int | None
    source_path: str | None = None
    bytes_processed: int = 0
    bytes_total: int | None = None


class ScanControl:
    """A thread-safe cancellation signal and progress callback for one run."""

    def __init__(self, callback: Callable[[ScanProgress], None] | None = None) -> None:
        self._cancelled = Event()
        self._callback = callback

    def cancel(self) -> None:
        """Request cancellation at the next scanner checkpoint."""
        self._cancelled.set()

    def check(self) -> None:
        if self._cancelled.is_set():
            raise ScanCancelled("Scan cancelled; analysis is incomplete.")

    def emit(self, progress: ScanProgress) -> None:
        self.check()
        if self._callback is not None:
            try:
                self._callback(progress)
            except ScanCancelled:
                raise
            except Exception as exc:
                # I/O-shaped callback exceptions must not be caught as a
                # per-file source error by scanner exception boundaries.
                raise ProgressCallbackError("The scan progress callback failed.") from exc
        self.check()
