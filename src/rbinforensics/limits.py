"""Cooperative, per-operation workload budgets; never a partial-report success."""

from __future__ import annotations

import math
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass, fields
from time import monotonic


@dataclass(frozen=True)
class WorkLimits:
    max_records: int = 100_000
    max_payload_hash_bytes: int = 10 * 1024**3
    max_metadata_bytes: int = 256 * 1024**2
    max_depth: int = 64
    max_operation_seconds: float = 600.0
    max_export_bytes: int = 128 * 1024**2
    max_visited_entries: int = 1_000_000

    def __post_init__(self) -> None:
        for field in fields(self):
            value = getattr(self, field.name)
            if field.name == "max_operation_seconds":
                try:
                    finite = math.isfinite(value)
                except (TypeError, OverflowError):
                    finite = False
                if (
                    isinstance(value, bool)
                    or not isinstance(value, (int, float))
                    or not finite
                    or value <= 0
                ):
                    raise ValueError("max_operation_seconds must be finite and positive.")
            elif type(value) is not int or value < (0 if field.name == "max_depth" else 1):
                raise ValueError(f"{field.name} must be an integer within its supported range.")

    def to_dict(self) -> dict:
        return asdict(self)


class WorkLimitExceeded(Exception):
    """The named operation is incomplete; it must not publish partial success."""

    def __init__(self, operation: str, resource: str, limit: int | float, observed: int | float):
        self.operation = operation
        self.resource = resource
        self.limit = limit
        self.observed = observed
        super().__init__(
            f"{operation} incomplete: {resource} limit {limit} exceeded (observed {observed})."
        )


class OperationBudget:
    def __init__(self, limits: WorkLimits | None = None, *, operation="operation", control=None):
        if limits is not None and not isinstance(limits, WorkLimits):
            raise TypeError("limits must be WorkLimits or None.")
        self.limits = limits if limits is not None else WorkLimits()
        self.operation = operation
        self.control = control
        self.started = monotonic()
        self.records: set[tuple[str, str]] = set()
        self.visited_entries = 0
        self.payload_hash_bytes = 0
        self.metadata_bytes = 0
        self.export_bytes = 0

    def check(self) -> None:
        if self.control is not None:
            self.control.check()
        elapsed = monotonic() - self.started
        if elapsed > self.limits.max_operation_seconds:
            raise WorkLimitExceeded(
                self.operation, "max_operation_seconds", self.limits.max_operation_seconds, elapsed
            )

    def _check_limit(self, resource: str, observed: int) -> None:
        self._amount(observed)
        self.check()
        limit = getattr(self.limits, resource)
        if observed > limit:
            raise WorkLimitExceeded(self.operation, resource, limit, observed)

    @staticmethod
    def _amount(value: int) -> None:
        if type(value) is not int or value < 0:
            raise ValueError("Work amounts must be nonnegative integers.")

    def check_record_count(self, count: int) -> None:
        self._check_limit("max_records", count)

    def reserve_record(self, kind: str, path: object) -> None:
        key = kind, str(path)
        if key not in self.records:
            self.check_record_count(len(self.records) + 1)
            self.records.add(key)
        else:
            self.check()

    def visit_entry(self) -> None:
        self._check_limit("max_visited_entries", self.visited_entries + 1)
        self.visited_entries += 1

    def check_depth(self, depth: int) -> None:
        self._check_limit("max_depth", depth)

    def check_hash_capacity(self, size: int) -> None:
        self._amount(size)
        self._check_limit("max_payload_hash_bytes", self.payload_hash_bytes + size)

    def consume_hash_bytes(self, count: int) -> None:
        self._amount(count)
        self._check_limit("max_payload_hash_bytes", self.payload_hash_bytes + count)
        self.payload_hash_bytes += count

    def check_metadata_capacity(self, size: int) -> None:
        self._amount(size)
        self._check_limit("max_metadata_bytes", self.metadata_bytes + size)

    def consume_metadata_bytes(self, count: int) -> None:
        self._amount(count)
        self._check_limit("max_metadata_bytes", self.metadata_bytes + count)
        self.metadata_bytes += count

    def consume_export_bytes(self, count: int) -> None:
        self._amount(count)
        self._check_limit("max_export_bytes", self.export_bytes + count)
        self.export_bytes += count


_ACTIVE_BUDGET: ContextVar[OperationBudget | None] = ContextVar("rbf_work_budget", default=None)


def current_budget() -> OperationBudget | None:
    return _ACTIVE_BUDGET.get()


def check_budget() -> None:
    budget = current_budget()
    if budget is not None:
        budget.check()


@contextmanager
def operation_budget(
    limits: WorkLimits | None = None,
    *,
    operation: str = "operation",
    control=None,
    reuse: bool = False,
) -> Iterator[OperationBudget]:
    if limits is not None and not isinstance(limits, WorkLimits):
        raise TypeError("limits must be WorkLimits or None.")
    existing = current_budget()
    if reuse and existing is not None:
        previous_limits = existing.limits
        if limits is not None and limits != previous_limits:
            # Nested helpers may tighten a parent budget, never enlarge it.
            existing.limits = WorkLimits(
                **{
                    field.name: min(
                        getattr(previous_limits, field.name), getattr(limits, field.name)
                    )
                    for field in fields(WorkLimits)
                }
            )
        try:
            existing.check()
            yield existing
            existing.check()
        finally:
            existing.limits = previous_limits
        return
    budget = OperationBudget(limits, operation=operation, control=control)
    token = _ACTIVE_BUDGET.set(budget)
    try:
        budget.check()
        yield budget
        budget.check()
    finally:
        _ACTIVE_BUDGET.reset(token)
