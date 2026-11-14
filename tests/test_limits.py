"""Work limits stop incomplete operations without leaking budgets or counters."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from pathlib import Path
from threading import Barrier

import pytest

from rbinforensics import limits
from rbinforensics.limits import (
    OperationBudget,
    WorkLimitExceeded,
    WorkLimits,
    check_budget,
    current_budget,
    operation_budget,
)
from rbinforensics.scan_control import ScanCancelled, ScanControl


def test_default_limits_are_active_frozen_and_serializable() -> None:
    values = WorkLimits()
    assert values.to_dict() == {
        "max_records": 100_000,
        "max_payload_hash_bytes": 10 * 1024**3,
        "max_metadata_bytes": 256 * 1024**2,
        "max_depth": 64,
        "max_operation_seconds": 600.0,
        "max_export_bytes": 128 * 1024**2,
        "max_visited_entries": 1_000_000,
    }
    with pytest.raises(FrozenInstanceError):
        values.max_records = 1
    serialized = values.to_dict()
    serialized["max_records"] = 1
    assert values.max_records == 100_000
    assert OperationBudget().limits == values


@pytest.mark.parametrize(
    "field",
    [
        "max_records",
        "max_payload_hash_bytes",
        "max_metadata_bytes",
        "max_export_bytes",
        "max_visited_entries",
    ],
)
@pytest.mark.parametrize("value", [0, -1, True, False, 1.0, "1", None])
def test_integer_limits_reject_nonpositive_or_noninteger_values(field, value) -> None:
    with pytest.raises(ValueError, match=field):
        WorkLimits(**{field: value})


@pytest.mark.parametrize("value", [-1, True, False, 0.0, "0", None])
def test_depth_rejects_invalid_values_but_allows_root_only(value) -> None:
    with pytest.raises(ValueError, match="max_depth"):
        WorkLimits(max_depth=value)
    assert WorkLimits(max_depth=0).max_depth == 0


@pytest.mark.parametrize(
    "value", [0, -1, True, False, float("inf"), float("-inf"), float("nan"), "1", None]
)
def test_duration_must_be_finite_positive_and_numeric(value) -> None:
    with pytest.raises(ValueError, match="max_operation_seconds"):
        WorkLimits(max_operation_seconds=value)


@pytest.mark.parametrize("value", [1, 0.01])
def test_duration_accepts_positive_integers_and_floats(value) -> None:
    assert WorkLimits(max_operation_seconds=value).max_operation_seconds == value


@pytest.mark.parametrize("value", [False, 0, {}, "defaults"])
def test_budget_rejects_invalid_limit_objects_instead_of_silently_using_defaults(value) -> None:
    with pytest.raises(TypeError, match="WorkLimits"):
        OperationBudget(value)


def test_record_reservations_are_idempotent_and_reject_before_growth() -> None:
    budget = OperationBudget(WorkLimits(max_records=2), operation="scan")
    budget.reserve_record("metadata", Path("case/$Ione"))
    budget.reserve_record("metadata", "case/$Ione")
    budget.reserve_record("orphan_payload", "case/$Rtwo")
    with pytest.raises(WorkLimitExceeded) as stopped:
        budget.reserve_record("discovery", "case/unreadable")
    assert len(budget.records) == 2
    assert stopped.value.operation == "scan"
    assert stopped.value.resource == "max_records"
    assert stopped.value.limit == 2
    assert stopped.value.observed == 3
    assert "incomplete" in str(stopped.value)


def test_existing_record_count_does_not_reserve_records_twice() -> None:
    budget = OperationBudget(WorkLimits(max_records=2))
    budget.reserve_record("metadata", "case/$Ione")
    budget.check_record_count(0)
    budget.check_record_count(2)
    assert len(budget.records) == 1
    with pytest.raises(WorkLimitExceeded) as stopped:
        budget.check_record_count(3)
    assert stopped.value.resource == "max_records"
    assert len(budget.records) == 1


def test_visited_entries_count_each_observation_and_stop_at_limit() -> None:
    budget = OperationBudget(WorkLimits(max_visited_entries=2))
    budget.visit_entry()
    budget.visit_entry()
    with pytest.raises(WorkLimitExceeded) as stopped:
        budget.visit_entry()
    assert stopped.value.resource == "max_visited_entries"
    assert budget.visited_entries == 2


def test_depth_limit_is_relative_to_root_and_inclusive() -> None:
    root_only = OperationBudget(WorkLimits(max_depth=0))
    root_only.check_depth(0)
    with pytest.raises(WorkLimitExceeded) as stopped:
        root_only.check_depth(1)
    assert stopped.value.resource == "max_depth"
    budget = OperationBudget(WorkLimits(max_depth=2))
    budget.check_depth(2)
    with pytest.raises(WorkLimitExceeded):
        budget.check_depth(3)


@pytest.mark.parametrize(
    ("resource", "counter", "consume", "capacity"),
    [
        (
            "max_payload_hash_bytes",
            "payload_hash_bytes",
            "consume_hash_bytes",
            "check_hash_capacity",
        ),
        (
            "max_metadata_bytes",
            "metadata_bytes",
            "consume_metadata_bytes",
            "check_metadata_capacity",
        ),
    ],
)
def test_byte_capacities_are_cumulative_and_preflight_does_not_consume(
    resource, counter, consume, capacity
) -> None:
    budget = OperationBudget(WorkLimits(**{resource: 5}))
    getattr(budget, capacity)(5)
    assert getattr(budget, counter) == 0
    getattr(budget, consume)(2)
    getattr(budget, capacity)(3)
    assert getattr(budget, counter) == 2
    with pytest.raises(WorkLimitExceeded) as stopped:
        getattr(budget, capacity)(4)
    assert stopped.value.resource == resource
    assert stopped.value.observed == 6
    assert getattr(budget, counter) == 2
    getattr(budget, consume)(3)
    getattr(budget, consume)(0)
    with pytest.raises(WorkLimitExceeded):
        getattr(budget, consume)(1)
    assert getattr(budget, counter) == 5


def test_export_bytes_reject_overflow_without_changing_counter() -> None:
    budget = OperationBudget(WorkLimits(max_export_bytes=4), operation="export")
    budget.consume_export_bytes(1)
    budget.consume_export_bytes(3)
    budget.consume_export_bytes(0)
    with pytest.raises(WorkLimitExceeded) as stopped:
        budget.consume_export_bytes(1)
    assert stopped.value.operation == "export"
    assert stopped.value.resource == "max_export_bytes"
    assert budget.export_bytes == 4


@pytest.mark.parametrize(
    "method",
    [
        "check_record_count",
        "check_depth",
        "check_hash_capacity",
        "consume_hash_bytes",
        "check_metadata_capacity",
        "consume_metadata_bytes",
        "consume_export_bytes",
    ],
)
@pytest.mark.parametrize("value", [-1, True, False, 1.0, "1", None])
def test_invalid_work_counts_cannot_reduce_or_bypass_budgets(method, value) -> None:
    budget = OperationBudget()
    budget.consume_hash_bytes(2)
    budget.consume_metadata_bytes(3)
    budget.consume_export_bytes(4)
    with pytest.raises(ValueError):
        getattr(budget, method)(value)
    assert budget.payload_hash_bytes == 2
    assert budget.metadata_bytes == 3
    assert budget.export_bytes == 4
    assert budget.records == set()


def test_deadline_uses_monotonic_elapsed_time_and_allows_exact_boundary(monkeypatch) -> None:
    clock = [100.0]
    monkeypatch.setattr(limits, "monotonic", lambda: clock[0])
    budget = OperationBudget(WorkLimits(max_operation_seconds=2), operation="filter")
    clock[0] = 102.0
    budget.check()
    clock[0] = 102.001
    with pytest.raises(WorkLimitExceeded) as stopped:
        budget.consume_hash_bytes(1)
    assert stopped.value.operation == "filter"
    assert stopped.value.resource == "max_operation_seconds"
    assert stopped.value.limit == 2
    assert stopped.value.observed == pytest.approx(2.001)
    assert budget.payload_hash_bytes == 0


def test_completed_body_cannot_hide_expiration_at_operation_exit(monkeypatch) -> None:
    clock = [0.0]
    monkeypatch.setattr(limits, "monotonic", lambda: clock[0])
    with pytest.raises(WorkLimitExceeded, match="timeline incomplete"):
        with operation_budget(WorkLimits(max_operation_seconds=1), operation="timeline"):
            clock[0] = 2.0
    assert current_budget() is None


def test_expired_operation_entry_restores_outer_context(monkeypatch) -> None:
    clock = [0.0]
    monkeypatch.setattr(limits, "monotonic", lambda: clock[0])
    with operation_budget() as outer:
        times = iter((0.0, 2.0))
        with monkeypatch.context() as context:
            context.setattr(limits, "monotonic", lambda: next(times))
            with pytest.raises(WorkLimitExceeded):
                with operation_budget(WorkLimits(max_operation_seconds=1)):
                    pytest.fail("An expired operation must not enter its body")
        assert current_budget() is outer
    assert current_budget() is None


def test_reused_scope_shares_deadline_and_consumption_without_reset(monkeypatch) -> None:
    clock = [0.0]
    monkeypatch.setattr(limits, "monotonic", lambda: clock[0])
    with operation_budget(
        WorkLimits(max_export_bytes=2, max_operation_seconds=1), operation="scan"
    ) as outer:
        outer.consume_export_bytes(1)
        clock[0] = 0.75
        with operation_budget(
            WorkLimits(max_export_bytes=100), operation="filter", reuse=True
        ) as inner:
            assert inner is outer
            assert inner.operation == "scan"
            inner.consume_export_bytes(1)
        assert outer.export_bytes == 2
        with pytest.raises(WorkLimitExceeded, match="max_export_bytes"):
            outer.consume_export_bytes(1)
    assert current_budget() is None


def test_reused_scope_cannot_extend_parent_deadline(monkeypatch) -> None:
    clock = [0.0]
    monkeypatch.setattr(limits, "monotonic", lambda: clock[0])
    with pytest.raises(WorkLimitExceeded) as stopped:
        with operation_budget(WorkLimits(max_operation_seconds=1), operation="scan"):
            clock[0] = 0.75
            with operation_budget(
                WorkLimits(max_operation_seconds=100), operation="timeline", reuse=True
            ):
                clock[0] = 1.25
                check_budget()
    assert stopped.value.operation == "scan"
    assert stopped.value.resource == "max_operation_seconds"
    assert current_budget() is None


def test_nested_fresh_operation_has_independent_counters_and_restores_parent() -> None:
    with operation_budget(WorkLimits(max_export_bytes=1), operation="outer") as outer:
        outer.consume_export_bytes(1)
        with operation_budget(WorkLimits(max_export_bytes=2), operation="inner") as inner:
            assert inner is not outer
            assert current_budget() is inner
            inner.consume_export_bytes(2)
        assert current_budget() is outer
        assert outer.export_bytes == 1
    assert current_budget() is None


@pytest.mark.parametrize("reuse", [False, True])
def test_nested_failure_restores_outer_context_and_preserves_exception(reuse) -> None:
    with operation_budget() as outer:
        with pytest.raises(LookupError, match="consumer failed"):
            with operation_budget(reuse=reuse):
                raise LookupError("consumer failed")
        assert current_budget() is outer
        outer.check()
    assert current_budget() is None


def test_reuse_without_parent_still_starts_a_default_operation() -> None:
    assert current_budget() is None
    check_budget()
    assert current_budget() is None
    with operation_budget(reuse=True) as budget:
        assert current_budget() is budget
        assert budget.limits == WorkLimits()


def test_reused_helper_can_tighten_but_restores_parent_limits():
    parent_limits = WorkLimits(max_export_bytes=10)
    with operation_budget(parent_limits) as outer:
        with pytest.raises(WorkLimitExceeded):
            with operation_budget(WorkLimits(max_export_bytes=1), reuse=True) as inner:
                assert inner is outer
                inner.consume_export_bytes(1)
                inner.consume_export_bytes(1)
        assert outer.limits is parent_limits
        assert outer.export_bytes == 1
        outer.consume_export_bytes(9)


@pytest.mark.parametrize("invalid", [False, 0, "", {}])
def test_reused_scope_does_not_ignore_invalid_limits(invalid):
    with operation_budget() as outer:
        with pytest.raises(TypeError, match="WorkLimits"):
            with operation_budget(invalid, reuse=True):
                pytest.fail("Invalid overrides must not be ignored")
        assert current_budget() is outer
        check_budget()
    assert current_budget() is None


def test_concurrent_threads_keep_budgets_and_failures_isolated() -> None:
    barrier = Barrier(2)

    def work(size):
        assert current_budget() is None
        with operation_budget(
            WorkLimits(max_export_bytes=size), operation=f"export-{size}"
        ) as budget:
            budget.consume_export_bytes(size)
            barrier.wait(timeout=5)
            assert current_budget() is budget
            if size == 1:
                with pytest.raises(WorkLimitExceeded):
                    budget.consume_export_bytes(1)
            snapshot = budget.operation, budget.export_bytes
        assert current_budget() is None
        return snapshot

    with operation_budget() as parent:
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(work, 1)
            second = pool.submit(work, 2)
            assert first.result(timeout=10) == ("export-1", 1)
            assert second.result(timeout=10) == ("export-2", 2)
        assert current_budget() is parent
        assert parent.export_bytes == 0
    assert current_budget() is None


@pytest.mark.parametrize("cancel_before_entry", [False, True])
def test_cancellation_propagates_and_context_is_cleaned(cancel_before_entry) -> None:
    control = ScanControl()
    if cancel_before_entry:
        control.cancel()
    with pytest.raises(ScanCancelled):
        with operation_budget(control=control) as budget:
            control.cancel()
            budget.consume_export_bytes(1)
    assert current_budget() is None
    with operation_budget() as unrelated:
        unrelated.check()


def test_reused_reservation_still_observes_cancellation() -> None:
    control = ScanControl()
    budget = OperationBudget(control=control)
    budget.reserve_record("metadata", "case/$Ione")
    control.cancel()
    with pytest.raises(ScanCancelled):
        budget.reserve_record("metadata", "case/$Ione")
    assert len(budget.records) == 1
