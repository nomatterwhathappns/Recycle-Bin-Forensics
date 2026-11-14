"""Selection preserves observations; timeline uses recorded deletion instants."""

from __future__ import annotations

import copy

import pytest

from rbinforensics import analysis
from rbinforensics import limits as limits_module
from rbinforensics.analysis import (
    FilterOptions,
    apply_filters,
    build_timeline,
    selected_records,
    validate_filters,
)
from rbinforensics.limits import WorkLimitExceeded, WorkLimits, current_budget, operation_budget

TICKS = 133_485_408_001_234_567  # 2024-01-01T00:00:00.1234567Z


def record(
    source: str,
    original: str | None = r"C:\Users\Demo\report.PDF",
    *,
    sid: str | None = "S-1-5-21-1001",
    size: int = 500,
    ticks: int = TICKS,
    utc: str | None = "2024-01-01T00:00:00.1234567Z",
    kind: str = "metadata",
) -> dict:
    metadata = None
    if original is not None:
        metadata = {
            "original_path": original,
            "original_size": size,
            "deletion_filetime": ticks,
            "deleted_at_utc": utc,
            "deleted_at_display": utc,
        }
    return {
        "record_type": kind,
        "source_path": "/case/" + source,
        "source_name": source,
        "sid": sid,
        "metadata": metadata,
        "payload": {"status": "missing"} if metadata else None,
        "issues": [],
    }


@pytest.fixture
def observations() -> dict:
    return {
        "summary": {"candidates": 4, "parsed": 3, "errors": 2, "skipped": 0},
        "records": [
            record("$IA.PDF"),
            record(
                "$IB.txt",
                r"D:\Notes\meeting.txt",
                sid="S-1-5-21-2002",
                size=0,
                ticks=TICKS + 1,
                utc="2024-01-01T00:00:00.1234568Z",
            ),
            record("$Rorphan.pdf", original=None, kind="orphan_payload"),
            record("inaccessible", original=None, kind="discovery"),
            record("$Ibroken.pdf", original=None),
            record("$Iundated.PDF", ticks=0, utc=None),
        ],
    }


def names(report: dict) -> list[str]:
    return [item["source_name"] for item in selected_records(report)]


def test_no_filters_preserve_all_records_without_aliasing(observations: dict) -> None:
    before = copy.deepcopy(observations)
    filtered = apply_filters(observations, FilterOptions())
    assert filtered["selection"] == {
        "filters": {
            "query": None,
            "extensions": [],
            "sid": None,
            "deleted_after": None,
            "deleted_before": None,
            "min_size": None,
            "max_size": None,
        },
        "active": False,
        "matched": 6,
        "excluded": 0,
        "record_indexes": [0, 1, 2, 3, 4, 5],
    }
    assert filtered["summary"] == before["summary"]
    assert filtered["records"] == before["records"]
    filtered["records"][0]["metadata"]["original_path"] = "changed presentation"
    assert observations == before


def test_selected_records_without_selection_returns_all(observations: dict) -> None:
    assert selected_records(observations) == observations["records"]


def test_literal_case_insensitive_query_in_original_and_source(observations: dict) -> None:
    assert names(apply_filters(observations, FilterOptions(query="REPORT.pdf"))) == [
        "$IA.PDF",
        "inaccessible",
        "$Iundated.PDF",
    ]
    assert names(apply_filters(observations, FilterOptions(query="$rorphan"))) == [
        "$Rorphan.pdf",
        "inaccessible",
    ]
    assert len(names(apply_filters(observations, FilterOptions(query="/CASE/")))) == 6


def test_query_never_interprets_regex_or_glob(observations: dict) -> None:
    assert names(apply_filters(observations, FilterOptions(query=".*"))) == ["inaccessible"]


def test_query_does_not_match_across_artificial_field_boundaries(observations: dict) -> None:
    assert names(apply_filters(observations, FilterOptions(query=".PDF\n/case/"))) == [
        "inaccessible"
    ]


def test_discovery_problem_remains_visible_when_nothing_matches(observations: dict) -> None:
    result = apply_filters(observations, FilterOptions(query="not-present", min_size=10_000))
    assert result["selection"]["record_indexes"] == [3]
    assert result["selection"]["matched"] == 1
    assert result["selection"]["excluded"] == 5
    assert result["summary"] == observations["summary"]
    assert result["records"] == observations["records"]


def test_failed_and_skipped_candidates_remain_visible_but_warnings_obey_filters() -> None:
    failed = record("$Ifailed.PDF", original=None)
    failed["status"] = "error"
    skipped = record("$Iskipped.PDF", original=None)
    skipped["status"] = "skipped"
    warning = record("$Iwarning.PDF")
    warning["status"] = "warning"
    report = {"records": [failed, skipped, warning], "summary": {"errors": 1, "skipped": 1}}
    result = apply_filters(
        report,
        FilterOptions(query="not-present", extensions=("txt",), min_size=1_000),
    )
    assert names(result) == ["$Ifailed.PDF", "$Iskipped.PDF"]
    assert result["selection"]["matched"] == 2
    assert result["selection"]["excluded"] == 1
    assert result["records"] == report["records"]
    assert result["summary"] == report["summary"]


def test_extensions_normalize_and_match_orphan_filename(observations: dict) -> None:
    result = apply_filters(observations, FilterOptions(extensions=("PDF", ".pdf", " .TXT ")))
    assert result["selection"]["filters"]["extensions"] == [".pdf", ".txt"]
    assert names(result) == ["$IA.PDF", "$IB.txt", "$Rorphan.pdf", "inaccessible", "$Iundated.PDF"]


def test_compound_extension_suffix_matches_original_filename() -> None:
    report = {"records": [record("$IA.bin", r"C:\archives\logs.TAR.GZ")], "summary": {}}
    assert names(apply_filters(report, FilterOptions(extensions=("tar.gz",)))) == ["$IA.bin"]


def test_extensions_use_original_path_over_artifact_name(observations: dict) -> None:
    observations["records"][0]["source_name"] = "$IA.txt"
    result = apply_filters(observations, FilterOptions(extensions=("pdf",)))
    assert "$IA.txt" in names(result)
    assert "$Ibroken.pdf" not in names(result)


def test_filters_combine_with_and_and_sid_is_exact(observations: dict) -> None:
    result = apply_filters(
        observations,
        FilterOptions(query="report", extensions=("pdf",), sid="s-1-5-21-1001", min_size=500),
    )
    assert names(result) == ["$IA.PDF", "inaccessible", "$Iundated.PDF"]
    assert names(apply_filters(observations, FilterOptions(sid="1001"))) == ["inaccessible"]


def test_zero_size_is_active_and_unknown_sizes_are_excluded(observations: dict) -> None:
    result = apply_filters(observations, FilterOptions(min_size=0, max_size=0))
    assert result["selection"]["active"] is True
    assert names(result) == ["$IB.txt", "inaccessible"]


def test_exact_size_bounds_are_inclusive(observations: dict) -> None:
    result = apply_filters(observations, FilterOptions(min_size=500, max_size=500))
    assert names(result) == ["$IA.PDF", "inaccessible", "$Iundated.PDF"]


def test_seventh_fractional_digit_boundary_is_not_rounded(observations: dict) -> None:
    result = apply_filters(
        observations,
        FilterOptions(
            deleted_after="2024-01-01T00:00:00.1234568Z",
            deleted_before="2024-01-01T00:00:00.1234568Z",
        ),
    )
    assert names(result) == ["$IB.txt", "inaccessible"]


@pytest.mark.parametrize(
    "instant",
    [
        "2024-01-01T07:00:00.1234567+07:00",
        "2023-12-31T19:00:00.1234567-05:00",
        "2024-01-01t00:00:00.1234567z",
        "2024-01-01 00:00:00.1234567Z",
    ],
)
def test_offsets_compare_same_exact_instant(observations: dict, instant: str) -> None:
    result = apply_filters(
        observations, FilterOptions(deleted_after=instant, deleted_before=instant)
    )
    assert names(result) == ["$IA.PDF", "inaccessible"]


def test_date_only_before_means_midnight_not_end_of_day(observations: dict) -> None:
    result = apply_filters(observations, FilterOptions(deleted_before="2024-01-01"))
    assert names(result) == ["inaccessible"]
    after = apply_filters(observations, FilterOptions(deleted_after="2024-01-01"))
    assert names(after) == ["$IA.PDF", "$IB.txt", "inaccessible"]


def test_date_boundaries_before_epoch_do_not_overflow(observations: dict) -> None:
    validate_filters(FilterOptions(deleted_after="0001-01-01T00:00:00+23:59"))
    assert names(apply_filters(observations, FilterOptions(deleted_after="1601-01-01"))) == [
        "$IA.PDF",
        "$IB.txt",
        "inaccessible",
    ]


@pytest.mark.parametrize(
    "instant",
    [
        "2024-01-01T00:00:00",
        "2024-01-01T00:00:00.12345678Z",
        "2023-02-29",
        "0000-01-01",
        "2024-13-01",
        "2024-01-01T24:00:00Z",
        "2024-01-01T00:00:60Z",
        "2024-01-01T00:00:00+24:00",
        "2024-01-01T00:00:00+01:60",
        "tomorrow",
        "",
    ],
)
def test_invalid_deletion_bounds_raise_friendly_value_error(instant: str) -> None:
    with pytest.raises(ValueError):
        validate_filters(FilterOptions(deleted_after=instant))


@pytest.mark.parametrize(
    "filters",
    [
        FilterOptions(min_size=-1),
        FilterOptions(max_size=-1),
        FilterOptions(min_size=True),
        FilterOptions(min_size=1.5),
        FilterOptions(min_size=2, max_size=1),
        FilterOptions(deleted_after="2024-01-02", deleted_before="2024-01-01"),
        FilterOptions(extensions=("",)),
        FilterOptions(extensions=("*pdf",)),
        FilterOptions(extensions=("a/b",)),
        FilterOptions(extensions=("a\\b",)),
        FilterOptions(extensions=("..",)),
        FilterOptions(extensions=(".p\0df",)),
    ],
)
def test_invalid_filter_combinations_rejected(filters: FilterOptions) -> None:
    with pytest.raises(ValueError):
        validate_filters(filters)


def test_empty_query_and_sid_are_normalized_to_inactive(observations: dict) -> None:
    result = apply_filters(observations, FilterOptions(query="", sid="  "))
    assert result["selection"]["active"] is False
    assert result["selection"]["matched"] == 6


def test_timeline_orders_by_exact_tick_then_source_and_preserves_input(observations: dict) -> None:
    before = copy.deepcopy(observations)
    records = list(reversed(observations["records"]))
    records.append(record("$I0.PDF"))
    timeline = build_timeline(records)
    assert [event["source_path"] for event in timeline["events"]] == [
        "/case/$I0.PDF",
        "/case/$IA.PDF",
        "/case/$IB.txt",
    ]
    assert [event["deletion_filetime"] for event in timeline["events"]] == [TICKS, TICKS, TICKS + 1]
    assert timeline["undated_records"] == 4
    assert observations == before


def test_timeline_aggregates_only_included_dated_events(observations: dict) -> None:
    result = build_timeline(observations["records"])
    assert result["daily_counts"] == [{"date_utc": "2024-01-01", "count": 2}]
    assert result["by_sid"] == [
        {"sid": "S-1-5-21-1001", "count": 1},
        {"sid": "S-1-5-21-2002", "count": 1},
    ]
    assert result["by_extension"] == [
        {"extension": ".pdf", "count": 1},
        {"extension": ".txt", "count": 1},
    ]
    assert result["events"][0]["payload_status"] == "missing"


def test_timeline_respects_selection_without_changing_full_scan(observations: dict) -> None:
    result = apply_filters(observations, FilterOptions(extensions=("txt",)))
    timeline = build_timeline(selected_records(result))
    assert len(result["records"]) == 6
    assert len(timeline["events"]) == 1
    assert timeline["events"][0]["original_path"] == r"D:\Notes\meeting.txt"
    assert timeline["undated_records"] == 1  # The retained discovery error.


def test_timeline_handles_unknown_sid_extensionless_name_and_invalid_time() -> None:
    dated = record("$Ix", r"C:\extensionless", sid=None)
    dated["payload"] = None
    invalid = record("$Ibad", utc="not-a-time")
    result = build_timeline([dated, invalid])
    assert result["by_sid"] == [{"sid": None, "count": 1}]
    assert result["by_extension"] == [{"extension": "", "count": 1}]
    assert result["events"][0]["payload_status"] is None
    assert result["undated_records"] == 1


def test_empty_timeline_has_explicit_empty_aggregates() -> None:
    assert build_timeline([]) == {
        "order": "deletion_time_ascending",
        "events": [],
        "undated_records": 0,
        "daily_counts": [],
        "by_sid": [],
        "by_extension": [],
    }


def test_filter_record_limit_is_checked_before_copying_inventory(
    observations: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unexpected_copy(*args, **kwargs):
        raise AssertionError("Oversized inventories must be rejected before copying")

    monkeypatch.setattr(analysis.copy, "deepcopy", unexpected_copy)
    with pytest.raises(WorkLimitExceeded) as stopped:
        apply_filters(observations, FilterOptions(), limits=WorkLimits(max_records=5))
    assert stopped.value.operation == "filter"
    assert stopped.value.resource == "max_records"
    assert stopped.value.observed == 6
    assert current_budget() is None


def test_filter_exact_record_limit_preserves_nested_isolation(observations: dict) -> None:
    observations["options"] = {"labels": ["baseline"]}
    observations["records"][0]["issues"] = [
        {"code": "example", "message": "baseline", "severity": "warning"}
    ]
    before = copy.deepcopy(observations)
    result = apply_filters(observations, FilterOptions(), limits=WorkLimits(max_records=6))
    result["summary"]["parsed"] = -1
    result["options"]["labels"].append("view")
    result["records"][0]["issues"][0]["message"] = "view"
    result["records"][0]["payload"]["status"] = "view"
    result["records"][0]["metadata"]["original_path"] = "view"
    assert observations == before


def test_filter_does_not_copy_previous_selection_or_timeline(observations: dict) -> None:
    class ObsoleteView:
        def __deepcopy__(self, memo):
            raise AssertionError("The previous derived view must not be copied")

    old_selection = ObsoleteView()
    old_timeline = ObsoleteView()
    observations["selection"] = old_selection
    observations["timeline"] = old_timeline
    result = apply_filters(observations, FilterOptions(extensions=("txt",)))
    assert result["selection"]["record_indexes"] == [1, 3]
    assert "timeline" not in result
    assert observations["selection"] is old_selection
    assert observations["timeline"] is old_timeline
    result["timeline"] = build_timeline(selected_records(result))
    assert len(result["timeline"]["events"]) == 1


def test_filter_deadline_after_record_copy_leaves_baseline_unchanged(
    observations: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    before = copy.deepcopy(observations)
    clock = [0.0]
    monkeypatch.setattr(limits_module, "monotonic", lambda: clock[0])
    original_copy = copy.deepcopy

    def slow_copy(value, *args, **kwargs):
        result = original_copy(value, *args, **kwargs)
        if value is observations["records"][0]:
            clock[0] = 2.0
        return result

    monkeypatch.setattr(analysis.copy, "deepcopy", slow_copy)
    with pytest.raises(WorkLimitExceeded) as stopped:
        apply_filters(observations, FilterOptions(), limits=WorkLimits(max_operation_seconds=1))
    assert stopped.value.resource == "max_operation_seconds"
    assert observations == before
    assert current_budget() is None
    assert build_timeline(observations["records"])["events"]


@pytest.mark.parametrize("operation", ["filter", "timeline"])
def test_analysis_reuses_outer_operation_limits(observations: dict, operation: str) -> None:
    with operation_budget(WorkLimits(max_records=5), operation="scan") as outer:
        with pytest.raises(WorkLimitExceeded) as stopped:
            if operation == "filter":
                apply_filters(observations, FilterOptions(), limits=WorkLimits(max_records=6))
            else:
                build_timeline(observations["records"], limits=WorkLimits(max_records=6))
        assert stopped.value.operation == "scan"
        assert stopped.value.resource == "max_records"
        assert current_budget() is outer
    assert current_budget() is None


def test_timeline_record_limit_counts_undated_inputs(observations: dict) -> None:
    before = copy.deepcopy(observations)
    with pytest.raises(WorkLimitExceeded) as stopped:
        build_timeline(observations["records"], limits=WorkLimits(max_records=5))
    assert stopped.value.operation == "timeline"
    assert stopped.value.observed == 6
    assert observations == before
    result = build_timeline(observations["records"], limits=WorkLimits(max_records=6))
    assert result["undated_records"] == 4


def test_timeline_checks_deadline_after_sort_without_mutating_records(
    observations: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [0.0]
    monkeypatch.setattr(limits_module, "monotonic", lambda: clock[0])

    class SlowPath(str):
        def __lt__(self, other):
            clock[0] = 2.0
            return super().__lt__(other)

    first = record("$IB.pdf")
    first["source_path"] = SlowPath(first["source_path"])
    second = record("$IA.pdf")
    second["source_path"] = SlowPath(second["source_path"])
    records = [first, second]
    before = copy.deepcopy(records)
    with pytest.raises(WorkLimitExceeded) as stopped:
        build_timeline(records, limits=WorkLimits(max_operation_seconds=1))
    assert stopped.value.resource == "max_operation_seconds"
    assert records == before
    assert current_budget() is None


def test_timeline_checks_deadline_between_records(
    observations: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    before = copy.deepcopy(observations)
    clock = [0.0]
    monkeypatch.setattr(limits_module, "monotonic", lambda: clock[0])
    parse_instant = analysis._instant_ticks

    def slow_instant(value):
        result = parse_instant(value)
        clock[0] = 2.0
        return result

    monkeypatch.setattr(analysis, "_instant_ticks", slow_instant)
    with pytest.raises(WorkLimitExceeded, match="timeline incomplete"):
        build_timeline(observations["records"], limits=WorkLimits(max_operation_seconds=1))
    assert observations == before
