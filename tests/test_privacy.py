"""Sharing derivatives retain facts without exporting identifying source text."""

from __future__ import annotations

import copy
import hashlib
import json
import struct
from pathlib import Path

import pytest

from rbinforensics.analysis import FilterOptions
from rbinforensics.limits import WorkLimitExceeded, WorkLimits, operation_budget
from rbinforensics.privacy import SHARING_REPORT_KIND, SHARING_SCHEMA_VERSION, redact_report
from rbinforensics.reports import render
from rbinforensics.scanner import ScanOptions, scan

SID = "S-1-5-21-111222333-444555666-777888999-1001"
TICKS = 133_485_408_001_234_567
SECRETS = (
    "SOURCE_SENTINEL",
    "USER_SENTINEL",
    "CASE_SENTINEL",
    "EXAMINER_SENTINEL",
    "OTHER_SENTINEL",
    "EXT_SENTINEL",
    "BROKEN_SENTINEL",
    "ORPHAN_SENTINEL",
    "DIAGNOSTIC_SENTINEL",
    "UNKNOWN_SENTINEL",
    SID,
)


def _item(directory: Path, suffix: str, original: str, content: bytes) -> None:
    encoded = (original + "\0").encode("utf-16-le")
    (directory / ("$I" + suffix)).write_bytes(
        struct.pack("<QQQI", 2, len(content), TICKS, len(encoded) // 2) + encoded
    )
    (directory / ("$R" + suffix)).write_bytes(content)


@pytest.fixture
def report(tmp_path: Path) -> dict:
    source = tmp_path.resolve() / "SOURCE_SENTINEL"
    sid_directory = source / SID
    sid_directory.mkdir(parents=True)
    _item(
        sid_directory,
        "FIRST.EXT_SENTINEL",
        r"C:\Users\USER_SENTINEL\CASE_SENTINEL.EXT_SENTINEL",
        b"private first payload",
    )
    _item(
        sid_directory,
        "SECOND.txt",
        r"C:\Users\OTHER_SENTINEL\excluded.txt",
        b"private other payload",
    )
    (sid_directory / "$IBROKEN_SENTINEL").write_bytes(b"bad")
    (sid_directory / "$RORPHAN_SENTINEL.bin").write_bytes(b"orphan contents")
    result = scan(
        source,
        ScanOptions(
            recursive=True,
            hash_payload=True,
            case_id="CASE_SENTINEL",
            examiner="EXAMINER_SENTINEL",
        ),
        FilterOptions(
            query="CASE_SENTINEL",
            extensions=(".EXT_SENTINEL",),
            sid=SID,
            deleted_after="2023-01-01",
            deleted_before="2025-01-01",
            min_size=1,
            max_size=100,
        ),
    )
    for record in result["records"]:
        if record["issues"]:
            record["issues"][0]["message"] = f"DIAGNOSTIC_SENTINEL: {record['source_path']}"
    assert result["selection"]["matched"] == 2
    assert len(result["timeline"]["events"]) == 1
    return result


def _sensitive_strings(report: dict) -> set[str]:
    values = set(SECRETS)
    values.add(report["input"])
    for record in report["records"]:
        values.update((record["source_path"], record["source_name"]))
        if record["source_sha256"]:
            values.add(record["source_sha256"])
        if record["metadata"]:
            values.add(record["metadata"]["original_path"])
        if record["payload"]:
            payload = record["payload"]
            if payload["path"]:
                values.add(payload["path"])
            if payload["sha256"]:
                values.add(payload["sha256"])
    return values


@pytest.mark.parametrize("format_name", ["json", "csv", "html", "table"])
def test_sensitive_source_values_do_not_appear_in_any_rendering(report, format_name):
    derivative = redact_report(report)
    text = render(derivative, format_name)
    for secret in _sensitive_strings(report):
        assert secret not in text
        assert secret not in json.dumps(derivative, ensure_ascii=False)
    assert derivative["schema_version"] == SHARING_SCHEMA_VERSION
    assert derivative["report_kind"] == SHARING_REPORT_KIND
    assert derivative["derived_from_schema_version"] == "2.0"


def test_original_and_derivative_are_deeply_isolated(report):
    original = copy.deepcopy(report)
    derivative = redact_report(report)
    assert report == original
    derivative["records"][0]["issues"].append({"code": "new"})
    derivative["selection"]["record_indexes"].clear()
    derivative["timeline"]["daily_counts"].clear()
    derivative["options"]["case_id"] = "another"
    assert report == original
    report["records"][-1]["source_name"] = "changed later"
    assert all(item["source_name"] != "changed later" for item in derivative["records"])


def test_inventory_selection_and_quantitative_facts_are_preserved(report):
    derivative = redact_report(report)
    assert len(derivative["records"]) == len(report["records"])
    assert derivative["summary"] == report["summary"]
    for key in ("active", "matched", "excluded", "record_indexes"):
        assert derivative["selection"][key] == report["selection"][key]
    for source, redacted in zip(report["records"], derivative["records"], strict=True):
        for field in ("record_type", "source_size", "status"):
            assert redacted[field] == source[field]
        if source["metadata"]:
            for field in (
                "format_version",
                "original_size",
                "deletion_filetime",
                "deleted_at_utc",
                "deleted_at_display",
            ):
                assert redacted["metadata"][field] == source["metadata"][field]
        if source["payload"]:
            for field in ("status", "size", "hash_status", "size_matches_metadata"):
                assert redacted["payload"][field] == source["payload"][field]
        assert [(item["code"], item["severity"]) for item in redacted["issues"]] == [
            (item["code"], item["severity"]) for item in source["issues"]
        ]
    for field in ("daily_counts", "undated_records", "order"):
        assert derivative["timeline"][field] == report["timeline"][field]
    dated = next(record for record in derivative["records"] if record["metadata"])
    assert dated["metadata"]["deletion_filetime"] == TICKS


def test_aliases_correlate_records_timeline_and_sid_groups(report):
    derivative = redact_report(report)
    originals = {record["source_path"]: index for index, record in enumerate(report["records"])}
    for event, redacted_event in zip(
        report["timeline"]["events"], derivative["timeline"]["events"], strict=True
    ):
        redacted_record = derivative["records"][originals[event["source_path"]]]
        assert redacted_event["source_path"] == redacted_record["source_path"]
        assert redacted_event["original_path"] == redacted_record["metadata"]["original_path"]
        assert redacted_event["sid"] == redacted_record["sid"]
    sid_aliases = {record["sid"] for record in derivative["records"]}
    assert sid_aliases == {"sid-000001"}
    assert derivative["timeline"]["by_sid"] == [{"sid": "sid-000001", "count": 1}]
    orphan = next(
        record for record in derivative["records"] if record["record_type"] == "orphan_payload"
    )
    assert orphan["source_path"] == orphan["payload"]["path"]
    for record in derivative["records"]:
        assert record["source_path"].startswith("path-")
        assert "." not in record["source_name"]
        if record["metadata"]:
            assert "." not in record["metadata"]["original_path"]
    assert derivative["timeline"]["by_extension"] == [
        {"extension": ".extension-000001", "count": 1}
    ]


def test_identical_values_get_identical_path_aliases_across_all_fields(report):
    record = next(item for item in report["records"] if item["metadata"])
    same = record["source_path"]
    report["input"] = same
    record["source_name"] = same
    record["metadata"]["original_path"] = same
    record["payload"]["path"] = same
    derivative = redact_report(report)
    index = report["records"].index(record)
    result = derivative["records"][index]
    assert result["source_path"] == derivative["input"]
    assert result["source_name"] == derivative["input"]
    assert result["metadata"]["original_path"] == derivative["input"]
    assert result["payload"]["path"] == derivative["input"]


def test_search_identity_labels_hashes_and_diagnostic_text_are_withheld(report):
    derivative = redact_report(report)
    assert derivative["options"]["case_id"] is None
    assert derivative["options"]["examiner"] is None
    filters = derivative["selection"]["filters"]
    assert filters["query"] == "[withheld]"
    assert filters["extensions"] == [".withheld"]
    assert filters["sid"] == "[withheld]"
    for field in ("deleted_after", "deleted_before", "min_size", "max_size"):
        assert filters[field] == report["selection"]["filters"][field]
    for record in derivative["records"]:
        assert record["source_sha256"] is None
        if record["payload"]:
            assert record["payload"]["sha256"] is None
        assert all(issue["message"] == "Diagnostic text withheld." for issue in record["issues"])
    assert "evidence_hashes" in derivative["redaction"]
    assert hashlib.sha256(b"private first payload").hexdigest() not in json.dumps(derivative)


def test_unknown_future_fields_are_not_copied_at_any_level(report):
    def inject(value):
        if isinstance(value, dict):
            for child in list(value.values()):
                inject(child)
            value["future_sensitive"] = {"value": "UNKNOWN_SENTINEL"}
        elif isinstance(value, list):
            for child in value:
                inject(child)

    inject(report)
    serialized = json.dumps(redact_report(report))
    assert "UNKNOWN_SENTINEL" not in serialized
    assert "future_sensitive" not in serialized


def test_nulls_empty_collections_and_no_selection_are_supported(tmp_path):
    source = tmp_path.resolve() / "empty"
    source.mkdir()
    report = scan(source)
    derivative = redact_report(report)
    assert derivative["records"] == []
    assert derivative["selection"]["filters"]["query"] is None
    assert derivative["selection"]["filters"]["extensions"] == []
    assert derivative["selection"]["filters"]["sid"] is None
    assert derivative["timeline"]["events"] == []
    report.pop("selection")
    report.pop("timeline")
    derivative = redact_report(report)
    assert "selection" not in derivative
    assert "timeline" not in derivative
    assert derivative["records"] == []


def test_absent_sid_and_extension_do_not_gain_invented_identity(tmp_path):
    source = tmp_path.resolve() / "source"
    source.mkdir()
    _item(source, "NOEXT", r"C:\safe\noextension", b"data")
    report = scan(source)
    derivative = redact_report(report)
    assert derivative["records"][0]["sid"] is None
    assert derivative["timeline"]["by_sid"] == [{"sid": None, "count": 1}]
    assert derivative["timeline"]["by_extension"] == [{"extension": "", "count": 1}]


@pytest.mark.parametrize(
    "report", [None, [], {}, {"schema_version": "1.0"}, {"schema_version": "sharing-1.0"}]
)
def test_only_complete_schema_2_reports_can_be_redacted(report):
    with pytest.raises(ValueError, match="schema-2.0"):
        redact_report(report)


def test_redaction_obeys_shared_record_capacity(report):
    with operation_budget(WorkLimits(max_records=1), operation="export"):
        with pytest.raises(WorkLimitExceeded, match="max_records"):
            redact_report(report)


def test_redaction_checks_deadlines_while_building_each_record(report, monkeypatch):
    from rbinforensics import limits

    now = [0.0]
    monkeypatch.setattr(limits, "monotonic", lambda: now[0])
    checks = [0]
    original = limits.OperationBudget.check

    def advance(budget):
        checks[0] += 1
        if checks[0] == 40:
            now[0] = 2.0
        return original(budget)

    monkeypatch.setattr(limits.OperationBudget, "check", advance)
    with pytest.raises(WorkLimitExceeded, match="max_operation_seconds"):
        with operation_budget(WorkLimits(max_operation_seconds=1), operation="export"):
            redact_report(report)
    assert checks[0] >= 40


def test_nested_non_scalar_facts_fail_instead_of_copying_arbitrary_objects(report):
    report["records"][0]["source_size"] = {"private": "UNKNOWN_SENTINEL"}
    with pytest.raises(ValueError, match="scalar report field: source_size"):
        redact_report(report)
