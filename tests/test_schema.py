"""Validate public report contracts against independently assembled evidence."""

import copy
import json
import struct
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

from rbinforensics.scanner import ScanOptions, scan

SCHEMA_PATH = Path(__file__).parents[1] / "schemas" / "report-v1.schema.json"
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FormatChecker())


def metadata(path="C:\\Case\\report-🐈.txt", size=5, ticks=116_444_736_012_345_679):
    encoded = (path + "\0").encode("utf-16-le")
    return struct.pack("<QQQI", 2, size, ticks, len(encoded) // 2) + encoded


def validate(report):
    # JSON serialization is part of the contract, not just Python object types.
    serialized = json.loads(json.dumps(report))
    VALIDATOR.validate(serialized)
    return serialized


@pytest.fixture
def clean_report(tmp_path):
    source = tmp_path / "$I123456.txt"
    source.write_bytes(metadata())
    (tmp_path / "$R123456.txt").write_bytes(b"hello")
    return scan(source, ScanOptions(hash_payload=True, case_id="SYNTHETIC-001", examiner="Lab"))


def test_schema_is_valid():
    Draft202012Validator.check_schema(SCHEMA)


def test_clean_report_and_full_precision_datetime(clean_report):
    report = validate(clean_report)
    assert report["summary"]["parsed"] == 1
    assert report["summary"]["payloads_hashed"] == 1
    assert report["records"][0]["metadata"]["deleted_at_utc"] == "1970-01-01T00:00:01.2345679Z"
    assert report["records"][0]["payload"]["sha256"] is not None


def test_malformed_report_retains_nullable_metadata(tmp_path):
    (tmp_path / "$Ibroken").write_bytes(b"bad")
    report = validate(scan(tmp_path))
    assert report["summary"]["errors"] == 1
    assert report["records"][0]["metadata"] is None
    assert report["records"][0]["payload"] is None
    assert report["records"][0]["source_sha256"] is not None


def test_warning_report_with_unknown_time_and_missing_payload(tmp_path):
    source = tmp_path / "$Imissing"
    source.write_bytes(metadata(ticks=0))
    report = validate(scan(source))
    assert report["records"][0]["status"] == "warning"
    assert report["records"][0]["metadata"]["deleted_at_utc"] is None
    assert report["records"][0]["metadata"]["deleted_at_display"] is None
    assert report["records"][0]["payload"]["status"] == "missing"


def test_discovery_error_report(tmp_path, monkeypatch):
    def inaccessible(_):
        raise PermissionError("Synthetic discovery failure")

    monkeypatch.setattr("rbinforensics.scanner.os.scandir", inaccessible)
    report = validate(scan(tmp_path))
    assert report["records"][0]["record_type"] == "discovery"
    assert report["records"][0]["status"] == "error"
    assert report["records"][0]["source_sha256"] is None


def test_empty_report_is_valid(tmp_path):
    report = validate(scan(tmp_path))
    assert report["records"] == []


def test_payload_directory_report(tmp_path):
    (tmp_path / "$Ifolder").write_bytes(metadata())
    (tmp_path / "$Rfolder").mkdir()
    report = validate(scan(tmp_path, ScanOptions(hash_payload=True)))
    assert report["records"][0]["payload"]["status"] == "available_directory"
    assert report["records"][0]["payload"]["hash_status"] == "not_applicable"


def test_sid_context_and_local_time(tmp_path):
    case = tmp_path / "S-1-5-21-12345"
    case.mkdir()
    (case / "$I123456.txt").write_bytes(metadata())
    report = validate(scan(tmp_path, ScanOptions(recursive=True, timezone="Asia/Jakarta")))
    record = report["records"][0]
    assert record["sid"] == "S-1-5-21-12345"
    assert record["metadata"]["deleted_at_display"] == "1970-01-01T07:00:01.2345679+07:00"


@pytest.mark.parametrize(
    "object_path",
    [
        (),
        ("tool",),
        ("options",),
        ("summary",),
        ("records", 0),
        ("records", 0, "metadata"),
        ("records", 0, "payload"),
    ],
)
def test_known_objects_reject_unexpected_properties(clean_report, object_path):
    report = copy.deepcopy(clean_report)
    target = report
    for key in object_path:
        target = target[key]
    target["undocumented_field"] = "unexpected"
    with pytest.raises(ValidationError):
        VALIDATOR.validate(report)


def test_issue_code_is_extensible_and_issue_properties_are_closed(clean_report):
    report = copy.deepcopy(clean_report)
    issue = {"code": "future_diagnostic_code", "severity": "warning", "message": "New warning"}
    report["records"][0]["issues"].append(issue)
    validate(report)
    issue["undocumented_field"] = True
    with pytest.raises(ValidationError):
        VALIDATOR.validate(report)


@pytest.mark.parametrize("field", ["schema_version", "tool", "options", "summary", "records"])
def test_required_top_level_fields(clean_report, field):
    report = copy.deepcopy(clean_report)
    del report[field]
    with pytest.raises(ValidationError):
        VALIDATOR.validate(report)


def test_invalid_timestamp_is_rejected(clean_report):
    report = copy.deepcopy(clean_report)
    report["records"][0]["metadata"]["deleted_at_utc"] = "not-a-date"
    with pytest.raises(ValidationError):
        VALIDATOR.validate(report)


def test_uint64_limit_is_enforced(clean_report):
    report = copy.deepcopy(clean_report)
    report["records"][0]["metadata"]["deletion_filetime"] = 2**64
    with pytest.raises(ValidationError):
        VALIDATOR.validate(report)
