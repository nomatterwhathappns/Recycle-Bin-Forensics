"""Offline HTML preserves provenance without executing artifact text."""

from __future__ import annotations

import base64
import copy
import hashlib
import re
from html.parser import HTMLParser

import pytest

from rbinforensics.html_report import render_html


def make_record(name: str = "$IABC.txt", *, kind: str = "metadata", status: str = "ok") -> dict:
    metadata = {
        "format_version": 2,
        "original_path": r"C:\Users\Demo\report.txt",
        "original_size": 9007199254740993,
        "deletion_filetime": 133485408001234567,
        "deleted_at_utc": "2024-01-01T00:00:00.1234567Z",
        "deleted_at_display": "2024-01-01T07:00:00.1234567+07:00",
    }
    payload = {
        "path": "/case/$RABC.txt",
        "status": "available_file",
        "size": 9007199254740993,
        "sha256": "b" * 64,
        "hash_status": "computed",
        "size_matches_metadata": True,
    }
    return {
        "record_type": kind,
        "source_path": "/case/" + name,
        "source_name": name,
        "source_size": 84,
        "source_sha256": "a" * 64,
        "sid": "S-1-5-21-1001",
        "status": status,
        "metadata": metadata if kind == "metadata" else None,
        "payload": payload if kind != "discovery" else None,
        "issues": [],
    }


@pytest.fixture
def report() -> dict:
    return {
        "schema_version": "2.0",
        "tool": {"name": "rbinforensics", "version": "1.0.0"},
        "input": "/case",
        "started_at_utc": "2024-02-01T00:00:00+00:00",
        "completed_at_utc": "2024-02-01T00:00:01+00:00",
        "options": {"case_id": "IR-001", "examiner": "Analyst", "timezone": "Asia/Jakarta"},
        "summary": {"candidates": 1, "parsed": 1, "errors": 0, "warnings": 0, "skipped": 0},
        "records": [make_record()],
    }


class Document(HTMLParser):
    def __init__(self, source: str) -> None:
        super().__init__()
        self.elements: list[tuple[str, dict]] = []
        self.feed(source)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.elements.append((tag, dict(attrs)))


def test_offline_report_has_context_inventory_hashes_and_timeline(report: dict) -> None:
    result = render_html(report)
    for value in (
        "Artifact inventory",
        "Deletion timeline",
        "Activity by day",
        "Warnings &amp; errors",
        "IR-001",
        "Analyst",
        "1.0.0",
        "9007199254740993",
        "133485408001234567",
        "2024-01-01T00:00:00.1234567Z",
        "2024-01-01T07:00:00.1234567+07:00",
        "a" * 64,
        "b" * 64,
    ):
        assert value in result
    assert 'data-size="9007199254740993"' in result
    assert 'data-time="133485408001234567"' in result
    assert "BigInt(left)" in result
    assert "Number(a.dataset.size)" not in result
    assert "Number(a.dataset.time)" not in result


def test_csp_authorizes_exact_static_script_and_blocks_external_resources(report: dict) -> None:
    source = render_html(report)
    document = Document(source)
    csp = next(
        attrs["content"]
        for tag, attrs in document.elements
        if attrs.get("http-equiv") == "Content-Security-Policy"
    )
    script = re.search(r"<script>(.*?)</script>", source, re.S).group(1)
    digest = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
    assert f"script-src 'sha256-{digest}'" in csp
    assert "default-src 'none'" in csp
    assert "base-uri 'none'" in csp
    assert "object-src 'none'" in csp
    assert "form-action 'none'" in csp
    assert "script-src 'unsafe-inline'" not in csp
    assert all(not attrs.get("src") for _, attrs in document.elements)
    assert all(
        not (attrs.get("href") or "").startswith(("http", "file:", "javascript:"))
        for _, attrs in document.elements
    )
    assert "innerHTML" not in script
    assert "eval(" not in script
    assert "fetch(" not in script


@pytest.mark.parametrize(
    "payload",
    [
        '<img src=x onerror="window.injected=1">',
        "</script><script>window.injected=1</script>",
        '" autofocus onfocus="window.injected=1',
        "javascript:alert(1)",
        "line\n\x1b[31m\u202ereport.txt",
    ],
)
def test_evidence_cannot_inject_elements_attributes_or_hidden_controls(
    report: dict, payload: str
) -> None:
    record = report["records"][0]
    record.update(
        source_name=payload, source_path=payload, sid=payload, status=payload, record_type=payload
    )
    record["metadata"]["original_path"] = payload
    record["payload"].update(path=payload, status=payload)
    record["issues"] = [{"code": payload, "severity": "warning", "message": payload}]
    report["options"].update(case_id=payload, examiner=payload)
    report["input"] = payload
    source = render_html(report)
    document = Document(source)
    assert sum(tag == "script" for tag, _ in document.elements) == 1
    assert all(tag != "img" for tag, _ in document.elements)
    assert all(not any(key.startswith("on") for key in attrs) for _, attrs in document.elements)
    assert "\x1b" not in source
    assert "\u202e" not in source
    assert "\n\x1b" not in source
    assert "<img src=x" not in source


def test_selection_changes_inventory_but_all_diagnostics_stay_visible(report: dict) -> None:
    error = make_record("$IBAD.txt", status="error")
    error["metadata"] = None
    error["issues"] = [
        {"code": "truncated_header", "severity": "error", "message": "Expected24 bytes"}
    ]
    report["records"].append(error)
    report["summary"]["errors"] = 1
    report["selection"] = {
        "active": True,
        "filters": {"query": "report"},
        "matched": 1,
        "excluded": 1,
        "record_indexes": [0],
    }
    source = render_html(report)
    document = Document(source)
    rows = [attrs for tag, attrs in document.elements if tag == "tr" and "data-order" in attrs]
    assert len(rows) == 1
    assert rows[0]["data-source"] == "$IABC.txt"
    assert "Full scan summary stays unchanged" in source
    assert "1 records included, 1 excluded" in source
    assert "query=report" in source
    assert "truncated_header" in source
    assert "Expected24 bytes" in source
    assert "/case/$IBAD.txt" in source


def test_orphans_discovery_and_unknown_values_render_without_invented_metadata(
    report: dict,
) -> None:
    orphan = make_record("$Rorphan.bin", kind="orphan_payload", status="warning")
    orphan["payload"]["status"] = "orphan_file"
    discovery = make_record("unreadable", kind="discovery", status="error")
    report["records"] = [orphan, discovery]
    result = render_html(report)
    assert "orphan_file" in result
    assert "orphan_payload" in result
    assert 'data-time=""' in result
    assert "No selected records have a usable deletion timestamp" in result
    assert "2 selected records have no usable deletion timestamp" in result
    assert "Unknown" in result


def test_empty_selection_and_empty_scan_are_explicit(report: dict) -> None:
    report["selection"] = {
        "active": True,
        "filters": {"query": "absent"},
        "matched": 0,
        "excluded": 1,
        "record_indexes": [],
    }
    result = render_html(report)
    assert "0 selected / 1 total" in result
    assert 'id="no-visible-records" class="empty">' in result
    assert "No dated events in this selection" in result
    report["records"] = []
    report.pop("selection")
    assert "0 selected / 0 total" in render_html(report)


def test_explicit_timeline_is_used_and_render_does_not_mutate_input(report: dict) -> None:
    report["timeline"] = {
        "events": [
            {
                "original_path": r"C:\timeline-only.txt",
                "deleted_at_utc": "2024-01-02T00:00:00.0000001Z",
                "original_size": 2,
                "sid": None,
            }
        ],
        "undated_records": 4,
        "daily_counts": [{"date_utc": "2024-01-02", "count": 1}],
    }
    before = copy.deepcopy(report)
    result = render_html(report)
    assert r"C:\timeline-only.txt" in result
    assert "4 selected records have no usable deletion timestamp" in result
    assert 'style="width:100%"' in result
    assert report == before


def test_all_filter_controls_have_associated_labels_and_noscript_fallback(report: dict) -> None:
    source = render_html(report)
    document = Document(source)
    ids = {attrs["id"] for tag, attrs in document.elements if tag in ("input", "select")}
    labels = {attrs["for"] for tag, attrs in document.elements if tag == "label"}
    assert ids <= labels
    assert "JavaScript is disabled" in source
    assert 'aria-live="polite"' in source
    assert 'scope="col"' in source
