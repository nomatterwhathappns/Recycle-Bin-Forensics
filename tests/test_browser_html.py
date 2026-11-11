"""Opt-in Chromium regression tests for the actual standalone report.

Run with RBF_RUN_BROWSER=1 after installing the ``browser`` development extra.
No browser package or executable is needed by the default test suite or tool.
"""

from __future__ import annotations

import os
import shutil
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest

from rbinforensics.html_report import render_html

pytestmark = pytest.mark.skipif(
    os.environ.get("RBF_RUN_BROWSER") != "1", reason="Set RBF_RUN_BROWSER=1 for browser tests"
)


def _report() -> dict:
    """Independent uint64-boundary and hostile-text fixture, without real data."""
    records = []
    for name, size, ticks, fraction in (
        ("$ILOW.txt", 9007199254740992, 133485408001234566, "1234566"),
        ("$IHIGH.txt", 9007199254740993, 133485408001234567, "1234567"),
    ):
        records.append(
            {
                "record_type": "metadata",
                "source_path": "/case/" + name,
                "source_name": name,
                "source_size": 84,
                "source_sha256": "a" * 64,
                "sid": "S-1-5-21-1001",
                "status": "ok",
                "issues": [],
                "metadata": {
                    "format_version": 2,
                    "original_path": r"C:\Users\Demo\report.txt",
                    "original_size": size,
                    "deletion_filetime": ticks,
                    "deleted_at_utc": f"2024-01-01T00:00:00.{fraction}Z",
                    "deleted_at_display": f"2024-01-01T00:00:00.{fraction}+00:00",
                },
                "payload": {
                    "path": "/case/" + name.replace("$I", "$R"),
                    "status": "available_file",
                    "size": size,
                    "sha256": "b" * 64,
                    "hash_status": "computed",
                    "size_matches_metadata": True,
                },
            }
        )
    records[1]["metadata"]["original_path"] = (
        'C:\\<img src=x onerror="window.injected=1">\\report.txt'
    )
    records[1]["status"] = "warning"
    records[1]["issues"] = [
        {
            "code": "hostile_text_example",
            "severity": "warning",
            "message": "</script><script>window.injected=1</script>",
        }
    ]
    records.append(
        {
            "record_type": "orphan_payload",
            "source_path": "/case/$RORPHAN.bin",
            "source_name": "$RORPHAN.bin",
            "source_size": None,
            "source_sha256": None,
            "sid": None,
            "status": "warning",
            "metadata": None,
            "payload": {
                "path": "/case/$RORPHAN.bin",
                "status": "available_file",
                "size": 0,
                "sha256": None,
                "hash_status": "not_requested",
                "size_matches_metadata": None,
            },
            "issues": [
                {"code": "orphan_payload", "severity": "warning", "message": "No matching metadata"}
            ],
        }
    )
    return {
        "schema_version": "2.0",
        "tool": {"name": "rbinforensics", "version": "1.0.0"},
        "input": "/case",
        "started_at_utc": "2024-02-01T00:00:00+00:00",
        "completed_at_utc": "2024-02-01T00:00:01+00:00",
        "options": {"case_id": "BROWSER-TEST", "examiner": "Synthetic", "timezone": "UTC"},
        "summary": {"candidates": 2, "parsed": 2, "errors": 0, "warnings": 2, "skipped": 0},
        "records": records,
    }


@pytest.fixture(scope="module")
def report_url(tmp_path_factory: pytest.TempPathFactory):
    directory = tmp_path_factory.mktemp("browser-report")
    (directory / "report.html").write_text(render_html(_report()), encoding="utf-8")

    class Handler(SimpleHTTPRequestHandler):
        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Handler, directory=str(directory)))
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/report.html"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture(scope="module")
def browser():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.fail("RBF_RUN_BROWSER=1 requires Playwright: install the 'browser' extra.")
    executable = os.environ.get("RBF_CHROMIUM") or next(
        (
            path
            for name in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable")
            if (path := shutil.which(name))
        ),
        None,
    )
    if not executable or not Path(executable).is_file():
        pytest.fail(
            "RBF_RUN_BROWSER=1 requires Chromium/Chrome; set RBF_CHROMIUM to its executable."
        )
    with sync_playwright() as playwright:
        instance = playwright.chromium.launch(
            executable_path=executable,
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage"],
        )
        try:
            yield instance
        finally:
            instance.close()


def test_browser_exact_integer_sort_search_and_filters(browser, report_url: str) -> None:
    page = browser.new_page(viewport={"width": 1440, "height": 1000})
    try:
        page.goto(report_url)
        assert page.locator("html").get_attribute("class") == "enhanced"
        assert page.locator("#visible-count").inner_text() == "3"
        page.select_option("#record-sort", "size")
        page.select_option("#sort-direction", "desc")
        rows = page.locator("#inventory-body tr")
        assert rows.nth(0).get_attribute("data-source") == "$IHIGH.txt"
        assert rows.nth(1).get_attribute("data-source") == "$ILOW.txt"
        assert rows.nth(2).get_attribute("data-source") == "$RORPHAN.bin"
        page.select_option("#record-sort", "time")
        assert rows.nth(0).get_attribute("data-source") == "$IHIGH.txt"
        assert rows.nth(1).get_attribute("data-source") == "$ILOW.txt"
        assert rows.nth(2).get_attribute("data-time") == ""
        page.fill("#record-search", "nothing-matches")
        assert page.locator("#visible-count").inner_text() == "0"
        assert page.locator("#no-visible-records").is_visible()
        assert page.get_by_text("hostile_text_example", exact=False).is_visible()
        page.click("#reset-controls")
        assert page.locator("#visible-count").inner_text() == "3"
        page.select_option("#record-kind", "orphan_payload")
        assert page.locator("#visible-count").inner_text() == "1"
        page.click("#reset-controls")
        page.select_option("#record-status", "ok")
        assert page.locator("#visible-count").inner_text() == "1"
        page.emulate_media(media="print")
        assert page.locator("#inventory-body tr:visible").count() == 3
    finally:
        page.close()


def test_browser_csp_hostile_text_is_inert_and_mobile_layout(browser, report_url: str) -> None:
    page = browser.new_page(viewport={"width": 390, "height": 844})
    errors, console_errors, requests = [], [], []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.on(
        "console",
        lambda message: console_errors.append(message.text) if message.type == "error" else None,
    )
    page.on("request", lambda request: requests.append(request.url))
    # Browsers may request their own favicon even without a document resource.
    page.route("**/favicon.ico", lambda route: route.fulfill(status=204))
    try:
        page.goto(report_url)
        assert page.locator("html").get_attribute("class") == "enhanced"
        assert page.locator("img").count() == 0
        assert page.locator("script").count() == 1
        assert page.evaluate("typeof window.injected") == "undefined"
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        page.fill("#record-search", "report.txt")
        assert page.locator("#visible-count").inner_text() == "2"
        assert not errors, errors
        assert not console_errors, console_errors
        origin = report_url.rsplit("/", 1)[0]
        assert all(url.startswith(origin + "/") for url in requests), requests
    finally:
        page.close()
