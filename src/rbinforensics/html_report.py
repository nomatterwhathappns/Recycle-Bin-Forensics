"""Standalone offline presentation; evidence is text, never executable markup.

The single embedded script is static and CSP-authorized by its SHA-256. No
evidence is interpolated into JavaScript. Browser controls read escaped DOM
attributes and use exact BigInt comparisons for raw 64-bit values.
"""

from __future__ import annotations

import base64
import hashlib
import html
import unicodedata
from collections import Counter
from collections.abc import Iterator

from .limits import WorkLimits, check_budget

_SCRIPT = """'use strict';
(() => {
  const query = document.getElementById('record-search');
  const kind = document.getElementById('record-kind');
  const status = document.getElementById('record-status');
  const sort = document.getElementById('record-sort');
  const direction = document.getElementById('sort-direction');
  const body = document.getElementById('inventory-body');
  const rows = Array.from(body.querySelectorAll('tr'));
  const count = document.getElementById('visible-count');
  const empty = document.getElementById('no-visible-records');
  const numeric = (left, right) => {
    const a = /^\\d+$/.test(left);
    const b = /^\\d+$/.test(right);
    if (!a || !b) return a ? -1 : b ? 1 : 0;
    const x = BigInt(left), y = BigInt(right);
    return (x < y ? -1 : x > y ? 1 : 0) * (direction.value === 'desc' ? -1 : 1);
  };
  function update() {
    const needle = query.value.toLowerCase();
    let visible = 0;
    rows.sort((a, b) => {
      let value;
      if (sort.value === 'size' || sort.value === 'time') {
        value = numeric(a.dataset[sort.value], b.dataset[sort.value]);
      } else {
        value = a.dataset.source.localeCompare(b.dataset.source);
        if (direction.value === 'desc') value *= -1;
      }
      return value || Number(a.dataset.order) - Number(b.dataset.order);
    });
    for (const row of rows) {
      const matches = row.dataset.search.toLowerCase().includes(needle)
        && (!kind.value || row.dataset.kind === kind.value)
        && (!status.value || row.dataset.status === status.value);
      row.hidden = !matches;
      if (matches) visible += 1;
      body.appendChild(row);
    }
    count.textContent = String(visible);
    empty.hidden = visible !== 0;
  }
  for (const element of [query, kind, status, sort, direction]) {
    element.addEventListener(element === query ? 'input' : 'change', update);
  }
  document.getElementById('reset-controls').addEventListener('click', () => {
    query.value = ''; kind.value = ''; status.value = '';
    sort.value = 'source'; direction.value = 'asc'; update(); query.focus();
  });
  document.getElementById('print-report').addEventListener('click', () => window.print());
  document.documentElement.classList.add('enhanced');
  update();
})();"""

_STYLE = """
:root{color-scheme:light;--bg:#f4f6f8;--paper:#fff;--ink:#172630;--muted:#5d6c76;
--line:#dce3e8;--accent:#087e83;--pale:#e8f5f4;--warn:#9a5a06;--error:#b52d43}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:14px/1.55 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
a{color:var(--accent)}button,input,select{font:inherit}button,select,input{min-height:40px}
button{cursor:pointer}button:focus-visible,input:focus-visible,select:focus-visible,
summary:focus-visible{outline:3px solid #149ca6;outline-offset:3px}
.skip{position:absolute;left:12px;top:-80px;background:white;padding:10px;z-index:10}
.skip:focus{top:10px}.shell{max-width:1440px;margin:auto;padding:32px 40px 48px}
.topbar{display:flex;justify-content:space-between;align-items:center;gap:20px;
border-bottom:1px solid var(--line);padding-bottom:22px;margin-bottom:30px}
.brand{display:flex;align-items:center;gap:12px;font-weight:750;letter-spacing:-.02em;font-size:16px}
.mark{display:grid;place-items:center;width:38px;height:38px;border-radius:10px;
background:var(--ink);color:white;font:700 14px ui-monospace,monospace;letter-spacing:0}
.topmeta{display:flex;align-items:center;gap:14px;color:var(--muted);font-size:12px}
.offline{border:1px solid #b8dcd7;border-radius:20px;padding:4px 10px;background:var(--pale);color:#09686b}
.hero{display:flex;justify-content:space-between;gap:24px;align-items:flex-end;margin:0 0 24px}
.eyebrow{font-size:11px;letter-spacing:.15em;text-transform:uppercase;color:var(--accent);font-weight:750}
h1{font-size:clamp(30px,4vw,42px);letter-spacing:-.05em;line-height:1.14;margin:8px 0 10px}
h2{font-size:19px;letter-spacing:-.025em;margin:0}h3{font-size:15px;margin:0 0 12px}
p{margin:8px 0}.muted{color:var(--muted)}.hero p{font-size:15px;color:var(--muted);max-width:760px}
.button{border:1px solid var(--line);background:var(--paper);border-radius:7px;padding:8px 14px;color:var(--ink)}
.summary-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin-bottom:24px}
.stat{padding:19px 22px;background:var(--paper);border:1px solid var(--line);border-radius:10px}
.stat-label{font-size:12px;color:var(--muted)}.stat-value{display:block;font-size:32px;line-height:1.4;
font-weight:700;letter-spacing:-.04em;font-variant-numeric:tabular-nums}.stat-note{font-size:11px;color:var(--muted)}
.panel{background:var(--paper);border:1px solid var(--line);border-radius:10px;margin:0 0 24px;overflow:hidden}
.section-head{display:flex;justify-content:space-between;align-items:flex-start;gap:20px;padding:22px 24px;
border-bottom:1px solid var(--line)}.section-head p{font-size:12px;color:var(--muted);margin:4px 0 0}
.tag{font:11px ui-monospace,SFMono-Regular,monospace;color:var(--muted);white-space:nowrap;padding-top:4px}
.context{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:18px 28px;padding:20px 24px;margin:0}
dt{font-size:11px;color:var(--muted);margin-bottom:3px}dd{margin:0;overflow-wrap:anywhere;font-size:13px}
.wide{grid-column:1/-1}code,.mono{font:12px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere}
.scope{padding:13px 24px;background:#f8fbfc;border-bottom:1px solid var(--line);font-size:12px;color:var(--muted)}
.scope strong{color:var(--ink)}.controls{display:none;grid-template-columns:minmax(180px,1fr) repeat(4,minmax(110px,auto)) auto;
gap:10px;padding:18px 24px;border-bottom:1px solid var(--line);align-items:end}.enhanced .controls{display:grid}
.control label{display:block;font-size:11px;color:var(--muted);margin-bottom:5px}.control input,.control select{
width:100%;border:1px solid #cbd5dc;border-radius:6px;background:var(--paper);color:var(--ink);padding:8px 10px}
.countline{padding:10px 24px;font-size:11px;color:var(--muted);border-bottom:1px solid var(--line)}
.table-scroll{overflow:auto}table{width:100%;border-collapse:collapse;min-width:850px;text-align:left}
th{font-size:10px;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);background:#f8fafb;
padding:12px 16px;border-bottom:1px solid var(--line);font-weight:700}td{vertical-align:top;padding:17px 16px;
border-bottom:1px solid #e9eef1;font-size:12px}th:first-child,td:first-child{padding-left:24px;width:40%}
tbody tr:last-child td{border-bottom:0}.artifact{font-weight:700;font-size:13px;margin-bottom:5px}
.original{color:var(--ink);margin-bottom:5px}.small{font-size:11px}.badge{display:inline-block;border-radius:4px;
padding:2px 7px;font-size:10px;letter-spacing:.03em;background:#edf2f5;color:#50616d;white-space:nowrap}
.badge.ok{background:var(--pale);color:#086d66}.badge.warning{background:#fff3dd;color:var(--warn)}
.badge.error{background:#fce9ed;color:var(--error)}.badge.skipped{background:#eef0f4;color:#5b6677}
.nowrap{white-space:nowrap}.number{font-variant-numeric:tabular-nums;white-space:nowrap}
details{margin-top:10px}summary{cursor:pointer;color:var(--accent);font-size:11px}
.record-details{display:grid;grid-template-columns:1fr;gap:7px;margin:10px 0 0}
.record-details dd{font-size:11px}.record-details dt{font-size:10px}.empty{padding:34px 24px;color:var(--muted);
text-align:center}.two-columns{display:grid;grid-template-columns:minmax(0,1.5fr) minmax(240px,1fr);gap:24px}
.timeline{list-style:none;margin:0;padding:6px 24px 14px;max-height:470px;overflow:auto}
.timeline li{display:grid;grid-template-columns:12px 1fr;gap:14px;padding:16px 0;border-bottom:1px solid #edf1f4}
.timeline li:last-child{border:0}.dot{width:8px;height:8px;margin-top:7px;border:2px solid var(--accent);border-radius:50%}
.timeline time{font:11px ui-monospace,monospace;color:var(--muted)}.event-path{margin-top:5px;overflow-wrap:anywhere}
.event-meta{margin-top:5px;font-size:10px;color:var(--muted)}.bars{list-style:none;padding:16px 24px 8px;margin:0}
.bars li{margin-bottom:16px}.bar-label{display:flex;justify-content:space-between;gap:12px;font-size:11px;color:var(--muted)}
.track{height:6px;background:#edf3f5;border-radius:9px;margin-top:6px;overflow:hidden}.bar{height:100%;background:var(--accent);border-radius:9px}
.notes{padding:0 24px 20px;color:var(--muted);font-size:11px}.diagnostics{list-style:none;margin:0;padding:0 24px}
.diagnostics>li{padding:17px 0;border-bottom:1px solid var(--line)}.diagnostics>li:last-child{border:0}
.issue-list{padding-left:18px;margin:8px 0 0}.issue-list li{margin:5px 0;font-size:12px;overflow-wrap:anywhere}
.issue-code{font-family:ui-monospace,monospace;font-size:11px}.footnote{font-size:11px;color:var(--muted);
display:flex;justify-content:space-between;gap:24px;border-top:1px solid var(--line);padding-top:20px}
[hidden]{display:none!important}noscript p{margin:14px 24px;padding:10px;background:#fff3dd;font-size:12px}
@media(max-width:1100px){.controls{grid-template-columns:repeat(3,minmax(0,1fr))}.control:first-child{grid-column:span 2}}
@media(max-width:760px){.shell{padding:20px 16px}.hero{align-items:flex-start}.summary-grid{grid-template-columns:repeat(2,minmax(0,1fr))}
.stat{padding:14px 16px}.stat-value{font-size:28px}.context{grid-template-columns:1fr 1fr}.two-columns{grid-template-columns:1fr;gap:0}
.controls{grid-template-columns:1fr 1fr}.control:first-child{grid-column:1/-1}.section-head,.scope,.controls{padding-left:18px;padding-right:18px}
.topmeta .version{display:none}.topbar{margin-bottom:24px}.hero .button{display:none}.footnote{flex-direction:column;gap:8px}}
@media print{body{background:white;font-size:10pt}.shell{max-width:none;padding:0}.topbar{margin-bottom:16px}
.controls,.hero .button,.skip,.countline{display:none!important}.panel{break-inside:avoid;border-radius:0}.summary-grid{gap:8px}
.section-head{padding:12px}.scope,.context,.notes{padding:12px}.table-scroll,.timeline{overflow:visible;max-height:none}
table{min-width:0}.two-columns{display:block}details{display:none}.footnote{font-size:8pt}.enhanced tr[hidden]{display:table-row!important}}
"""


def _iter_text(value: object | None) -> Iterator[str]:
    """Escape bounded text pieces so one evidence value cannot build a document."""
    raw = "Unknown" if value is None else str(value)
    for offset in range(0, len(raw), 4096):
        check_budget()
        visible = "".join(
            f"\\u{ord(char):04x}" if unicodedata.category(char).startswith("C") else char
            for char in raw[offset : offset + 4096]
        )
        yield html.escape(visible, quote=True)


def _iter_field(label: str, value: object | None, *, wide: bool = False) -> Iterator[str]:
    css = ' class="wide"' if wide else ""
    yield f"<div{css}><dt>"
    yield from _iter_text(label)
    yield "</dt><dd>"
    yield from _iter_text(value)
    yield "</dd></div>"


def _iter_badge(value: object) -> Iterator[str]:
    # CSS class selection comes from a closed vocabulary, never evidence text.
    css = value if value in ("ok", "warning", "error", "skipped") else ""
    yield f'<span class="badge {css}">'
    yield from _iter_text(value)
    yield "</span>"


def _iter_record_row(record: dict, order: int) -> Iterator[str]:
    check_budget()
    metadata = record.get("metadata") or {}
    payload = record.get("payload") or {}
    name = record.get("source_name", "Unknown")
    original = metadata.get("original_path")
    size = metadata.get("original_size", payload.get("size"))
    deleted = metadata.get("deleted_at_utc")
    raw_time = metadata.get("deletion_filetime") if deleted else ""
    attributes = {
        "source": name,
        "size": "" if size is None else size,
        "time": raw_time,
        "order": order,
        "kind": record.get("record_type", "metadata"),
        "status": record.get("status", "unknown"),
    }
    yield "<tr "
    for key, value in attributes.items():
        yield f'data-{key}="'
        yield from _iter_text(value)
        yield '" '
    yield 'data-search="'
    for index, value in enumerate((name, record.get("source_path"), original, record.get("sid"))):
        if index:
            yield " "
        yield from _iter_text(str(value or ""))
    yield '"><td><div class="artifact">'
    yield from _iter_text(name)
    yield "</div>"
    if original is not None:
        yield '<div class="original mono">'
        yield from _iter_text(original)
        yield "</div>"
    yield '<span class="badge">'
    yield from _iter_text(record.get("record_type", "metadata"))
    yield '</span><details><summary>Provenance &amp; details</summary><dl class="record-details">'
    for label, value in (
        ("Acquired source path", record.get("source_path")),
        ("Source size (bytes)", record.get("source_size")),
        ("Source SHA-256", record.get("source_sha256")),
        ("SID context", record.get("sid")),
        ("Metadata format", metadata.get("format_version")),
        ("Raw deletion FILETIME", metadata.get("deletion_filetime")),
        ("Display time", metadata.get("deleted_at_display")),
        ("Payload path", payload.get("path")),
        ("Payload size (bytes)", payload.get("size")),
        ("Payload SHA-256", payload.get("sha256")),
        ("Payload hash status", payload.get("hash_status")),
        ("Payload size matches metadata", payload.get("size_matches_metadata")),
    ):
        yield from _iter_field(label, value)
    yield '</dl></details></td><td class="mono nowrap">'
    yield from _iter_text(deleted)
    yield '</td><td class="number">'
    yield from _iter_text(size)
    yield '</td><td><span class="badge">'
    yield from _iter_text(payload.get("status"))
    yield "</span></td><td>"
    yield from _iter_badge(record.get("status", "unknown"))
    yield "</td></tr>"


def _timeline(report: dict, selected: list[dict]) -> dict:
    if "timeline" in report:
        check_budget()
        return report["timeline"]
    # Rendering a scanner-only report remains useful for library consumers.
    events = []
    for record in selected:
        check_budget()
        metadata = record.get("metadata") or {}
        if metadata.get("deleted_at_utc"):
            events.append(
                {**metadata, "source_path": record["source_path"], "sid": record.get("sid")}
            )

    def event_key(event: dict) -> tuple:
        check_budget()
        return event["deletion_filetime"], event["source_path"]

    events.sort(key=event_key)
    check_budget()
    days: Counter = Counter()
    for event in events:
        check_budget()
        days[event["deleted_at_utc"][:10]] += 1
    daily_counts = []
    for day, count in sorted(days.items()):
        check_budget()
        daily_counts.append({"date_utc": day, "count": count})
    return {
        "events": events,
        "undated_records": len(selected) - len(events),
        "daily_counts": daily_counts,
    }


def _iter_timeline(timeline: dict) -> Iterator[str]:
    events = timeline.get("events", [])
    yield (
        '<section class="panel" aria-labelledby="timeline-heading"><div class="section-head">'
        '<div><h2 id="timeline-heading">Deletion timeline</h2><p>Selected records, ordered by raw FILETIME. Times below are UTC.</p></div>'
        f'<span class="tag">{len(events)} events</span></div>'
    )
    if events:
        yield '<ol class="timeline">'
        for event in events:
            check_budget()
            yield '<li><span class="dot" aria-hidden="true"></span><div><time>'
            yield from _iter_text(event.get("deleted_at_utc"))
            yield '</time><div class="event-path mono">'
            yield from _iter_text(event.get("original_path"))
            yield '</div><div class="event-meta">'
            yield from _iter_text(event.get("original_size"))
            yield " bytes &middot; SID "
            yield from _iter_text(event.get("sid"))
            yield "</div></div></li>"
        yield "</ol>"
    else:
        yield '<div class="empty">No selected records have a usable deletion timestamp.</div>'
    yield '<p class="notes">'
    yield from _iter_text(timeline.get("undated_records", 0))
    yield (
        " selected records have no usable deletion timestamp. "
        "Source filesystem times are never substituted.</p></section>"
    )


def _iter_days(timeline: dict) -> Iterator[str]:
    days = timeline.get("daily_counts", [])
    maximum = 1
    for index, day in enumerate(days):
        check_budget()
        maximum = max(maximum, day["count"]) if index else day["count"]
    yield (
        '<section class="panel" aria-labelledby="daily-heading"><div class="section-head"><div>'
        '<h2 id="daily-heading">Activity by day</h2><p>UTC day &middot; selected deletion events</p></div></div>'
    )
    if days:
        yield '<ul class="bars">'
        for day in days:
            check_budget()
            yield '<li><div class="bar-label"><span>'
            yield from _iter_text(day["date_utc"])
            yield "</span><strong>"
            yield from _iter_text(day["count"])
            yield '</strong></div><div class="track"><div class="bar" style="width:'
            yield str(int(day["count"] * 100 / maximum))
            yield '%"></div></div></li>'
        yield "</ul>"
    else:
        yield '<div class="empty">No dated events in this selection.</div>'
    yield '<p class="notes">Counts describe supplied artifacts. A quiet day does not establish that no deletion occurred.</p></section>'


def _iter_diagnostics(records: list[dict]) -> Iterator[str]:
    affected = 0
    for record in records:
        check_budget()
        affected += bool(record.get("issues"))
    yield (
        '<section class="panel" aria-labelledby="diagnostics-heading"><div class="section-head"><div>'
        '<h2 id="diagnostics-heading">Warnings &amp; errors</h2>'
        "<p>Complete scan diagnostics. CLI selection and browser filters never hide this section.</p></div>"
        f'<span class="tag">{affected} affected records</span></div>'
    )
    if affected:
        yield '<ul class="diagnostics">'
        for record in records:
            check_budget()
            if not record.get("issues"):
                continue
            yield '<li><div class="mono">'
            yield from _iter_text(record.get("source_path"))
            yield '</div><ul class="issue-list">'
            for issue in record["issues"]:
                check_budget()
                yield "<li>"
                yield from _iter_badge(issue.get("severity", "warning"))
                yield ' <span class="issue-code">'
                yield from _iter_text(issue.get("code"))
                yield "</span>: "
                yield from _iter_text(issue.get("message"))
                yield "</li>"
            yield "</ul></li>"
        yield "</ul>"
    else:
        yield '<div class="empty">No warnings or errors were recorded.</div>'
    yield "</section>"


def _iter_html(report: dict) -> Iterator[str]:
    """Stream an offline report; the public renderer owns the operation budget."""
    records = report["records"]
    selection = report.get("selection") or {}
    indexes = selection.get("record_indexes", range(len(records)))
    selected = []
    for index in indexes:
        check_budget()
        selected.append(records[index])
    timeline = _timeline(report, selected)
    summary = report["summary"]
    options = report["options"]
    tool = report["tool"]
    orphan_count = problem_count = 0
    for record in records:
        check_budget()
        orphan_count += record.get("record_type") == "orphan_payload"
        problem_count += record.get("status") in ("warning", "error", "skipped")
    kinds = set()
    for record in selected:
        check_budget()
        kinds.add(record.get("record_type", "metadata"))
    kinds = sorted(kinds)
    check_budget()
    empty_hidden = " hidden" if selected else ""
    state = "active" if selection.get("active") else "not active"
    script_hash = base64.b64encode(hashlib.sha256(_SCRIPT.encode("utf-8")).digest()).decode("ascii")
    csp = (
        "default-src 'none'; base-uri 'none'; object-src 'none'; form-action 'none'; "
        f"style-src 'unsafe-inline'; script-src 'sha256-{script_hash}'"
    )
    yield (
        '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f'<meta http-equiv="Content-Security-Policy" content="{html.escape(csp, quote=True)}">'
        '<meta name="referrer" content="no-referrer">'
        "<title>Recycle Bin Forensics — Offline report</title>"
        f'<style>{_STYLE}</style></head><body><a class="skip" href="#inventory-heading">Skip to inventory</a>'
        '<main class="shell"><header class="topbar"><div class="brand"><span class="mark" aria-hidden="true">RB</span>'
        'Recycle Bin Forensics</div><div class="topmeta"><span class="version">v'
    )
    yield from _iter_text(tool.get("version"))
    yield (
        '</span><span class="offline">Offline report</span></div></header>'
        '<div class="hero"><div><span class="eyebrow">Evidence inventory &amp; timeline</span>'
        "<h1>Recycle Bin analysis</h1><p>Review recorded deletion artifacts, payload availability, and the findings that need attention.</p></div>"
        '<button id="print-report" class="button" type="button">Print report</button></div>'
        '<div class="summary-grid" aria-label="Complete scan summary">'
    )
    for label, value, note in (
        ("Inventory records", len(records), "Complete supplied scan scope"),
        ("Metadata parsed", summary.get("parsed", 0), "Decoded $I artifacts"),
        ("Orphan payloads", orphan_count, "No matching metadata observed"),
        ("Records needing review", problem_count, "Warnings, errors, or skipped items"),
    ):
        yield f'<div class="stat"><span class="stat-label">{label}</span><strong class="stat-value">'
        yield from _iter_text(value)
        yield f'</strong><span class="stat-note">{note}</span></div>'
    yield (
        '</div><section class="panel" aria-labelledby="context-heading"><div class="section-head"><div>'
        '<h2 id="context-heading">Run context</h2><p>Operator-supplied labels and analysis-system run times.</p></div></div>'
        '<dl class="context">'
    )
    for label, value, wide in (
        ("Case identifier", options.get("case_id") or "Not supplied", False),
        ("Examiner label", options.get("examiner") or "Not supplied", False),
        ("Display timezone", options.get("timezone", "UTC"), False),
        ("Run started (UTC)", report.get("started_at_utc"), False),
        ("Run completed (UTC)", report.get("completed_at_utc"), False),
        ("Schema version", report.get("schema_version"), False),
        ("Acquired input", report.get("input"), True),
    ):
        yield from _iter_field(label, value, wide=wide)
    yield (
        '</dl></section><section class="panel" aria-labelledby="inventory-heading"><div class="section-head"><div>'
        '<h2 id="inventory-heading">Artifact inventory</h2><p>Inspect original paths, deletion times, payload state, and provenance.</p></div>'
        f'<span class="tag">{len(selected)} selected / {len(records)} total</span></div>'
        f'<div class="scope"><strong>Full scan summary stays unchanged.</strong> CLI selection is {state}: '
        f"{len(selected)} records included, {len(records) - len(selected)} excluded."
    )
    if selection.get("active"):
        yield " Applied CLI filters: "
        separator = ""
        for key, value in (selection.get("filters") or {}).items():
            check_budget()
            if value is not None and value != () and value != []:
                yield separator
                yield from _iter_text(f"{key}={value}")
                separator = "; "
        yield "."
    yield (
        " Browser controls affect only this inventory view; the timeline retains the CLI selection.</div>"
        '<div class="controls" role="search" aria-label="Filter artifact inventory">'
        '<div class="control"><label for="record-search">Search path, filename, or SID</label>'
        '<input id="record-search" type="search" placeholder="Search selected artifacts…" autocomplete="off"></div>'
        '<div class="control"><label for="record-kind">Record type</label><select id="record-kind"><option value="">All types</option>'
    )
    for kind in kinds:
        yield '<option value="'
        yield from _iter_text(kind)
        yield '">'
        yield from _iter_text(kind)
        yield "</option>"
    yield (
        '</select></div><div class="control"><label for="record-status">Status</label><select id="record-status"><option value="">All states</option>'
        '<option value="ok">ok</option><option value="warning">warning</option><option value="error">error</option>'
        '<option value="skipped">skipped</option></select></div>'
        '<div class="control"><label for="record-sort">Sort by</label><select id="record-sort">'
        '<option value="source">Artifact name</option><option value="time">Deletion time</option><option value="size">Size in bytes</option></select></div>'
        '<div class="control"><label for="sort-direction">Order</label><select id="sort-direction">'
        '<option value="asc">Ascending</option><option value="desc">Descending</option></select></div>'
        '<button id="reset-controls" class="button" type="button">Reset</button></div>'
        "<noscript><p>JavaScript is disabled. All selected inventory records remain visible; browser controls are unavailable.</p></noscript>"
        f'<div class="countline" role="status" aria-live="polite"><span id="visible-count">{len(selected)}</span> visible of {len(selected)} CLI-selected records</div>'
        '<div class="table-scroll"><table aria-label="Selected artifact inventory"><thead><tr>'
        '<th scope="col">Artifact / recorded original path</th><th scope="col">Deleted (UTC)</th><th scope="col">Original bytes / orphan size</th>'
        '<th scope="col">Payload</th><th scope="col">State</th></tr></thead><tbody id="inventory-body">'
    )
    for order, record in enumerate(selected):
        yield from _iter_record_row(record, order)
    yield (
        "</tbody></table></div>"
        f'<div id="no-visible-records" class="empty"{empty_hidden}>No records match this view. Reset browser controls or review the CLI selection.</div></section>'
        '<div class="two-columns">'
    )
    yield from _iter_timeline(timeline)
    yield from _iter_days(timeline)
    yield "</div>"
    yield from _iter_diagnostics(records)
    yield (
        '<footer class="footnote"><span>Recorded artifacts support analysis; they do not establish actor, intent, authenticity, or acquisition completeness. '
        'Preserve source bytes and corroborate findings independently.</span><span class="nowrap">'
    )
    yield from _iter_text(tool.get("name"))
    yield " "
    yield from _iter_text(tool.get("version"))
    yield " &middot; schema "
    yield from _iter_text(report.get("schema_version"))
    yield f"</span></footer></main><script>{_SCRIPT}</script></body></html>\n"


def render_html(report: dict, *, limits: WorkLimits | None = None) -> str:
    """Return a complete bounded offline report without changing report values."""
    from .reports import render

    return render(report, "html", limits=limits)
