# Changelog

## 1.4.0

### Added

- Save JSON / discard / cancel protection before replacing or closing a completed analysis that has not been saved.
- Analysis-specific saved-state tracking: only a successful full-inventory JSON export acknowledges a save; CSV/HTML retain the safeguard.
- Regression coverage for save cancellation, failed exports, filtered results, empty inventories, and deferred actions.

### Changed

- Application/package version is `1.4.0`; completed forensic reports retain schema `2.0`.
- A pending close/new scan continues only after its requested JSON export succeeds.

## 1.3.0

### Added

- A deterministic synthetic validation corpus with an independent expected manifest, file hashes, and a verifier.
- Reproducible comparison with pinned rifiuti2, including explicit precision limits and documented reference differences.
- Comparison of controlled Windows Shell samples with the independent reference parser in CI.
- Scan/hash and optional native-GUI performance benchmarks with measured timing and process memory reports.
- Versioned GitHub Releases containing verified Windows/Python packages, a demo dataset, validation reports, and checksums.

### Changed

- Application/package version is `1.3.0`; completed forensic reports remain schema `2.0`.
- Official release publication requires the test matrix, reference validation, and native Windows package validation to succeed.

## 1.2.0

### Added

- A full-width detail area below the results table, with an adjustable table/detail separator.
- A resizable separate detail window and grouped summary, metadata, payload, and hash/source fields.
- Quick search with foldable advanced filters, a compact full-scan summary, and adjustable desktop text size.
- A responsive toolbar and date inputs that preserve button access on narrow windows with enlarged text.
- Clickable desktop column headings to sort the complete view by path, deletion time, size, or status before pagination.
- Presentation and native-widget regression coverage for detail selection, sorting precision, font changes, and workspace sizing.

### Changed

- Application/package version is `1.2.0`; completed JSON reports remain schema `2.0`.
- Detail labels distinguish successfully decoded metadata from missing or unavailable payload content.
- Desktop sorting uses raw integer FILETIME/size values and keeps unknown values at the end in either direction. It does not reorder exported report records or fabricate missing values.
- Changing a page, filter, or scan scope clears details for a selection that is no longer visible; enlarged details follow the current selection.
- Display size and pane position are session controls, not persistent case data.

## 1.1.0

### Added

- A local Tk desktop interface with evidence selection, analysis options, result tables, filters, details, and report export.
- Background scan/export work so desktop interactions do not block the event loop.
- Discovery, processing, and hashing progress with cooperative cancellation.
- A Windows portable-package build with bundled Tcl/Tk/timezone support, startup validation, ZIP output, and SHA-256 checksums.
- Desktop documentation and GUI/controller/cancellation regression coverage.

### Changed

- Application/package version is `1.1.0`; the completed JSON report contract remains schema `2.0`.
- Cancelling an analysis leaves it explicitly incomplete and does not expose a completed report for export. Starting a new scan clears the previous in-memory result.
- CLI and desktop continue to share one parser, scanner, selection, and report-writing implementation.

## 1.0.0

First numbered 1.0 release of the expanded toolkit.

### Added

- Directory inventory of orphan `$R` files and directories with explicit missing-metadata interpretation.
- Literal search and filters for extensions, SID, original size, and deletion-time bounds.
- Exact-tick deletion ordering and selected-view statistics by UTC day, SID, and extension.
- Standalone offline HTML reports with browser review controls and protected evidence text.
- Chromium regression tests for report interaction, exact uint64 sorting, and inert untrusted markup.
- A full-inventory JSON contract with explicit selection and timeline objects.
- Expanded validation, documentation, and an opt-in controlled Windows artefact validation procedure.

### Changed

- Application/package version is `1.0.0`.
- New reports declare schema version `2.0`. The earlier development `1.0` report schema remains available for historical reports; it does not validate new reports.
- Recursive inventory treats `$R` directories as payload objects instead of walking into their contents.
- Human/CSV/HTML output presents selected records. JSON retains all scan records so filters do not erase the audit inventory.

### Migration from development reports

1. Check `schema_version` before consuming JSON; use the matching schema file.
2. Account for `orphan_payload` records whose metadata is `null`.
3. Treat `summary` as full scan scope and `selection` as the requested view including mandatory diagnostics.
4. Read `timeline` only as an interpretation of selected valid deletion timestamps.
5. Retain raw uint64 values with an exact-integer JSON consumer.

The release number describes the software contract, not forensic certification. Operational adoption still requires validation against known-good artefacts relevant to the intended environment.
