# Changelog

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
