# Desktop user guide

Recycle Bin Forensics 1.3.0 provides a local Tk desktop interface to the same engine used by `rbf scan`. The interface labels are in Indonesian. It reads an acquired `$I` file or an evidence directory and produces the existing schema 2.0 report formats. It does not upload evidence or require a local web server.

## Windows portable package

1. Open this repository's [GitHub Releases](https://github.com/nomatterwhathappns/Recycle-Bin-Forensics/releases).
2. Select the intended version and download its Windows x64 ZIP plus `SHA256SUMS.txt`.
3. Compare the ZIP's SHA-256 with its entry in `SHA256SUMS.txt` before extraction.
4. Locate the versioned portable ZIP and `SHA256SUMS.txt`. For 1.3.0, the package name is `RecycleBinForensics-1.3.0-windows-x64.zip`.
5. Extract the portable ZIP to a chosen application folder. Keep all extracted files and subdirectories together.
6. Open `RecycleBinForensics.exe` inside the extracted application folder.

The portable build contains Python, Tcl/Tk, and the timezone database it needs; a separate Python installation is not required. Copying only the executable loses its support files. Download artifacts from the intended repository and matching workflow run. `BUILD-INFO.json` inside the application folder records the build version, commit where available, platform/tool versions, and packaged smoke-test result.

Development packages are also available from successful runs of the [Windows package workflow](../.github/workflows/windows-package.yml). Those temporary Actions artifacts can contain an outer ZIP wrapper; extract the wrapper before following the portable ZIP instructions.

Compare the ZIP's SHA-256 with the supplied checksum file when transferring or archiving a build:

```powershell
Get-FileHash .\RecycleBinForensics-1.3.0-windows-x64.zip -Algorithm SHA256
Get-Content .\SHA256SUMS.txt
```

Checksums identify the downloaded bytes. They are separate from publisher signing or validation of evidence analysed by the application.

## Running from source

After following the [README installation instructions](../README.md#source-installation-and-cli), start the app with one of:

```sh
rbf-gui
python -m rbinforensics.gui
rbf gui
```

Python must include Tk support and have access to a graphical display. `python -m tkinter` opens a small test window when the installation supports Tk. Some Linux distributions provide Tk separately; for example, Debian/Ubuntu system Python uses the matching `python3-tk` package. A virtual environment still depends on the Tk support of the Python that created it. Use a package appropriate to that interpreter rather than assuming another Python installation's Tk will be available.

UTC operation does not require a third-party timezone dependency. Install `.[timezone]` when the source environment lacks the IANA database needed for a named zone. The portable Windows build includes that database.

### Updating a source installation on Parrot/Linux

Close the application before replacing its installed code. In an existing checkout with its virtual environment, run:

```sh
git pull --ff-only
source .venv/bin/activate
python -m pip install '.[timezone]'
rbf --version
rbf-gui
```

The expected version is `rbf 1.3.0`. Keep local modifications when resolving update conflicts. New source code does not change or overwrite reports from earlier runs. For a first installation, use the README setup steps; Debian-derived distributions such as Parrot also need Tk support matching the selected Python interpreter.

## 1. Choose the analysis source

Open **Analisis baru**. Use **Pilih folder** for an acquired Recycle Bin tree or **Pilih file $I** for one metadata item. Check the displayed source before starting.

- Enable subfolders when the input contains nested volume/SID directories.
- Enable payload SHA-256 when content comparison is needed. This reads regular `$R` payload contents and can take longer for large files. Metadata hashing remains part of the analysis.
- Choose the display timezone. UTC, `Asia/Jakarta`, `Asia/Makassar`, and `Asia/Jayapura` are offered; another IANA name can be typed. UTC remains the timestamp reference; a named zone changes the additional display field.
- Add case and examiner labels if useful. These are operator-supplied annotations, not authenticated identities.

The original Windows path encoded inside `$I` remains evidence text. Selecting a metadata item does not cause the app to open that original path on the examiner's computer. Payload lookup uses sibling acquired filenames.

Use a protected original plus a verified working copy or read-only mount. Read-only program operations can still update filesystem access times on a writable source. The [evidence workflow](EVIDENCE_WORKFLOW.md) explains collection and interpretation limits.

## 2. Start, follow progress, or cancel

Select **Mulai analisis**. Filesystem reading and parsing run in a worker thread; the graphical event loop handles controls and displays queued progress.

| Phase | What the app knows |
| --- | --- |
| Discovering | The total inventory has not been established; activity is shown without an invented percentage |
| Processing | Completed item count versus the discovered metadata/orphan inventory |
| Hashing | Bytes processed within the current payload where available |
| Complete | Discovery, reads, parsing, and analysis finished and a report is available |

Use **Batalkan** to request cooperative cancellation. The engine checks for cancellation during discovery, between items, and between payload read blocks. A blocked operating-system read may take time to return before the request can be acted on.

Cancellation leaves the run explicitly incomplete. The application does not present its partial work as a completed report and disables export of that cancelled scan. Starting a new scan clears the previous in-memory report, so an earlier result cannot accidentally be exported as the new run. A completed scan can still contain reported errors or skipped items; completion of the process is different from a clean evidence collection.

If a job is still active when the window is closed, the app asks whether to request cancellation where possible and close after the worker stops. Exports and filters finish before the window closes; an export is not abruptly killed halfway through writing.

## 3. Review the results

Open **Hasil analisis** after a completed run. The compact full-scan summary describes all supplied evidence, while the shown-record count describes the current selection. The table fills the available width; the grouped detail area is below it.

- **Inventaris** presents metadata and orphan payload observations.
- **Timeline** uses decoded deletion FILETIME values. Unknown deletion times stay unknown; payload modification times are not substituted.
- **Perlu ditinjau** exposes all records with issues from the full scan, including records outside the current inventory filter.

Quick search remains visible. Expand the advanced filters when extension, SID, date, or original-size criteria are needed, then select **Terapkan**. Folding the controls away preserves their values and the active selection; it does not silently reset a filter. Check the shown-record count and active-filter indication when a smaller view is in use. Enter alternative extensions separated by commas, for example `.pdf,.docx`. Different filter categories combine with AND; alternative extensions combine with OR. **Reset** rebuilds the view from the complete scan rather than from the currently visible subset.

The calendar buttons choose **UTC dates**. A date-only **Dari** starts at UTC midnight. A date-only **Sampai** includes that entire UTC day through `23:59:59.9999999Z`. Explicit ISO datetimes with `Z` or an offset can also be entered. This is a GUI convenience: CLI date-only `--deleted-before` still means midnight at the start of the date. The GUI records its expanded end-of-day bound in the report selection, so the exact request can be reproduced. Display timezone does not change date-filter meaning.

Diagnostic records remain visible according to the same rules as CLI reports. An item outside an investigative filter can therefore remain shown when its processing failed or was skipped. The review tab remains a full-scan issue list; the inventory and deletion timeline use the requested selection.

Tables show up to 200 records per page. Use the arrow buttons and range counter to browse further pages. Pagination is a display limit, not a scan or export limit; all completed scan records remain available to the report formats.

### Give the table or details more room

Drag the horizontal separator between the table and detail area to change their relative heights. On a small screen with large text, fold the advanced filters away after applying them to give the results room; the toolbar uses an extra row when its controls need it. **Perbesar detail** opens the selected record in a separate resizable window, which can be maximized through the operating system. The enlarged window follows the current selection; clearing a selection, changing pages, or starting another scan must not leave a different record looking current in that window.

Compare the [compact workspace preview](images/desktop-compact.png) with the [enlarged detail preview](images/desktop-detail.png). Both use fictitious demonstration records.

Text-size controls adjust the desktop fonts for the current session. The supported range is 9–16 points, with 11 as the initial size. Font changes preserve the selected record, filter values, and evidence data. These settings do not write preferences or case history to disk. Native fonts and window decorations vary between platforms.

### Read grouped detail fields

Select a row to populate the detail area. Its groups separate the questions an examiner normally asks:

| Group | What to inspect |
| --- | --- |
| **Ringkasan** | Recorded original path, acquired source path, important time/size values, and distinct metadata/payload states |
| **Metadata** | Encoded format version, original size, raw FILETIME, UTC/display timestamp, SID context, and metadata source size |
| **Payload** | Observed sibling classification, acquired path, regular-file size, size comparison, and hashing availability |
| **Hash & sumber** | Explicitly labelled source and payload SHA-256 values and provenance information |

A successful metadata decode and a missing payload can both be true. The detail view therefore describes metadata as successfully read while separately saying that no payload was found; it does not present a single `ok` label as evidence that content exists. An orphan has no decoded original path or deletion time. Source size means metadata-file bytes for a metadata record; it refers to the observed payload for an orphan record.

Long paths and hashes remain selectable, with copy controls for fields that need exact transfer. **Salin seluruh detail** copies the complete grouped detail representation. **Salin hash** copies a computed payload hash when available, otherwise the source hash, and identifies which object was copied in the status message. Source and payload hashes also have separate field-copy controls. Treat copied values as case data. Control characters are shown as escapes in the desktop, while JSON retains the original logical strings.

### Sort a complete table view

Click a path, deletion-time, size, or status heading to sort the complete table view; click again to reverse its direction. Sorting happens before the 200-row page is taken, so an item on a later page can move to the first page. Raw integer FILETIME and size values are compared exactly, including values above JavaScript's safe-integer range. Zero-byte files are known-size observations; unknown values stay at the end in both directions.

Column sorting is a presentation control. It does not modify baseline scan records, the analytical deletion timeline, or exported report ordering. A manual sort can change the displayed order of the Timeline table; choose its deletion-time column in ascending order for a chronological view. Moving to another page or rebuilding a filtered table clears a detail selection that is no longer current. Font resizing preserves the current selection instead.

| State | Meaning |
| --- | --- |
| Missing payload | Metadata was decoded but no matching sibling `$R` was observed |
| Orphan payload | A `$R` entry lacks matching metadata in scope; original path/time are not invented |
| Parse error | A candidate existed but could not be decoded under the supported layouts |
| Skipped | A redirect or another unsafe/nonregular object was deliberately not read |
| Size mismatch | Observed payload size differs from the original size recorded in metadata |

None of these states alone establishes who deleted an item, why it happened, or whether an acquisition was complete.

## 4. Export and open a report

Choose HTML for interactive review in a browser, JSON for a complete structured audit inventory, or CSV for spreadsheet-oriented review. Select a new destination outside the evidence directory. The parent directory must already exist. For a single `$I` input, its parent directory is treated as evidence scope too.

The app uses the same exclusive report writer as the CLI: existing reports are not overwritten, symlink/reparse-point destinations are rejected, and a failed write is not left looking like a successfully completed report. Starting an export temporarily locks the in-memory selection used for that export.

**Buka laporan HTML** opens the latest saved report in the default browser when that export is HTML. **Buka lokasi laporan** opens the parent folder of the latest saved report. Both actions refer only to a report destination chosen by the user. The encoded original Windows path in an artefact is never treated as a trusted launch target.

JSON keeps the full scan records plus explicit selection and timeline objects. Filtering does not erase the audit inventory. CSV and HTML present selected records, and their protected text representation can differ from the exact strings retained in JSON. See [REPORT_SCHEMA.md](REPORT_SCHEMA.md) for field semantics and uint64 precision notes.

## Troubleshooting

| Problem | Next check |
| --- | --- |
| Tk cannot be imported or a window cannot open | Check the Python interpreter's Tk support and graphical display; use the complete portable Windows package when applicable |
| Named timezone is unavailable | Install the source `timezone` extra or use the bundled Windows package; UTC remains available |
| No artefacts found | Check input scope and the subfolder option; absence from supplied scope does not prove no deletion occurred |
| Report destination refused | Choose a new file outside evidence and check that its parent exists and does not pass through a redirect |
| Scan cancelled | Start a new run and let it complete before exporting |
| Input is inaccessible | Check the working copy and its permissions; review the displayed error rather than assuming an empty source |

## Build and validation

The Windows packaging workflow builds on Windows, includes the Tk/timezone support files, and runs the packaged executable's startup smoke check before uploading artifacts. The smoke path exercises application startup and the bundled engine; it is separate from forensic interoperability testing.

Native GUI tests, controller tests, cancellation/progress tests, the existing cross-platform suite, and [controlled Windows artefact validation](VALIDATION_WINDOWS.md) cover different behaviors. A workflow being configured is not itself evidence that a particular build passed. Use the matching successful run and its results when recording a build for use.
