# Export integrity

A file export creates two new files outside the evidence tree:

- The report in JSON, CSV, HTML, or terminal-table format.
- `<report-filename>.manifest.json`, the completion receipt and integrity context.

Standard output has no sidecar. Keep the saved pair together. Existing report or manifest paths are refused; choose a new name rather than deleting an earlier case export.

The manifest contract is separate from forensic JSON schema 2.0. It records the exact UTF-8 report size and SHA-256, application version, export time, original scan context, inventory and selection counts, filters, timezone, case/examiner fields, and runtime limits. A filtered JSON still contains the complete inventory; CSV, HTML, and table output display the selection.

```sh
rbf scan /cases/collected --recursive --format csv --output /reports/triage.csv
rbf verify-export /reports/triage.csv
```

Successful verification exits 0. A missing, invalid, oversized, or mismatched manifest/report exits 2. Verification opens the explicitly selected report and its sibling manifest; paths described as evidence in the manifest are never opened. Copying the pair under a different report basename requires a new export because its basename is part of the contract.

The report-size budget applies to report bytes. The manifest is bounded separately to 1 MiB. Both files must finish writing and syncing before export succeeds; failure cleans up files still owned by that operation. A desktop JSON save is acknowledged only after both succeed. Two files cannot be committed atomically as one filesystem object: interruption or power loss may leave an incomplete pair. A missing manifest is never treated as a verified export.

SHA-256 checks byte integrity against a trusted manifest. It is not a digital signature: an actor able to replace both files can recompute the hash. Store trusted checksums and case records separately when authenticity or chain of custody matters. The manifest contains sensitive context like the report; apply the same access controls to both.

## Private files and sharing derivatives

On POSIX systems, every newly created report and manifest starts with mode `0600` (owner read/write), regardless of a permissive umask. The output directory must already exist; its permissions and storage policies remain the operator's responsibility. Windows inherits the destination directory's ACL; the application does not set or certify a private Windows ACL. Use an appropriately restricted case folder.

Ordinary exports preserve identifiers. To create a separate sharing derivative:

```sh
rbf scan /cases/collected --recursive --format html --redact --output /reports/recycle-bin-sharing.html
rbf verify-export /reports/recycle-bin-sharing.html
```

In the desktop, each **Ekspor** menu offers an ordinary report or **Salinan tersamarkan untuk dibagikan**. The latter replaces acquired/original paths, filenames, SID groups, and extension groups with consistent aliases; withholds case/examiner labels, identifying filter text, free-text diagnostics, and original evidence hashes; and omits unknown fields. The paired manifest uses only the derivative's context. Selected indexes and quantitative facts remain unchanged. Times, sizes, statuses, and diagnostic codes are retained for useful discussion. Aliases apply within one export; no reverse mapping is included.

A sharing JSON uses `schema_version: "sharing-1.0"` and `report_kind: "redacted-sharing"`, rather than claiming forensic schema 2.0. CSV adds a `redacted_sharing_report_kind` column (also visible when there are no selected records); table and HTML include visible sharing labels. The original in-memory analysis is unchanged. A sharing JSON does not acknowledge saving the complete original analysis; **Simpan JSON** in the unsaved-analysis dialog always saves the ordinary full inventory.

This is identifier reduction, not guaranteed anonymity. Review retained times/sizes and the chosen destination filename before sharing. The manifest intentionally records that filename. Do not put a person's name or case identifier in it. Export a complete ordinary JSON privately before using a derivative for a portfolio example or technical discussion.
