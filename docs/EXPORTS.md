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
