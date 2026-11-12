# Releases and reproducibility

Official packages are published at [GitHub Releases](https://github.com/nomatterwhathappns/Recycle-Bin-Forensics/releases). Select an explicit version when recording an examination environment; the `latest` link can change.

## Assets

- `RecycleBinForensics-VERSION-windows-x64.zip`: the complete portable Windows application, including Python/Tcl/Tk and timezone data. Extract the entire folder.
- `rbinforensics-VERSION-py3-none-any.whl`: the Python package. Source installations still need Python 3.10+ and matching Tk support for the GUI.
- `rbinforensics-VERSION.tar.gz`: source distribution, including tools, tests, documentation, and the synthetic corpus.
- A versioned synthetic corpus ZIP: fictitious artefacts plus their expected manifest. This is demonstration data, not a Windows acquisition.
- JSON validation and benchmark reports: recorded observations with their tool versions, environment, scope, and limitations.
- `SHA256SUMS.txt`: digests of the release assets. It detects different downloaded bytes; it is not publisher code signing.

Use the exact filenames listed on the selected release. Development Actions artifacts expire and are separate from these published release assets.

## Verify downloads

Download the checksum file and the assets you need into a new directory. On Linux:

```sh
sha256sum --ignore-missing -c SHA256SUMS.txt
```

On Windows, use `Get-FileHash -Algorithm SHA256 PATH` and compare its value with the matching filename in `SHA256SUMS.txt`. Do not treat a checksum for a different version or a different ZIP wrapper as a match.

The Windows application's `BUILD-INFO.json` records its package version, source commit, build tools, and executable smoke result. The portable ZIP is also extracted to a separate location and executed during the Windows build before publication.

## Publication gates

The [release workflow](../.github/workflows/release.yml) accepts a `vMAJOR.MINOR.PATCH` tag that matches the application version. It requires the complete reusable CI workflow and native Windows packaging workflow to pass. That includes independently comparing both the synthetic corpus and the controlled Windows Shell samples with the pinned reference parser. Documented reference limitations remain visible in those reports; unexplained differences fail validation.

The assembler validates package identity, commit, Windows smoke checks, archive contents, and the synthetic corpus before writing a new staging directory. Publication creates a draft, uploads its assets, downloads them again, verifies their checksums, and publishes the draft only after verification. Existing releases and assets are not overwritten automatically. A failed publication can leave a draft for diagnosis; inspect it before deciding how to recover.

Benchmark timings are measurements on the recorded host and workload, rather than a release speed requirement or a promise about another machine. A benchmark's source commit can precede the release commit that adds its report; the report records its measured source state explicitly. See [benchmark methodology](BENCHMARKS.md), [dataset interpretation](DATASET.md), and [reference validation](VALIDATION_REFERENCE.md).
