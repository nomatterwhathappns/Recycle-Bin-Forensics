# Independent parser comparison

`tools/compare_reference.py` runs the supplied `$I` bytes through this project and
[rifiuti2](https://abelcheung.github.io/rifiuti2/), an independently implemented
Recycle Bin parser. Each input is processed separately. The reference executable
is an external validation dependency; it is not bundled with the application.

The comparison checks format version, original path, original size, and deletion
time at **whole-second UTC precision**. rifiuti2 0.8.2 does not expose fractional
FILETIME ticks in this output. Agreement therefore cannot cross-validate RBF's
100 ns precision or distinguish the corpus's adjacent ticks. Those properties
have separate independent byte/expected-value tests.

This comparison also does not validate payload correlation, hashing, filtering,
report exports, all Windows releases, or malformed-input acceptance. See
[the synthetic dataset](DATASET.md) and [real Windows Shell validation](VALIDATION_WINDOWS.md)
for those separate test boundaries.

## Install the pinned reference on Linux x64

Parrot users can install their distribution's `rifiuti2` package and supply its
`rifiuti-vista` path. Record the actual version and executable digest: a different
package need not have the same bytes as the pinned Debian build.

The reproducible CI dependency is Debian `rifiuti2_0.8.2-1_amd64.deb`, downloaded
over HTTPS from Debian's official archive. From the repository root:

```sh
mkdir -p work/reference
curl --fail --location --output work/reference/rifiuti2.deb \
  https://deb.debian.org/debian/pool/main/r/rifiuti2/rifiuti2_0.8.2-1_amd64.deb
printf '%s  %s\n' \
  00c273928431c14ab315886964690c26fc68762f40443ea69a9de334037ae83f \
  work/reference/rifiuti2.deb | sha256sum --check
dpkg-deb --extract work/reference/rifiuti2.deb work/reference/extracted
work/reference/extracted/usr/bin/rifiuti-vista --version
```

The archive SHA-256 is
`00c273928431c14ab315886964690c26fc68762f40443ea69a9de334037ae83f`.
The extracted executable SHA-256 is
`d3e87d37d2adf99e4788261aff1ae8e5bf63c4abac2864c9ea4dd9e018507c44`.
Debian packages need compatible system libraries; this build was exercised on
Debian 13 and CI tests its selected Ubuntu host. The reference's upstream license
is BSD-3-Clause; Debian's package also includes its packaging notices.

## Run and interpret the comparison

The checked-in corpus is entirely synthetic and contains deliberately malformed
items. Run its independent oracle verification before the parser comparison:

```sh
python examples/verify_corpus.py tests/fixtures/synthetic-v1
python tools/compare_reference.py \
  --corpus tests/fixtures/synthetic-v1 \
  --reference work/reference/extracted/usr/bin/rifiuti-vista \
  --output work/reference/synthetic-reference.json
```

The output path must be new and outside the input directory. Exit status `0`
means the requested acceptance rule passed, `1` means a recorded field/ground-truth
difference, and `2` means validation could not complete. Empty comparisons,
wrong reference records, changed source bytes, and unexpected executable failures
are rejected. Source hashes, manifest hash, reference version/executable hash,
compared fields, diagnostics, environment, and all differences are retained.

The default command returns **1** for this corpus because there are two documented
differences. To explicitly accept only those narrowly defined reference behaviors:

```sh
python tools/compare_reference.py \
  --corpus tests/fixtures/synthetic-v1 \
  --reference work/reference/extracted/usr/bin/rifiuti-vista \
  --allow-known-differences \
  --output work/reference/synthetic-reference-accepted.json
```

This flag leaves every difference visible. An unexplained difference or an RBF
disagreement with the corpus's expected values still fails. The exceptions require
reference version 0.8.2 and the exact values below; they do not permit arbitrary
negative sizes, missing dates, or differences in other fields.

| Synthetic case | RBF | rifiuti2 0.8.2 | Interpretation |
| --- | --- | --- | --- |
| `max-uint64` | `18446744073709551615` | `-1` | The reference formats the maximum unsigned size through a signed 64-bit value. RBF retains the QWORD's unsigned integer. |
| `unknown-time` | Unknown (`null`), raw FILETIME `0` retained | `1601-01-01T00:00:00Z`, with suspicious-time diagnostic | The tools present the zero sentinel differently; RBF does not infer an actual deletion at the epoch. |

The reference emits an additional warning for the trailing-bytes case while its
decoded fields agree. Reference exit `5` means a record with a warning; this is
recorded separately and is never silently converted into a clean reference run.

The local v1.3.0 run on Debian 13, Python 3.12.14, using the exact executable
digest above produced:

- 12 decoded metadata records compared; 10 had matching fields.
- 2 documented reference differences; 0 unexplained or ground-truth differences.
- 2 reference-warning records (zero time and trailing bytes).
- 6 deliberately malformed metadata cases retained as diagnostics, plus 2 orphan
  cases excluded because no `$I` metadata exists.

For example, rifiuti2 emitted a record with warnings for truncated-v2-path and
invalid-UTF16 inputs that RBF rejects structurally. Those outcomes are retained
under `excluded`; they are not counted as decoded-field agreement or proof that
either parser's malformed-input policy should be adopted by the other.

## Compare acquired Windows samples

Supply individual copied `$I` files repeatedly:

```sh
python tools/compare_reference.py \
  --input 'work/acquired/$IEXAMPLE1.txt' \
  --input 'work/acquired/$IEXAMPLE2.txt' \
  --reference work/reference/extracted/usr/bin/rifiuti-vista \
  --output work/windows-reference.json
```

The controlled Windows CI test creates uniquely owned ASCII/Unicode samples,
records their known path/size/time interval and digest, and safely copies only
their own metadata for this independent comparison. Its ground-truth validation
and the Linux comparison are separate checks. Inspect the matching commit's
`reference-validation-results` artifact for `synthetic-reference.json` and
`windows-reference.json`; a workflow definition alone does not establish a pass.

The XML adapter is deliberate: rifiuti2 0.8.2's JSON output contains trailing
commas. The adapter requires one correctly identified record and parses sizes as
integers; it does not repair JSON, use floating-point sizes, or reinterpret local
time as UTC.
