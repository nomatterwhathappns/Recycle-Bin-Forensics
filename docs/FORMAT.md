# Binary format and parsing decisions

`$I` is the metadata half of a modern Windows Recycle Bin item. A matching `$R` name may contain the original file or directory. This tool parses modern format versions 1 and 2 and makes no claim to support legacy `INFO2`.

All multibyte integers described below are unsigned and **little-endian**. Byte offsets start at zero. Version is the encoded metadata format, not a reliable Windows operating-system identification.

## Common header

| Offset | Length | Meaning | Python unpacking |
| --- | --- | --- | --- |
| `0x00` | 8 bytes | Format version, `1` or `2` | `<Q` |
| `0x08` | 8 bytes | Recorded original size in bytes | `<Q` |
| `0x10` | 8 bytes | Deletion FILETIME | `<Q` |

The common header is 24 bytes. `<QQQ` means little-endian, three unsigned 64-bit values. Explicit endianness prevents host architecture from changing the interpretation.

## Version 1

| Offset | Length | Meaning |
| --- | --- | --- |
| `0x18` | 520 bytes | Fixed path field: 260 UTF-16LE code units |

The normal full record size is 544 bytes. The path is terminated by a UTF-16 NUL; remaining field bytes are padding. A short fixed field is truncated evidence, not a safely parseable complete record. The parser looks for a terminator on two-byte code-unit boundaries, not by searching for any adjacent zero bytes.

## Version 2

| Offset | Length | Meaning |
| --- | --- | --- |
| `0x18` | 4 bytes | Number of UTF-16 code units in the path field, including terminal NUL |
| `0x1c` | `length × 2` bytes | UTF-16LE path field |

The declared path must fit in the bytes supplied. A length field is untrusted input: validate it before allocating, slicing, or decoding. The implementation imposes a bounded maximum to prevent implausible lengths from being treated as normal evidence. Consult the parser for the precise accepted bound and emitted issue codes.

## Unicode matters

The encoding is UTF-16 **little-endian**, not UTF-8. A BMP character usually uses one 16-bit code unit; many emoji and other non-BMP characters use a surrogate pair, consuming two units. Therefore `len(path)` in Python is not necessarily the encoded length field. Build lengths using `len(path.encode('utf-16-le')) // 2` and account for the terminator.

Strict decoding rejects malformed surrogate sequences rather than replacing bytes with `�` and silently changing a reported path. Extra bytes, unusual path forms, and missing/embedded terminators need explicit interpretation. Read the record's warnings as well as its status.

## FILETIME conversion

Windows FILETIME counts 100-nanosecond intervals since **1601-01-01 00:00:00 UTC**. It is an integer, not a Unix timestamp.

```text
ticks_per_second = 10,000,000
whole_seconds, fraction = divmod(raw_filetime, ticks_per_second)
UTC = 1601-01-01T00:00:00Z + whole_seconds
fractional_seconds = fraction formatted as seven decimal digits
```

Integer arithmetic retains the last 100 ns digit; ordinary Python `datetime` stores only microseconds. Converting through a float can round values, while returning a naive local datetime can introduce an unstated timezone. The report retains both the raw integer and a UTC representation. Optional local-time display is a separate interpretation of the same instant.

A zero or unrepresentable timestamp is not replaced with the current time. It is surfaced as unavailable with a warning so downstream analysts can distinguish absent/anomalous values from real decoded times.

## Correlation and hashes

For an acquired file named `$IABC123.ext`, the candidate payload is a sibling `$RABC123.ext`. This is name correlation, not a cryptographic association. The decoded original path is never used to find a payload. ASCII letter case is normalized during matching, and a nonexact match adds `payload_case_insensitive_match`. Unicode casefold substitutions are deliberately avoided: characters such as `ß` must not become `ss` and falsely associate distinct acquired items. Multiple matching entries remain ambiguous; none is selected.

Metadata SHA-256 fingerprints the bytes actually read, including bytes that do not successfully parse. Optional payload hashing is limited to safe regular files and is reported separately. File and directory availability do not imply that a payload has the recorded original size or has remained unchanged.

## Boundaries of this implementation

- Malformed records yield per-file errors; later candidates can still be examined.
- Unsupported versions are not guessed from their apparent size.
- Decoded original paths are data, never commands or local destinations.
- Forensic findings require external validation and case context.
- Synthetic unit tests exercise implementation logic; independent Windows acquisitions are still needed for interoperability validation.

## References

- Microsoft: [FILETIME structure](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime).
- Microsoft: [System time](https://learn.microsoft.com/en-us/windows/win32/sysinfo/system-time).
- Python: [`struct` binary data formats](https://docs.python.org/3/library/struct.html).
- Python: [Unicode HOWTO](https://docs.python.org/3/howto/unicode.html).
- Python: [`zoneinfo` and timezone data availability](https://docs.python.org/3/library/zoneinfo.html).

Microsoft's FILETIME documentation describes the timestamp primitive, not an authoritative specification for every `$I` record layout. The exact parser assumptions are documented here and in `parser.py` so they can be checked against independently acquired samples.
