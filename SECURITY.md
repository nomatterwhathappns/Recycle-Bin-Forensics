# Security policy

## Supported version

Security fixes are developed on `main` for the current **1.7.x** release line.
Use the latest published patch in that line. Older lines, including 1.6.x and
1.3.x, do not receive promised backports; upgrade to the current release.
Unreleased commits on `main` can be ahead of the latest published package.

This is a community project with no service-level or response-time guarantee.
The repository's [Releases](https://github.com/nomatterwhathappns/Recycle-Bin-Forensics/releases)
identify published versions; a green CI result describes those tested checks,
not a security certification.

## Reporting a vulnerability

If private vulnerability reporting is enabled for this repository, use
**Security → Advisories → Report a vulnerability** on GitHub:

<https://github.com/nomatterwhathappns/Recycle-Bin-Forensics/security/advisories/new>

If that option is unavailable, open a minimal public issue asking the maintainer
to establish a private reporting channel. Omit exploit details, sensitive files,
and case data from that initial issue. Do not invent a contact address or send
credentials through a public issue.

A useful private report includes the affected version, platform, impact,
reproduction steps using synthetic data, and a proposed mitigation if known.

## Processing untrusted evidence

Recycle Bin artefacts and file names are untrusted inputs. Metadata paths are
evidence strings, not destinations to open or restore. Do not execute recovered
files, or import untrusted Python code, while investigating a case.

Run analysis against an authorized working copy in a controlled environment.
Keep reports outside the evidence tree. The tool does not provide forensic
acquisition, write blocking, malware isolation, or a chain-of-custody system.
Ordinary reads can affect access times on some mounted file systems. Use suitable
read-only mounts and acquisition procedures when preservation matters.

Ordinary exports and their SHA-256 manifests contain sensitive paths and case
metadata. Keep them under the same access and retention policies as evidence.
New POSIX report/manifest files use owner-only creation permissions; Windows
inherits the destination directory's ACL. Restrict the destination folder using
the host's access controls. The application does not establish a private Windows
ACL or provide protection from a compromised analysis host.

Explicit sharing derivatives reduce identifiers and omit evidence hashes, but
retain times, sizes, statuses, and a chosen export basename. Review them before
sharing; they are not guaranteed anonymous and do not replace full forensic
JSON. SHA-256 verification detects changes relative to a trusted manifest and is
not a publisher signature or proof of case authenticity.

Configurable workload limits provide bounded operations with cooperative
deadlines. They are not hard RAM limits or a substitute for process/host
isolation when handling hostile acquisitions. See [limits](docs/LIMITS.md) and
[export policy](docs/EXPORTS.md).
