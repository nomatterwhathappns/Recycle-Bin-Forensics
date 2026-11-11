# Security policy

## Supported version

Security fixes are developed on `main` for the current 0.1.x series. The project
is an initial release; no service-level or response-time guarantee is provided.

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

Exports can contain sensitive paths and metadata. Treat CSV and JSON reports
according to the same access and retention policies as the case evidence.
