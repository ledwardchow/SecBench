# SecBench

SecBench is a cross-platform desktop application (Windows / macOS / Linux) that authenticates to an Azure tenant and a Microsoft 365 organization and runs the following CIS Benchmarks,
producing HTML, JSON, CSV, and PDF reports:

- Microsoft Azure Compute Services (2.0.0)
- Microsoft Azure Database Services (2.0.0)
- Microsoft Azure Foundations (6.0.0)
- Microsoft Azure Storage Services (1.0.0)
- Microsoft 365 Foundations (6.0.1)

> SecBench is an independent, informational tool. It is **not** affiliated with,
> sponsored by, or endorsed by the Center for Internet Security (CIS). Authoritative
> control text and audit guidance live in the official CIS Benchmark PDFs at
> <https://www.cisecurity.org/cis-benchmarks/>. Use this tool as an aid; do not treat
> its output as a certified attestation.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
secbench-gui                        # launch the desktop UI
secbench --list                     # CLI: list benchmarks
```

## Authentication

The Connect screen lets you choose:

1. **Interactive browser** sign-in (recommended for desktop use).
2. **Device code** flow (useful over SSH / headless).
3. **Service principal** (client ID + secret or certificate).

Required minimum permissions:

- Azure: `Reader` on every subscription you want to evaluate, plus
  `Security Reader` for Defender for Cloud controls.
- Microsoft Graph: `Directory.Read.All`, `Policy.Read.All`,
  `Reports.Read.All`, `SecurityEvents.Read.All`,
  `RoleManagement.Read.Directory`, `Application.Read.All`,
  `AuditLog.Read.All`.

## Reports

After a run completes, use the Reports page to export:

- Interactive **HTML** (Jinja2-rendered, self-contained).
- Machine-readable **JSON**.
- Flat **CSV** (one row per control).
- **PDF** (rendered via WeasyPrint where available, falling back to ReportLab).

## Packaging

See `packaging/` for OS-specific PyInstaller scripts:

```bash
bash packaging/build_macos.sh
powershell packaging/build_windows.ps1
bash packaging/build_linux.sh
```

## Disclaimer

The CIS Benchmark trademarks are property of the Center for Internet Security.
Sec-Benchmarks reproduces only short, factual references to control identifiers
and section titles; full audit/remediation prose remains under CIS copyright and
is intentionally summarized rather than verbatim. Always consult the official
benchmark documents for authoritative guidance.
