# KASEVRA

**Digital Evidence & Integrity Toolkit**

*Collect with care. Verify with confidence.*

KASEVRA is an offline-first command-line toolkit for collecting selected digital evidence, recording SHA-256 hashes, comparing reference baselines, verifying collected files, and generating reports.

## Requirements

- Python 3.11 or newer
- macOS, Windows, or Linux

## Installation

Install the development version from the project directory:

```bash
python -m pip install -e ".[dev]"
```

## Commands

```bash
kasevra --help
kasevra --version
kasevra doctor
kasevra collect SOURCE DESTINATION
kasevra baseline MANIFEST OUTPUT
kasevra analyze BASELINE MANIFEST
kasevra verify COLLECTION
kasevra report COLLECTION --format json --output REPORT.json
kasevra report COLLECTION --format html --output REPORT.html
kasevra dashboard
```

## Integrity model

KASEVRA records SHA-256 hashes in collection manifests and can independently verify collected files against those recorded hashes.

A successful hash comparison establishes consistency with the recorded manifest. It does not independently prove the origin, authenticity, or chain of custody of evidence.

## Security and safety

- Collection is designed to leave source evidence unchanged.
- Collection and verification avoid following symbolic links.
- Existing outputs are protected against accidental overwriting.
- Reports disclose when analysis or verification has not been performed.
- Treat collected evidence and manifests as potentially untrusted input.
- Preserve original evidence and maintain independent chain-of-custody records where required.

## Scope limitations

KASEVRA is not a full disk-imaging or memory-forensics tool. It does not provide remediation, live network scanning, or automatic threat-intelligence services.

## Development checks

Run the test suite, lint checks, formatting check, and package build:

```bash
python -m pytest --cov=kasevra --cov-report=term
python -m ruff check .
python -m ruff format --check .
python -m build
```

## Continuous integration

The GitHub Actions workflow is configured for Ubuntu, macOS, and Windows with Python 3.11 through 3.14. Cross-platform results remain pending until the workflow has run successfully.

## Project status

KASEVRA is under development. The first intended public release is **v1.0.0**. No interim public releases are planned.
