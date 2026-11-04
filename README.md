<!--
  KASEVRA
  Digital Evidence & Integrity Toolkit
  Project documentation: https://github.com/Hritam06/kasevra
-->

<div align="center">
  <h1>KASEVRA</h1>
  <p><strong>Digital Evidence &amp; Integrity Toolkit</strong></p>
  <p><em>Collect with care. Verify with confidence.</em></p>
  <p>
    An offline-first toolkit for collecting selected digital evidence,
    recording SHA-256 hashes, comparing reference baselines, and verifying
    file integrity.
  </p>
  <p>
    <a href="https://github.com/Hritam06/kasevra/releases/tag/v1.0.0">
      <img src="https://img.shields.io/badge/release-v1.0.0-216e39" alt="Latest published release v1.0.0">
    </a>
    <a href="https://github.com/Hritam06/kasevra/actions/workflows/tests.yml">
      <img src="https://github.com/Hritam06/kasevra/actions/workflows/tests.yml/badge.svg" alt="Tests">
    </a>
    <img src="https://img.shields.io/badge/Python-3.11%2B-3776AB" alt="Python 3.11 or later">
  </p>
  <p>
    <a href="#quick-start">Quick start</a> ·
    <a href="#v1-command-line-interface">V1 CLI</a> ·
    <a href="#v2-programmatic-capabilities">V2 capabilities</a> ·
    <a href="#security-model-and-limitations">Security model</a> ·
    <a href="docs/V2_GUIDE.md">V2 guide</a>
  </p>
</div>

---

## Overview

KASEVRA is a file-level evidence collection and integrity toolkit. It helps operators acquire selected files, preserve reference hashes, verify collected content, compare collections with baselines, and produce reviewable reports.

The repository retains the published **V1.0.0** command-line workflow and contains a developing V2 Python API foundation. V2 adds a versioned manifest model, independent verification and baseline comparison, detached Ed25519 signatures, hash-linked custody events, and structured JSON/HTML reporting.

> **Scope note:** V2 interfaces are currently programmatic Python APIs. The installed CLI still exposes the V1 commands. V2 is not presented as a published release.

### What it provides

- **Evidence acquisition** — selected-file acquisition with streamed SHA-256 hashing and structured per-file outcomes.
- **Versioned manifests** — a V2 schema with canonical serialization and digest validation.
- **Integrity verification** — independent checks for matching, modified, missing, unexpected, and errored evidence.
- **Baseline comparison** — reference-based comparison with independent hashing of current evidence.
- **Digital signatures** — detached Ed25519 signatures for exact manifest bytes.
- **Chain-of-custody records** — hash-linked events with append and validation helpers.
- **Reporting** — structured JSON and self-contained HTML report generation.
- **Offline-first operation** — local workflows without a cloud service dependency.

> **Important:** A matching hash does not establish evidence authenticity or provenance. KASEVRA reports the checks performed; it does not guarantee that evidence is complete, authentic, or legally admissible.

## Quick start

### Requirements

- Python **3.11 or later**
- macOS, Windows, or Linux

### Install from source

```bash
git clone https://github.com/Hritam06/kasevra.git
cd kasevra

python -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

On Windows PowerShell, activate the environment with:

```powershell
.venv\Scripts\Activate.ps1
```

Confirm the command is available:

```bash
kasevra --help
kasevra --version
```

## V1 command-line interface

The currently exposed CLI commands are:

| Command | Purpose |
|---|---|
| `kasevra doctor` | Check the local environment and runtime. |
| `kasevra collect SOURCE DESTINATION` | Copy selected files and write a SHA-256 manifest. |
| `kasevra baseline MANIFEST OUTPUT` | Create a reference baseline. |
| `kasevra analyze BASELINE MANIFEST` | Compare manifest records with a baseline. |
| `kasevra verify COLLECTION` | Verify collected files against the SHA-256 manifest. |
| `kasevra report COLLECTION --format json --output REPORT.json` | Generate a JSON report. |
| `kasevra report COLLECTION --format html --output REPORT.html` | Generate an HTML report. |
| `kasevra dashboard` | Preview terminal UI using sample data. |

Show all options:

```bash
kasevra --help
kasevra collect --help
kasevra report --help
```

## V2 programmatic capabilities

The V2 implementation is organized as Python modules, not additional CLI subcommands.

| Capability | Module | Main interfaces |
|---|---|---|
| Acquisition | `kasevra.collectors.acquisition` | `acquire_files` |
| Manifest schema | `kasevra.schemas.manifest_v2` | `CaseRecord`, `EvidenceRecord`, `CollectionRecord`, `ManifestV2`, `create_manifest` |
| Manifest I/O | `kasevra.integrity.manifest` | `serialize_manifest`, `write_manifest`, `load_manifest` |
| Verification | `kasevra.integrity.verification` | `verify_v2_collection` |
| Baseline comparison | `kasevra.integrity.comparison` | `create_v2_baseline`, `compare_v2_baseline` |
| Key management | `kasevra.crypto.keys` | `generate_keypair`, `load_private_key`, `load_public_key` |
| Detached signatures | `kasevra.crypto.signing` | `sign_manifest`, `verify_signature` |
| Custody events | `kasevra.custody.events` | `CustodyEvent`, `create_event` |
| Custody chain | `kasevra.custody.chain` | `append_event`, `validate_chain` |
| JSON reporting | `kasevra.reporting.json_report` | `build_v2_report`, `serialize_v2_report`, `write_v2_json_report` |
| HTML reporting | `kasevra.reporting.html_report` | `render_v2_html_report`, `write_v2_html_report` |

See the [V2 Guide](docs/V2_GUIDE.md) for the data model, API responsibilities, workflow notes, and migration considerations.

## V2 manifest and integrity model

The V2 manifest identifier is `kasevra-evidence-manifest-v2`, with schema version `2.0.0`.

Canonical JSON serialization provides deterministic encoding for digest calculation. Manifest digest calculation excludes the top-level digest field itself. Duplicate JSON keys and unsupported values are rejected by the V2 manifest handling foundation.

Verification recalculates hashes for collected evidence. Outcomes distinguish `PASS`, `MODIFIED`, `MISSING`, `UNEXPECTED`, and `ERROR`.

Baseline comparison checks current evidence against a separately stored reference. Baseline creation copies the manifest's reference hashes; it does not independently rehash evidence at baseline creation time.

## Signatures and custody records

V2 uses Ed25519 through the `cryptography` dependency. Detached signatures cover the exact manifest bytes. Keep private keys outside evidence packages and establish trust in public keys independently.

Custody events are linked using event hashes and previous-event hashes. Validation can detect many modifications, deletions, or reorderings. This is tamper-evident logging, not tamper-proof storage. The log alone does not establish the identity of an operator or the truth of an event.

## Reports

V2 reporting helpers build structured reports from supplied collection and analysis information and can serialize JSON or render HTML. Report generation does not independently perform checks that were not supplied to the report builder. Review included sections and limitations before interpreting a report.

## Development and tests

Install development dependencies and run:

```bash
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
python -m build
```

The current local validation recorded for the V2 development work is **139 passing tests**, Ruff lint and formatting checks passing, a clean dependency check, and successful source distribution and wheel builds. These are local results, not a claim that every remote CI matrix job has run for the current unmerged changes.

## Security model and limitations

KASEVRA is an offline-first, file-level toolkit, not a full forensic suite.

- **Hash consistency:** a matching hash means checked bytes match the supplied reference. It does not prove origin, authenticity, or provenance.
- **Acquisition boundaries:** source handling is designed to avoid modification, but platform-specific filesystem behavior and all parent-directory race conditions cannot be eliminated.
- **Baseline trust:** protect baseline files independently from the evidence collection.
- **Signature trust:** a valid signature establishes consistency with a signing key; trust in the key and its custodian is a separate decision.
- **Custody log trust:** hash-linked events are tamper-evident, not tamper-proof.
- **Forensic scope:** KASEVRA does not perform full disk imaging, memory acquisition, packet capture, or a complete forensic examination.
- **Legal conclusions:** no feature guarantees legal admissibility or evidentiary authenticity.

Treat evidence, manifests, baselines, signatures, custody logs, and reports as potentially untrusted input. Preserve original evidence and maintain independent records where required.

## Documentation

- [V2 Guide](docs/V2_GUIDE.md)
- [Changelog](CHANGELOG.md)
- [Security Policy](SECURITY.md)
- [MIT License](LICENSE)

## License

KASEVRA is distributed under the repository's [MIT License](LICENSE).
