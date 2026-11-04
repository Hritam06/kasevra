# KASEVRA V2 Guide

## Status

This guide describes the V2 programmatic interfaces present in the repository. Package metadata and the published release remain at version 1.0.0. V2 functionality is not currently exposed as additional CLI commands.

V2 extends the existing file-level evidence workflow while retaining the V1 command-line interface.

## Architecture

V2 functionality is organized into focused Python modules:

- `collectors.acquisition`: selected-file acquisition.
- `schemas.manifest_v2`: typed V2 case, evidence, and collection records.
- `integrity`: canonical serialization, hashing, manifest handling, verification, and comparison.
- `crypto`: Ed25519 key handling and detached manifest signatures.
- `custody`: event creation, append-only event logging, and chain validation.
- `reporting`: structured JSON and HTML report generation.

## V2 manifest

The V2 manifest identifier is `kasevra-evidence-manifest-v2`; its schema version is `2.0.0`.

The schema defines case, evidence, and collection records. Evidence acquisition statuses include `collected`, `skipped`, and `failed`. Collection statuses include `complete`, `partial`, and `failed`.

Canonical JSON serialization uses deterministic key ordering and compact encoding. Manifest digest calculation excludes the top-level digest field itself. Floating-point values are rejected by the canonical JSON foundation.

Use `kasevra.schemas.manifest_v2` to work with the data model and `kasevra.integrity.manifest` to serialize, write, and load manifests. The loader validates the V2 structure and digest and rejects duplicate JSON keys.

## Evidence acquisition

The acquisition interface is `acquire_files` in `kasevra.collectors.acquisition`.

The implementation is designed to collect selected regular files into a new destination, stream file content while calculating SHA-256, apply a configurable file-size limit, avoid following final-component symbolic links, detect some source changes during acquisition, record unsuccessful acquisition outcomes, and refuse to overwrite an existing destination.

Acquisition is not a full disk image. Parent-directory races and platform-specific filesystem behavior remain relevant limitations. Preserve original source material and independently protect acquired evidence.

## Independent verification

Use `verify_v2_collection` from `kasevra.integrity.verification`.

Verification checks the collection manifest and recalculates hashes for evidence files. Results distinguish:

- `PASS`: current file content matches the recorded reference.
- `MODIFIED`: current content or size differs.
- `MISSING`: expected evidence is absent.
- `UNEXPECTED`: an unlisted item is present.
- `ERROR`: a check could not be completed safely.

A successful result is limited to the files and checks actually examined. It does not prove provenance, authenticity, completeness, or legal admissibility.

## Baseline comparison

Use `create_v2_baseline` and `compare_v2_baseline` from `kasevra.integrity.comparison`.

A baseline records reference evidence identifiers, paths, sizes, and hashes. Baseline creation copies reference hashes from the manifest; it does not independently rehash evidence at that time.

Comparison validates the baseline and current manifest, then independently hashes current evidence files. Results can include `PASS`, `MODIFIED`, `MISSING`, `ADDED`, `REMOVED`, `ERROR`, and `UNEXPECTED`.

Protect baselines independently. A baseline is a comparison reference, not proof that the original evidence was trustworthy.

## Digital signatures

The signature implementation uses Ed25519 through the `cryptography` dependency.

Key interfaces are in `kasevra.crypto.keys`:

- `generate_keypair`
- `load_private_key`
- `load_public_key`

Detached signing and verification interfaces are in `kasevra.crypto.signing`:

- `sign_manifest`
- `verify_signature`

Signatures cover the exact manifest bytes. Keep private keys separate from evidence collections and protect them with appropriate access controls. A valid signature confirms consistency with the corresponding signing key; trust in the key and its operator must be established separately.

## Chain of custody

Create events using `create_event` from `kasevra.custody.events`. Append and validate events using `append_event` and `validate_chain` from `kasevra.custody.chain`.

Events include identifiers, timestamps, action and operator information, details, a previous-event hash, and an event hash. The first event links to the defined genesis hash. Validation checks the hash linkage and event integrity.

The log is append-oriented and detects many forms of modification, deletion, or reordering. It is not tamper-proof. Access to the log and its storage must be controlled independently. The log alone does not prove the identity of an operator or the truth of an event.

## Reporting

V2 report interfaces are in `kasevra.reporting`:

- `build_v2_report` assembles supplied collection and analysis information.
- `serialize_v2_report` produces deterministic JSON text.
- `write_v2_json_report` writes a JSON report.
- `render_v2_html_report` renders an HTML report.
- `write_v2_html_report` writes an HTML report.

Reports can include verification, comparison, signature, and custody information when supplied. A report does not independently perform checks that were not provided to the report builder. Review included sections and limitations before interpreting a report.

## V1 compatibility and migration

The existing V1 CLI commands remain the supported command-line workflow:

- `collect`
- `baseline`
- `analyze`
- `verify`
- `report`
- `doctor`
- `dashboard`

V2 introduces a separate versioned manifest format and programmatic interfaces. Do not assume a V1 manifest is a V2 manifest or pass one to a V2-only loader. Preserve original V1 collections and manifests. Use the V2 schema and serialization functions when creating V2 manifests.

No automatic migration of existing V1 evidence collections is documented here. Retain V1 records as they are and validate any future migration procedure against copies before using it with important evidence.

## Security limitations

KASEVRA is designed for offline, file-level evidence handling. It does not eliminate all filesystem race conditions, guarantee secure behavior against every local adversary, or replace operating-system access controls.

- Hashes identify byte-level consistency with a reference; they do not establish authenticity.
- Signatures depend on private-key security and independent public-key trust.
- Hash-linked custody records are tamper-evident, not tamper-proof.
- Baselines must be protected independently.
- Verification and comparison describe the checks completed and may report errors or limitations.
- No feature guarantees legal admissibility or a complete forensic examination.

For vulnerability reporting, follow [SECURITY.md](../SECURITY.md).
