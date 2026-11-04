# Changelog

All notable changes to KASEVRA will be documented here.

## Unreleased

### V2 development

- Added a V2 evidence manifest schema with canonical serialization and digest validation.
- Added programmatic evidence acquisition with streamed SHA-256 hashing and structured outcomes.
- Added independent V2 collection verification and enhanced baseline comparison.
- Added Ed25519 key management and detached manifest signatures.
- Added hash-linked chain-of-custody event logging and validation.
- Added structured JSON and HTML reporting.
- Added validation and hardening for manifests, baselines, keys, signatures, and custody events.
- Added automated V2 unit and security-hardening tests.

### Documentation

- Added a V2 programmatic API guide.
- Clarified the distinction between the existing V1 CLI and V2 Python interfaces.

## v1.0.0

Initial public release.

### Features

- Evidence collection with SHA-256 manifest generation.
- Reference baseline creation.
- Collection analysis against recorded baseline data.
- Independent file integrity verification.
- JSON and HTML report generation.
- Terminal health checks and sample dashboard preview.
- Offline-first operation and read-only evidence handling.

### Security

- Symbolic-link handling designed to avoid following links.
- Output overwrite protection.
- Manifest and path validation.
- Explicit reporting of warnings and incomplete verification states.

### Documentation

- Installation, usage, integrity model, security, and scope documentation.
- Cross-platform CI workflow configuration for Ubuntu, macOS, and Windows with Python 3.11 through 3.14.
