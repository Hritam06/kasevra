# Changelog

All notable changes to KASEVRA will be documented here.

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
- Cross-platform CI workflow for Ubuntu, macOS, and Windows with Python 3.11 through 3.14.
