# Security Policy

## Supported Versions

Security fixes are provided for the latest published stable release of KASEVRA.

| Version | Security support |
| --- | --- |
| KASEVRA V2.0.0 (latest stable release) | Supported |
| Earlier releases | Not guaranteed |

Users are encouraged to upgrade to the latest stable release before reporting a vulnerability, where practical.

## Reporting a Vulnerability

Please do not disclose suspected security vulnerabilities through public GitHub issues, discussions, pull requests, or other public channels.

Use GitHub's Private vulnerability reporting feature for the KASEVRA repository when it is enabled.

To submit a report:

1. Open the KASEVRA GitHub repository.
2. Navigate to the Security tab.
3. Open the Advisories or private vulnerability reporting section.
4. Select Report a vulnerability and submit the report privately.

If private vulnerability reporting is unavailable, use a private communication channel listed on the repository maintainer's GitHub profile. Do not publish vulnerability details while seeking a reporting contact.

## What to Include

Please include as much of the following information as you can safely provide:

- A concise description of the suspected vulnerability.
- The affected KASEVRA release, version, or commit.
- The Python version and operating environment, if relevant.
- The affected API, CLI workflow, or component.
- Clear steps to reproduce the issue.
- The potential security impact.
- Relevant logs, error messages, or proof-of-concept material.

Before submitting, remove passwords, API keys, tokens, private keys, personal information, confidential evidence, and other sensitive material.

## Scope

This policy covers security issues in KASEVRA's maintained source code, Python API, retained V1 command-line interface, evidence acquisition and processing workflows, manifest handling, integrity verification, baseline comparison, cryptographic key management and signing, chain-of-custody records, reporting, packaging, and project-maintained integrations.

Examples of relevant reports include:

- Unsafe handling of malformed, specially crafted, or symbolic-link-based input files.
- Path traversal, unintended file access, or insecure file handling.
- Improper validation or serialization of evidence manifests.
- Incorrect integrity verification or digest validation caused by implementation flaws.
- Insecure cryptographic key handling or signature verification.
- Tampering with or improper validation of chain-of-custody records.
- Exposure of sensitive information through logs, errors, or generated reports.
- Unexpected command or code execution through KASEVRA workflows.
- Vulnerabilities in dependencies as they affect KASEVRA.

KASEVRA is an offline-first, file-level evidence integrity and chain-of-custody toolkit. Its hashes, signatures, manifests, and custody records do not independently prove evidence authenticity, provenance, completeness, or legal admissibility.

This policy does not imply that every third-party dependency, operating system, or external service is maintained by the KASEVRA project.

## Response and Disclosure

Reports will be reviewed as maintainer availability permits. The maintainer may request additional information to reproduce and assess a reported issue.

Confirmed vulnerabilities will be evaluated and addressed as appropriate. Please allow a reasonable opportunity for investigation and remediation before publicly disclosing vulnerability details.

No fixed acknowledgement, response, resolution, or remediation timeframe is guaranteed.
