"""Generate JSON and HTML reports from KASEVRA evidence collections."""

import html
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from kasevra.core.results import OperationResult, ResultStatus
from kasevra.exceptions import IntegrityError, OperationError, SafetyError

MANIFEST_NAME = "manifest.json"
SUPPORTED_FORMATS = {"json", "html"}


def _load_manifest(collection: Path) -> dict:
    """Load and validate a collection manifest."""
    collection = Path(os.path.abspath(collection.expanduser()))

    if collection.is_symlink():
        raise SafetyError("Collection path must not be a symbolic link.")
    if not collection.is_dir():
        raise OperationError("Collection directory does not exist.")

    manifest_path = collection / MANIFEST_NAME
    if manifest_path.is_symlink():
        raise SafetyError("Collection manifest must not be a symbolic link.")
    if not manifest_path.is_file():
        raise OperationError("Collection manifest.json was not found.")

    try:
        with manifest_path.open("r", encoding="utf-8") as stream:
            manifest = json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise IntegrityError("Collection manifest could not be read.") from exc

    if not isinstance(manifest, dict):
        raise IntegrityError("Manifest must contain a JSON object.")
    if manifest.get("format") != "kasevra-evidence-manifest-v1":
        raise IntegrityError("Unsupported collection manifest format.")

    entries = manifest.get("entries")
    errors = manifest.get("errors", [])

    if not isinstance(entries, list) or not isinstance(errors, list):
        raise IntegrityError("Manifest entries or errors have an invalid format.")
    if manifest.get("collected_file_count") != len(entries):
        raise IntegrityError("Manifest file count does not match its entries.")

    for entry in entries:
        if not isinstance(entry, dict):
            raise IntegrityError("Manifest contains an invalid file entry.")

        relative_path = entry.get("collected_path")
        size_bytes = entry.get("size_bytes")
        sha256 = entry.get("sha256")

        if not isinstance(relative_path, str) or not relative_path:
            raise IntegrityError("Manifest contains an invalid collected path.")

        relative = Path(relative_path)
        if relative.is_absolute() or ".." in relative.parts:
            raise IntegrityError("Manifest contains an unsafe collected path.")
        if not isinstance(size_bytes, int) or isinstance(size_bytes, bool):
            raise IntegrityError("Manifest contains an invalid file size.")
        if size_bytes < 0:
            raise IntegrityError("Manifest contains a negative file size.")
        if (
            not isinstance(sha256, str)
            or len(sha256) != 64
            or any(char not in "0123456789abcdefABCDEF" for char in sha256)
        ):
            raise IntegrityError("Manifest contains an invalid SHA-256 value.")

    if not all(isinstance(error, str) for error in errors):
        raise IntegrityError("Manifest contains an invalid warning.")

    return manifest


def _build_report(collection: Path, manifest: dict) -> dict:
    """Build report data without modifying evidence."""
    return {
        "report_format": "kasevra-report-v1",
        "generated_utc": datetime.now(UTC).isoformat(),
        "collection": {
            "path": str(collection),
            "source": manifest.get("source"),
            "created_utc": manifest.get("created_utc"),
            "hash_algorithm": manifest.get("hash_algorithm"),
            "file_count": manifest["collected_file_count"],
        },
        "files": [
            {
                "path": entry["collected_path"],
                "size_bytes": entry["size_bytes"],
                "sha256": entry["sha256"],
            }
            for entry in manifest["entries"]
        ],
        "collection_warnings": manifest.get("errors", []),
        "analysis": {
            "status": "not_included",
            "message": "Analysis findings were not supplied to this report.",
        },
        "verification": {
            "status": "not_included",
            "message": "Verification findings were not supplied to this report.",
        },
        "limitations": manifest.get("limitations", []),
        "integrity_notice": (
            "Manifest hashes record collection-time byte content. "
            "This report does not independently verify evidence files "
            "or prove evidence authenticity."
        ),
    }


def _render_html(report: dict) -> str:
    """Render a self-contained HTML report with escaped untrusted content."""

    def safe(value: object) -> str:
        return html.escape(str(value), quote=True)

    collection = report["collection"]
    rows = (
        "\n".join(
            "<tr>"
            f"<td>{safe(item['path'])}</td>"
            f"<td>{item['size_bytes']}</td>"
            f"<td><code>{safe(item['sha256'])}</code></td>"
            "</tr>"
            for item in report["files"]
        )
        or '<tr><td colspan="3">No files recorded.</td></tr>'
    )

    warnings = (
        "\n".join(f"<li>{safe(item)}</li>" for item in report["collection_warnings"])
        or "<li>None recorded.</li>"
    )

    limitations = (
        "\n".join(f"<li>{safe(item)}</li>" for item in report["limitations"])
        or "<li>No limitations supplied in the manifest.</li>"
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>KASEVRA Evidence Report</title>
<style>
:root {{
 color-scheme: dark;
 font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
 background: #101719;
 color: #e6eeee;
}}
body {{ max-width: 1100px; margin: 0 auto; padding: 32px 20px; line-height: 1.6; }}
header {{ border-bottom: 2px solid #35e0c1; padding-bottom: 20px; }}
h1, h2 {{ color: #35e0c1; }}
.panel {{ background: #192326; border: 1px solid #304448;
 border-radius: 10px; padding: 20px; margin: 20px 0;
 overflow-wrap: anywhere; }}
table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
th, td {{ text-align: left; padding: 10px;
 border-bottom: 1px solid #304448; vertical-align: top; }}
th {{ color: #35e0c1; }}
code {{ overflow-wrap: anywhere; }}
.notice {{ border-left: 4px solid #e5b85c; padding: 12px 16px; background: #29271e; }}
.status {{ color: #e5b85c; font-weight: bold; }}
footer {{ color: #91a3a5; border-top: 1px solid #304448;
 margin-top: 32px; padding-top: 16px; }}
@media (max-width: 650px) {{
 body {{ padding: 18px 12px; }}
 table {{ font-size: 0.78rem; }}
 th, td {{ padding: 7px 5px; }}
}}
</style>
</head>
<body>
<header>
<h1>KASEVRA</h1>
<div>Digital Evidence &amp; Integrity Toolkit</div>
<div>Collect with care. Verify with confidence.</div>
</header>
<section class="panel">
<h2>Collection summary</h2>
<p><strong>Collection path:</strong> {safe(collection["path"])}</p>
<p><strong>Source:</strong> {safe(collection.get("source"))}</p>
<p><strong>Created (UTC):</strong> {safe(collection.get("created_utc"))}</p>
<p><strong>Report generated (UTC):</strong> {safe(report["generated_utc"])}</p>
<p><strong>Files recorded:</strong> {collection["file_count"]}</p>
<p><strong>Hash algorithm:</strong> {safe(collection.get("hash_algorithm"))}</p>
</section>
<section class="panel">
<h2>Evidence inventory</h2>
<table><thead><tr>
<th>Collected path</th><th>Size (bytes)</th><th>SHA-256</th>
</tr></thead>
<tbody>{rows}</tbody></table>
</section>
<section class="panel"><h2>Collection warnings</h2><ul>{warnings}</ul></section>
<section class="panel">
<h2>Analysis and verification</h2>
<p><span class="status">Analysis: NOT INCLUDED</span></p>
<p>{safe(report["analysis"]["message"])}</p>
<p><span class="status">Verification: NOT INCLUDED</span></p>
<p>{safe(report["verification"]["message"])}</p>
</section>
<section class="panel">
<h2>Integrity limitations</h2>
<ul>{limitations}</ul>
<p class="notice">{safe(report["integrity_notice"])}</p>
</section>
<footer>Generated by KASEVRA. This report does not independently
establish evidence authenticity.</footer>
</body>
</html>
"""


def _write_report(output: Path, content: str) -> None:
    """Write atomically without overwriting an existing path."""
    output = Path(os.path.abspath(output.expanduser()))

    if output.is_symlink():
        raise SafetyError("Report output must not be a symbolic link.")
    if output.exists():
        raise SafetyError("Report output already exists; refusing to overwrite it.")
    if not output.parent.is_dir():
        raise OperationError("Report output directory does not exist.")

    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=output.parent,
            prefix=".kasevra-report-",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
            stream.write(content)
            stream.write("\n")

        os.link(temporary_path, output)
    except FileExistsError as exc:
        raise SafetyError(
            "Report output already exists; refusing to overwrite it."
        ) from exc
    except OSError as exc:
        raise OperationError("Report could not be written safely.") from exc
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def generate_report(
    collection: Path,
    output: Path,
    report_format: str = "json",
) -> OperationResult:
    """Generate a JSON or HTML report from a collection manifest."""
    report_format = report_format.lower()
    if report_format not in SUPPORTED_FORMATS:
        raise SafetyError("Report format must be either 'json' or 'html'.")

    collection = Path(os.path.abspath(collection.expanduser()))
    output = Path(os.path.abspath(output.expanduser()))

    if output == collection / MANIFEST_NAME:
        raise SafetyError("Report output cannot replace the collection manifest.")
    if output == collection or collection in output.parents:
        raise SafetyError("Report output must be outside the evidence collection.")

    manifest = _load_manifest(collection)
    report = _build_report(collection, manifest)

    content = (
        json.dumps(report, indent=2, ensure_ascii=False)
        if report_format == "json"
        else _render_html(report)
    )
    _write_report(output, content)

    return OperationResult(
        name="Report",
        status=ResultStatus.SUCCESS,
        message=f"{report_format.upper()} report generated successfully.",
        details={
            "format": report_format,
            "output": str(output),
            "files_reported": len(report["files"]),
            "collection_warnings": len(report["collection_warnings"]),
            "analysis_included": False,
            "verification_included": False,
        },
    )
