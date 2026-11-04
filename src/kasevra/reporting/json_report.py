"""Deterministic JSON report construction and safe output."""

import json
import os
import tempfile
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from kasevra.exceptions import OperationError, SafetyError
from kasevra.reporting.summary import build_summary

REPORT_FORMAT = "kasevra-report-v2"


def _validate_json_value(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        raise ValueError(f"Floating-point values are not permitted at {path}.")
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"Report object keys must be strings at {path}.")
            _validate_json_value(item, f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _validate_json_value(item, f"{path}[{index}]")
        return
    raise ValueError(f"Unsupported report value at {path}: {type(value).__name__}.")


def build_v2_report(
    manifest: Mapping[str, Any],
    *,
    verification: Mapping[str, Any] | None = None,
    comparison: Mapping[str, Any] | None = None,
    signature: Mapping[str, Any] | None = None,
    custody: Mapping[str, Any] | None = None,
    generated_utc: str | None = None,
) -> dict[str, Any]:
    """Build a report from supplied results; never perform or infer checks."""
    if not isinstance(manifest, Mapping):
        raise ValueError("Manifest must be a mapping.")

    sections = {
        "verification": verification,
        "comparison": comparison,
        "signature": signature,
        "custody": custody,
    }
    report = {
        "report_format": REPORT_FORMAT,
        "generated_utc": generated_utc
        or datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "collection": dict(manifest),
        **sections,
        "summary": build_summary(sections),
        "integrity_notice": (
            "This report presents supplied records and results. "
            "A matching hash alone does not establish evidence authenticity, "
            "and a report does not prove legal admissibility."
        ),
    }
    _validate_json_value(report)
    return report


def serialize_v2_report(report: Mapping[str, Any]) -> str:
    """Serialize a report as stable, strict UTF-8-compatible JSON."""
    if not isinstance(report, Mapping) or report.get("report_format") != REPORT_FORMAT:
        raise ValueError("Unsupported V2 report object.")
    _validate_json_value(report)
    return (
        json.dumps(
            report,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        )
        + "\n"
    )


def write_v2_json_report(report: Mapping[str, Any], output: Path) -> Path:
    """Create a JSON report without replacing an existing destination."""
    output = Path(os.path.abspath(Path(output).expanduser()))
    if output.is_symlink():
        raise SafetyError("Report output must not be a symbolic link.")
    if output.exists():
        raise SafetyError("Report output already exists; refusing to overwrite it.")
    if not output.parent.is_dir():
        raise OperationError("Report output directory does not exist.")

    content = serialize_v2_report(report)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=output.parent,
            prefix=".kasevra-v2-report-",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary_path, output)
    except FileExistsError as exc:
        raise SafetyError(
            "Report output already exists; refusing to overwrite it."
        ) from exc
    except OSError as exc:
        raise OperationError("V2 JSON report could not be written safely.") from exc
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    return output
