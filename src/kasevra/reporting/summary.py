"""Build concise, truthful summaries for V2 reports."""

from collections import Counter
from collections.abc import Mapping
from typing import Any


def build_summary(sections: Mapping[str, Any]) -> dict[str, Any]:
    """Summarize supplied section statuses without inferring omitted checks."""
    statuses: Counter[str] = Counter()
    included = []
    omitted = []

    for name in ("verification", "comparison", "signature", "custody"):
        section = sections.get(name)
        if section is None:
            omitted.append(name)
            continue
        included.append(name)
        if isinstance(section, Mapping):
            status = section.get("status")
            if isinstance(status, str):
                statuses[status.upper()] += 1

    return {
        "included_sections": included,
        "not_included_sections": omitted,
        "section_status_counts": dict(sorted(statuses.items())),
    }
