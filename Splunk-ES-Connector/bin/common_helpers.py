"""Small pure-function helpers shared across normalizer, mapper, and search modules."""

from __future__ import annotations

from typing import Any


def to_list(value: Any) -> list[str]:
    """Normalize scalar/list values to a list of non-empty strings."""
    if value is None or value == "":
        return []

    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item or "").strip()]

    return [str(value).strip()]


def consolidated_findings(investigation: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Return consolidated_findings as a list of dictionaries."""
    if not investigation:
        return []

    cf = investigation.get("consolidated_findings")

    if isinstance(cf, dict):
        return [cf]

    if isinstance(cf, list):
        return [item for item in cf if isinstance(item, dict)]

    return []
