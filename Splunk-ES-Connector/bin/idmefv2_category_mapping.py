"""IDMEFv2 category mapping.

This module maps Splunk ES correlation search names to IDMEFv2 V08
Category values using the static CSV stored in:

    lookups/idmefv2_category_mapping.csv

The mapping file is treated as the source of truth for category assignment.
"""

from __future__ import annotations

import csv
import logging
from dataclasses import dataclass, replace
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple

logger = logging.getLogger(__name__)

DEFAULT_CATEGORY = "Other.Undetermined"


@dataclass(frozen=True)
class CategoryMappingResult:
    idmefv2_category: str
    matched_field: str
    matched_value: str
    mapping_confidence: str = ""
    idmefv2_rank: str = ""
    mapping_source: str = ""
    security_domain: str = ""
    splunk_severity: str = ""
    disabled: str = ""
    observed_in_current_notables: str = ""
    notes: str = ""


def _mapping_csv_path() -> Path:
    """Return the expected local path of the category mapping CSV."""
    app_root = Path(__file__).resolve().parent.parent
    return app_root / "lookups" / "idmefv2_category_mapping.csv"


def _normalize(value: Any) -> str:
    """Normalize a candidate string for exact-but-stable matching."""
    return " ".join(str(value or "").strip().lower().split())


@lru_cache(maxsize=1)
def _load_category_mapping() -> Dict[str, CategoryMappingResult]:
    """Load the static search_name -> IDMEFv2 Category mapping."""
    path = _mapping_csv_path()

    if not path.exists():
        logger.warning(
            "IDMEFv2 category mapping CSV not found at path=%s. "
            "Falling back to %s.",
            path,
            DEFAULT_CATEGORY,
        )
        return {}

    mapping: Dict[str, CategoryMappingResult] = {}

    with path.open("r", encoding="utf-8-sig", newline="") as csv_file:
        reader = csv.DictReader(csv_file)

        for row_number, row in enumerate(reader, start=2):
            splunk_search_name = str(
                row.get("splunk_search_name") or ""
            ).strip()

            idmefv2_category = str(
                row.get("idmefv2_category") or ""
            ).strip()

            if not splunk_search_name or not idmefv2_category:
                logger.debug(
                    "Skipping incomplete category mapping row=%s search_name=%r "
                    "category=%r",
                    row_number,
                    splunk_search_name,
                    idmefv2_category,
                )
                continue

            key = _normalize(splunk_search_name)

            if key in mapping:
                logger.warning(
                    "Duplicate IDMEFv2 category mapping for search_name=%r "
                    "at row=%s. Keeping the first value.",
                    splunk_search_name,
                    row_number,
                )
                continue

            mapping[key] = CategoryMappingResult(
                idmefv2_category=idmefv2_category,
                matched_field="splunk_search_name",
                matched_value=splunk_search_name,
                mapping_confidence=str(
                    row.get("mapping_confidence") or ""
                ).strip(),
                idmefv2_rank=str(
                    row.get("idmefv2_rank") or ""
                ).strip(),
                mapping_source=str(
                    row.get("mapping_source") or ""
                ).strip(),
                security_domain=str(
                    row.get("security_domain") or ""
                ).strip(),
                splunk_severity=str(
                    row.get("splunk_severity") or ""
                ).strip(),
                disabled=str(
                    row.get("disabled") or ""
                ).strip(),
                observed_in_current_notables=str(
                    row.get("observed_in_current_notables") or ""
                ).strip(),
                notes=str(
                    row.get("notes") or ""
                ).strip(),
            )

    logger.info(
        "Loaded %s IDMEFv2 category mapping rows from %s.",
        len(mapping),
        path,
    )

    return mapping


def find_category_mapping(
    candidates: Iterable[Tuple[str, Any]],
) -> Optional[CategoryMappingResult]:
    """Find the first matching IDMEFv2 category from ordered candidates.

    Args:
        candidates:
            Ordered pairs of:

                (field_name, candidate_value)

            Example:

                ("technical_alert.search_name", "Network - FGT - TCP Port Scan - Rule")

    Returns:
        CategoryMappingResult if a mapping is found, otherwise None.
    """
    mapping = _load_category_mapping()

    for field_name, value in candidates:
        key = _normalize(value)

        if not key:
            continue

        result = mapping.get(key)

        if result is None:
            continue

        return replace(
            result,
            matched_field=field_name,
            matched_value=str(value or "").strip(),
        )

    return None


def category_from_candidates(
    candidates: Iterable[Tuple[str, Any]],
) -> str:
    """Return the mapped IDMEFv2 category or the default fallback category."""
    result = find_category_mapping(candidates)

    if result is None:
        return DEFAULT_CATEGORY

    return result.idmefv2_category