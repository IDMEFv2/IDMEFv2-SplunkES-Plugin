"""Mission Control client: retrieves investigations by rule_id via pagination."""

from __future__ import annotations

import logging
from typing import Any

from splunk_rest_client import SplunkRestClient

INVESTIGATIONS_PATH = "/servicesNS/nobody/missioncontrol/public/v2/investigations"
PAGE_LIMIT = 100

logger = logging.getLogger(__name__)


def _as_investigation_page(data: Any) -> list[dict[str, Any]]:
    """Normalize Mission Control investigations response to a list of dicts.

    Observed response shape:
    - direct JSON array

    Defensive supported shapes:
    - {"items": [...]}
    - {"entry": [...]}
    """
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]

    if isinstance(data, dict):
        if "code" in data and "message" in data:
            logger.error(
                "Mission Control returned error code=%s message=%s",
                data.get("code"),
                data.get("message"),
            )
            return []

        items = data.get("items")
        if isinstance(items, list):
            return [item for item in items if isinstance(item, dict)]

        entry = data.get("entry")
        if isinstance(entry, list):
            return [item for item in entry if isinstance(item, dict)]

    logger.error(
        "Unexpected /investigations response type: %s",
        type(data).__name__,
    )
    return []


def _consolidated_findings(investigation: dict[str, Any]) -> list[dict[str, Any]]:
    """Return consolidated_findings as a list of dictionaries."""
    cf = investigation.get("consolidated_findings")

    if isinstance(cf, dict):
        return [cf]

    if isinstance(cf, list):
        return [item for item in cf if isinstance(item, dict)]

    return []


def _cf_values(investigation: dict[str, Any], field: str) -> set[str]:
    """Extract all values for a field from consolidated_findings."""
    values: set[str] = set()

    for cf in _consolidated_findings(investigation):
        value = cf.get(field)

        if isinstance(value, list):
            for item in value:
                item_str = str(item or "").strip()
                if item_str:
                    values.add(item_str)
        else:
            value_str = str(value or "").strip()
            if value_str:
                values.add(value_str)

    return values


def _matches_rule_id(investigation: dict[str, Any], rule_id: str) -> bool:
    """Check whether an investigation matches the trigger rule_id."""
    candidate_values: set[str] = set()

    for field in ("rule_id", "ir_lookup_key", "event_id"):
        candidate_values.update(_cf_values(investigation, field))

    return rule_id in candidate_values


def find_investigation_by_rule_id(
    client: SplunkRestClient,
    rule_id: str,
) -> dict[str, Any] | None:
    """Paginate through /investigations and return the first matching rule_id.

    Matching logic:
    - consolidated_findings.rule_id == rule_id
    - consolidated_findings.ir_lookup_key == rule_id
    - consolidated_findings.event_id == rule_id
    """
    rule_id = str(rule_id or "").strip()

    if not rule_id:
        logger.warning("Cannot find investigation with empty rule_id.")
        return None

    offset = 0

    while True:
        try:
            data = client.get_json(
                INVESTIGATIONS_PATH,
                params={
                    "limit": PAGE_LIMIT,
                    "offset": offset,
                    "sort": "update_time:desc",
                    "update_time_min": 0,
                    "output_mode": "json",
                },
            )
        except RuntimeError as exc:
            logger.error("Mission Control /investigations failed: %s", exc)
            return None

        page = _as_investigation_page(data)

        if not page:
            break

        for investigation in page:
            if _matches_rule_id(investigation, rule_id):
                logger.debug(
                    "Matched investigation %s for rule_id=%s",
                    investigation.get("investigation_id")
                    or investigation.get("investigation_guid"),
                    rule_id,
                )
                return investigation

        if len(page) < PAGE_LIMIT:
            break

        offset += PAGE_LIMIT

    logger.warning("No investigation found for rule_id=%s", rule_id)
    return None