"""Incident review history and status label retrieval via Search REST API."""

from __future__ import annotations

import logging
from typing import Any

from splunk_rest_client import SplunkRestClient

logger = logging.getLogger(__name__)

_SPL_HISTORY = (
    '| inputlookup incident_review_lookup '
    '| eval review_epoch=tonumber(coalesce(review_time, time)) '
    '| search rule_id="{rule_id}" '
    '| where isnotnull(review_epoch) '
    '| lookup reviewstatuses_lookup status OUTPUT label as status_label end as status_end '
    '| eval review_time_iso=strftime(review_epoch, "%Y-%m-%dT%H:%M:%S%z") '
    '| table _key rule_id status status_label status_end review_epoch '
    'review_time_iso user owner comment '
    '| sort review_epoch'
)

_SPL_STATUS_LABELS = (
    '| inputlookup reviewstatuses_lookup '
    '| table status label description end '
    '| dedup status label '
    '| sort status'
)


def _escape_spl(value: str) -> str:
    return str(value or "").replace("\\", "\\\\").replace('"', '\\"')


def get_history(client: SplunkRestClient, rule_id: str) -> list[dict[str, Any]]:
    """Retrieve full lifecycle history for a rule_id from incident_review_lookup."""
    rule_id = str(rule_id or "").strip()

    if not rule_id:
        logger.warning("Cannot retrieve incident review history with empty rule_id.")
        return []

    spl = _SPL_HISTORY.format(rule_id=_escape_spl(rule_id))

    try:
        rows = client.search_export(spl)
        logger.debug("History for rule_id=%s: %d records", rule_id, len(rows))
        return rows
    except RuntimeError as exc:
        logger.warning("Could not fetch history for rule_id=%s: %s", rule_id, exc)
        return []


def load_status_labels(client: SplunkRestClient) -> dict[str, str]:
    """Return {status_code: label} from reviewstatuses_lookup."""
    try:
        rows = client.search_export(_SPL_STATUS_LABELS)

        labels: dict[str, str] = {}

        for row in rows:
            code = str(row.get("status") or "").strip()
            label = str(row.get("label") or "").strip()

            if code and label:
                labels[code] = label

        logger.debug("Loaded %d status labels", len(labels))
        return labels

    except RuntimeError as exc:
        logger.warning("Could not load reviewstatuses_lookup: %s", exc)
        return {}
