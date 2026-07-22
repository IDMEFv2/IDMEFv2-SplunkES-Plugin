"""Optional index=notable enrichment with candidate scoring.

This module must never block processing. All failures return empty results.

Observed behavior from validation testing:
  - index=notable contains events but rule_id/event_id/ir_lookup_key may be empty.
  - Direct join by rule_id can return no results.
  - Free-text search by risk_object/entity/src/dest can return useful candidates.
"""

from __future__ import annotations

import logging
from typing import Any

from splunk_rest_client import SplunkRestClient

logger = logging.getLogger(__name__)


_FIELDS = (
    "_time orig_time firstTime lastTime "
    "search_name source_event_id source_guid "
    "event_id rule_id ir_lookup_key detection_id "
    "rule_name rule_title rule_description "
    "orig_rule_title orig_rule_description "
    "description message note "
    "priority severity urgency category threat_category security_domain "
    "orig_security_domain "
    "src src_ip src_host src_port src_user src_category "
    "dest dest_ip dest_host dest_port dest_user dest_category recipient "
    "user user_category "
    "risk_score risk_object risk_object_type risk_object_category confidence "
    "dvc dvc_ip dvc_name dvc_host dvc_category dvc_bunit "
    "orig_host host location source app service protocol "
    "vendor_product product_version "
    "file_hash file_name file_size "
    "scanned_ports signature signature_id "
    "sourcetype index"
)

_SPL_DIRECT = (
    'search index=notable earliest={earliest} latest=now '
    '(source_event_id="{rule_id}" '
    'OR rule_id="{rule_id}" '
    'OR ir_lookup_key="{rule_id}" '
    'OR event_id="{rule_id}") '
    '| eval rule_title=coalesce(rule_title, orig_rule_title, search_name) '
    '| eval rule_description=coalesce(rule_description, orig_rule_description) '
    '| eval security_domain=coalesce(security_domain, orig_security_domain) '
    '| eval description=coalesce(description, message, rule_description, search_name) '
    '| table {fields} '
    '| head 20'
)

# Fallback for environments where incident_review_lookup.rule_id is a notable
# review key such as
#   <uuid>@@notable@@time<epoch>
# while index=notable stores only the base id, or stores the identifier only in
# _raw. This remains intentionally narrow because identifier terms are extracted
# from the review key, not from broad words such as the rule title.
_SPL_IDENTIFIER = (
    'search index=notable earliest={earliest} latest=now ({terms}) '
    '| table {fields} '
    '| head 20'
)

_SPL_SCORED = (
    'search index=notable earliest={earliest} latest=now "{search_term}" '
    '| eval match_score=0 '
    '| eval match_score=match_score + if(risk_object="{search_term}", 50, 0) '
    '| eval match_score=match_score + if(search_name="{search_name}", 40, 0) '
    '| eval match_score=match_score + if(rule_name="{rule_name}", 30, 0) '
    '| eval match_score=match_score + if(risk_score="{risk_score}", 20, 0) '
    '| eval match_score=match_score + if(severity="{severity}", 10, 0) '
    '| eval match_score=match_score + if(src="{search_term}", 10, 0) '
    '| eval match_score=match_score + if(dest="{search_term}", 10, 0) '
    '| eval match_score=match_score + if(src_ip="{search_term}", 10, 0) '
    '| eval match_score=match_score + if(dest_ip="{search_term}", 10, 0) '
    '| eval match_score=match_score + if(src_host="{search_term}", 10, 0) '
    '| eval match_score=match_score + if(dest_host="{search_term}", 10, 0) '
    '| sort - match_score - _time '
    '| table match_score {fields} '
    '| head 20'
)


def _escape_spl(value: str) -> str:
    return str(value or "").replace("\\", "\\\\").replace('"', '\\"')


def _identifier_terms(rule_id: str) -> list[str]:
    """Return precise identifier terms derived from an incident_review rule_id."""
    text = str(rule_id or "").strip()

    if not text:
        return []

    terms: list[str] = [text]

    # Common ES review key shape: <base-id>@@notable@@time<epoch>.
    if "@@" in text:
        base = text.split("@@", 1)[0].strip()

        if base:
            terms.append(base)

    # Deduplicate while preserving order.
    deduped: list[str] = []
    seen: set[str] = set()

    for term in terms:
        if term and term not in seen:
            deduped.append(term)
            seen.add(term)

    return deduped


def _quoted_or_terms(values: list[str]) -> str:
    return " OR ".join(f'"{_escape_spl(value)}"' for value in values if value)


def _consolidated_findings(investigation: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Return consolidated_findings as a list of dictionaries."""
    if not investigation:
        return []

    cf = investigation.get("consolidated_findings")

    if isinstance(cf, dict):
        return [cf]

    if isinstance(cf, list):
        return [item for item in cf if isinstance(item, dict)]

    return []


def _to_first_scalar(value: Any) -> str:
    """Return first useful scalar value from scalar/list input."""
    if isinstance(value, list):
        for item in value:
            item_str = str(item or "").strip()

            if item_str:
                return item_str

        return ""

    return str(value or "").strip()


def _cf_value(investigation: dict[str, Any] | None, field: str) -> str:
    """Return the first non-empty consolidated_findings value for a field."""
    for cf in _consolidated_findings(investigation):
        value = _to_first_scalar(cf.get(field))

        if value:
            return value

    return ""


def _first_available_cf_value(
    investigation: dict[str, Any] | None,
    fields: tuple[str, ...],
) -> str:
    """Return the first available value across multiple consolidated_findings fields."""
    for field in fields:
        value = _cf_value(investigation, field)

        if value:
            return value

    return ""


def find_candidates(
    client: SplunkRestClient,
    rule_id: str,
    investigation: dict[str, Any] | None,
    earliest: str,
    min_score: int,
) -> list[dict[str, Any]]:
    """Try direct join by rule_id, then scored fallback by risk_object/entity/src/dest."""
    rule_id = str(rule_id or "").strip()
    earliest = str(earliest or "-365d").strip()
    min_score = int(min_score or 0)

    # 1. Direct attempt.
    if rule_id:
        try:
            direct = client.search_export(
                _SPL_DIRECT.format(
                    earliest=_escape_spl(earliest),
                    rule_id=_escape_spl(rule_id),
                    fields=_FIELDS,
                )
            )

            if direct:
                logger.debug(
                    "Direct notable match: %d candidates for rule_id=%s",
                    len(direct),
                    rule_id,
                )
                return direct

        except RuntimeError as exc:
            logger.debug(
                "Direct notable search failed for rule_id=%s: %s",
                rule_id,
                exc,
            )

    # 2. Identifier fallback.
    # This helps when Mission Control has not created an investigation object,
    # but index=notable contains the notable/finding event whose id is embedded
    # in incident_review_lookup.rule_id.
    identifier_terms = _identifier_terms(rule_id)

    if identifier_terms:
        try:
            identifier_matches = client.search_export(
                _SPL_IDENTIFIER.format(
                    earliest=_escape_spl(earliest),
                    terms=_quoted_or_terms(identifier_terms),
                    fields=_FIELDS,
                )
            )

            if identifier_matches:
                logger.info(
                    "Identifier notable match: %d candidates for rule_id=%s terms=%s",
                    len(identifier_matches),
                    rule_id,
                    ",".join(identifier_terms),
                )
                return identifier_matches

        except RuntimeError as exc:
            logger.debug(
                "Identifier notable search failed for rule_id=%s: %s",
                rule_id,
                exc,
            )

    # 3. Scored fallback using investigation consolidated_findings fields.
    search_term = _first_available_cf_value(
        investigation,
        (
            "risk_object",
            "normalized_risk_object",
            "entity",
            "dest",
            "dest_ip",
            "dest_host",
            "src",
            "src_ip",
            "src_host",
            "host",
        ),
    )

    if not search_term:
        logger.info(
            "No investigation-derived risk_object/entity/src/dest available for scored notable fallback. rule_id=%s",
            rule_id,
        )
        return []

    search_name = _cf_value(investigation, "search_name")
    rule_name = _cf_value(investigation, "rule_name")
    risk_score = _cf_value(investigation, "risk_score")
    severity = _cf_value(investigation, "severity")

    try:
        scored = client.search_export(
            _SPL_SCORED.format(
                earliest=_escape_spl(earliest),
                search_term=_escape_spl(search_term),
                search_name=_escape_spl(search_name),
                rule_name=_escape_spl(rule_name),
                risk_score=_escape_spl(risk_score),
                severity=_escape_spl(severity),
                fields=_FIELDS,
            )
        )

    except RuntimeError as exc:
        logger.warning(
            "Scored notable search failed for rule_id=%s: %s",
            rule_id,
            exc,
        )
        return []

    filtered: list[dict[str, Any]] = []

    for row in scored:
        try:
            score = int(float(str(row.get("match_score") or 0)))
        except (TypeError, ValueError):
            score = 0

        if score >= min_score:
            filtered.append(row)

    logger.debug(
        "Scored notable search rule_id=%s search_term=%s: %d total, %d above min_score=%d",
        rule_id,
        search_term,
        len(scored),
        len(filtered),
        min_score,
    )

    return filtered