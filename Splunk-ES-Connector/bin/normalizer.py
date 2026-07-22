"""Builds normalized internal alert objects from all data sources.

No IDMEFv2 field mapping is implemented here.
The normalized object is the stable internal representation used before
the final IDMEFv2 mapper.
"""

from __future__ import annotations

import copy
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


TECHNICAL_FIELDS = (
    "_time",
    "firstTime",
    "lastTime",
    "search_name",
    "event_id",
    "rule_id",
    "ir_lookup_key",
    "detection_id",
    "rule_name",
    "rule_title",
    "rule_description",
    "description",
    "message",
    "note",
    "priority",
    "severity",
    "category",
    "threat_category",
    "security_domain",
    "src",
    "src_ip",
    "src_host",
    "src_port",
    "src_user",
    "src_category",
    "dest",
    "dest_ip",
    "dest_host",
    "dest_port",
    "dest_user",
    "dest_category",
    "recipient",
    "user",
    "user_category",
    "risk_score",
    "risk_object",
    "risk_object_type",
    "risk_object_category",
    "confidence",
    "dvc",
    "dvc_ip",
    "dvc_name",
    "dvc_host",
    "dvc_category",
    "dvc_bunit",
    "orig_host",
    "host",
    "location",
    "source",
    "app",
    "service",
    "protocol",
    "vendor_product",
    "product_version",
    "file_hash",
    "file_name",
    "file_size",
    "sourcetype",
    "index",
    "entity",
    "entity_type",
    "normalized_risk_object",
    "normalized_risk_object_type",
)


LIST_FIELDS = {
    "src",
    "dest",
    "user",
    "mitre_attack",
    "mitre_tactic",
    "mitre_technique",
}


LOWERCASE_FIELDS = {
    "severity",
    "priority",
    "urgency",
}


def _to_list(value: Any) -> list[str]:
    """Normalize scalar/list values to a list of non-empty strings."""
    if value is None or value == "":
        return []

    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item or "").strip()]

    return [str(value).strip()]


def _to_first_scalar(value: Any) -> str:
    """Return first useful scalar value from scalar/list input."""
    values = _to_list(value)
    return values[0] if values else ""


def _parse_annotations(value: Any) -> dict[str, Any]:
    """Parse annotations from dict or JSON string."""
    if isinstance(value, dict):
        return value

    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return {}

        return parsed if isinstance(parsed, dict) else {}

    return {}


def _get_nested_value(data: dict[str, Any], dotted_path: str) -> Any:
    """Read a nested value from a dict using dotted notation."""
    current: Any = data

    for part in dotted_path.split("."):
        if not isinstance(current, dict):
            return None

        current = current.get(part)

    return current


def _annotation_list(
    cf: dict[str, Any],
    annotations: dict[str, Any],
    *names: str,
) -> list[str]:
    """Read annotation values from nested annotations or flattened fields."""
    values: list[str] = []

    for name in names:
        direct_value = annotations.get(name)

        if direct_value not in (None, "", []):
            values.extend(_to_list(direct_value))

        nested_value = _get_nested_value(annotations, name)

        if nested_value not in (None, "", []):
            values.extend(_to_list(nested_value))

        flat_cf_value = cf.get(name)

        if flat_cf_value not in (None, "", []):
            values.extend(_to_list(flat_cf_value))

        dotted_cf_value = cf.get(f"annotations.{name}")

        if dotted_cf_value not in (None, "", []):
            values.extend(_to_list(dotted_cf_value))

    return _unique(values)


def _unique(values: list[str]) -> list[str]:
    """Return unique non-empty strings while preserving order."""
    seen: set[str] = set()
    result: list[str] = []

    for value in values:
        text = str(value or "").strip()

        if not text or text in seen:
            continue

        seen.add(text)
        result.append(text)

    return result


def _consolidated_findings(investigation: dict[str, Any]) -> list[dict[str, Any]]:
    """Return consolidated_findings as a list of dictionaries."""
    cf = investigation.get("consolidated_findings")

    if isinstance(cf, dict):
        return [cf]

    if isinstance(cf, list):
        return [item for item in cf if isinstance(item, dict)]

    return []


def _cf_candidate_values(cf: dict[str, Any]) -> set[str]:
    """Return candidate join values from a consolidated finding."""
    values: set[str] = set()

    for field_name in (
        "rule_id",
        "ir_lookup_key",
        "event_id",
        "detection_id",
    ):
        for value in _to_list(cf.get(field_name)):
            values.add(value)

    return values


def _select_consolidated_finding(
    investigation: dict[str, Any],
    rule_id: str,
) -> dict[str, Any]:
    """Select the consolidated_finding matching the rule_id, if possible."""
    findings = _consolidated_findings(investigation)

    if not findings:
        return {}

    rule_id = str(rule_id or "").strip()

    if rule_id:
        for cf in findings:
            if rule_id in _cf_candidate_values(cf):
                return cf

    return findings[0]


def _normalize_field_value(field_name: str, value: Any) -> Any:
    """Normalize selected technical fields without losing raw useful values."""
    if field_name in LIST_FIELDS:
        return _to_list(value)

    if field_name in LOWERCASE_FIELDS:
        return _to_first_scalar(value).lower()

    if isinstance(value, list):
        return _to_list(value)

    return _to_first_scalar(value)


def _extract_consolidated_fields(
    investigation: dict[str, Any],
    rule_id: str,
) -> dict[str, Any]:
    """Extract technical fields from the selected consolidated_finding."""
    cf = _select_consolidated_finding(investigation, rule_id)

    if not isinstance(cf, dict):
        cf = {}

    annotations = _parse_annotations(cf.get("annotations"))

    fields: dict[str, Any] = {}

    for field_name in TECHNICAL_FIELDS:
        fields[field_name] = _normalize_field_value(field_name, cf.get(field_name))

    # Backward-compatible fallbacks for risk object/entity naming.
    if not fields.get("risk_object"):
        fields["risk_object"] = _to_first_scalar(
            cf.get("normalized_risk_object") or cf.get("entity")
        )

    if not fields.get("risk_object_type"):
        fields["risk_object_type"] = _to_first_scalar(
            cf.get("normalized_risk_object_type") or cf.get("entity_type")
        )

    fields["mitre_attack"] = _annotation_list(
        cf,
        annotations,
        "mitre_attack",
        "annotations.mitre_attack",
    )

    fields["mitre_tactic"] = _annotation_list(
        cf,
        annotations,
        "mitre_tactic",
        "mitre_attack.mitre_tactic",
        "mitre_attack.mitre_tactic_id",
        "annotations.mitre_attack.mitre_tactic",
        "annotations.mitre_attack.mitre_tactic_id",
    )

    fields["mitre_technique"] = _annotation_list(
        cf,
        annotations,
        "mitre_technique",
        "mitre_attack.mitre_technique",
        "mitre_attack.mitre_technique_id",
        "annotations.mitre_attack.mitre_technique",
        "annotations.mitre_attack.mitre_technique_id",
    )

    fields["raw_consolidated_finding"] = copy.deepcopy(cf)

    return fields


def _best_notable_candidate(
    notable_candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    """Return the highest-scored notable candidate, if available."""
    if not notable_candidates:
        return {}

    def score(row: dict[str, Any]) -> float:
        try:
            return float(str(row.get("match_score") or 0))
        except (TypeError, ValueError):
            return 0.0

    return copy.deepcopy(max(notable_candidates, key=score))


def _fallback(value: Any, fallback: Any) -> Any:
    """Return value if meaningful, otherwise fallback."""
    if value in (None, "", []):
        return fallback

    return value


def build_alert_context(
    rule_id: str,
    investigation: dict[str, Any] | None,
    history: list[dict[str, Any]],
    notable_candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build the base normalized alert context from all available sources.

    The trigger_event is not attached here; call attach_trigger_event() next.
    """
    inv = investigation or {}
    rule_id = str(rule_id or "").strip()

    cf = _extract_consolidated_fields(inv, rule_id)
    notable_best_candidate = _best_notable_candidate(notable_candidates)

    resolved_rule_id = rule_id or str(cf.get("rule_id") or "")

    technical_alert = {
        "name": str(inv.get("name") or "").strip(),
        "description": _fallback(
            str(inv.get("description") or "").strip(),
            cf.get("description")
            or cf.get("message")
            or cf.get("rule_description")
            or notable_best_candidate.get("description")
            or notable_best_candidate.get("message")
            or "",
        ),
        "notable_best_candidate": copy.deepcopy(notable_best_candidate),
        "notable_candidates": copy.deepcopy(notable_candidates),
    }

    for field_name in TECHNICAL_FIELDS:
        technical_alert[field_name] = cf.get(field_name)

    technical_alert["mitre_attack"] = cf.get("mitre_attack", [])
    technical_alert["mitre_tactic"] = cf.get("mitre_tactic", [])
    technical_alert["mitre_technique"] = cf.get("mitre_technique", [])

    return {
        "source_model": "splunk_internal_app_hybrid",
        "trigger_event": {},
        "join_keys": {
            "investigation_guid": str(inv.get("investigation_guid") or ""),
            "investigation_id": str(inv.get("investigation_id") or ""),
            "rule_id": resolved_rule_id,
            "ir_lookup_key": str(cf.get("ir_lookup_key") or ""),
            "event_id": str(cf.get("event_id") or ""),
            "detection_id": str(cf.get("detection_id") or ""),
        },
        "lifecycle": {
            "status": str(inv.get("status") or ""),
            "status_name": str(inv.get("status_name") or ""),
            "owner": str(inv.get("owner") or ""),
            "urgency": str(inv.get("urgency") or ""),
            "disposition": str(inv.get("disposition") or ""),
            "disposition_name": str(inv.get("disposition_name") or ""),
            "create_time": inv.get("create_time"),
            "update_time": inv.get("update_time"),
            "history": copy.deepcopy(history),
        },
        "technical_alert": technical_alert,
        "raw": {
            "trigger": {},
            "investigation": copy.deepcopy(inv),
            "selected_consolidated_finding": cf.get("raw_consolidated_finding", {}),
            "incident_review_history": copy.deepcopy(history),
            "notable_best_candidate": copy.deepcopy(notable_best_candidate),
            "notable_candidates": copy.deepcopy(notable_candidates),
        },
    }


def attach_trigger_event(
    base_context: dict[str, Any],
    trigger_event: dict[str, Any],
) -> dict[str, Any]:
    """Attach a specific trigger event to the base context to form the final normalized object."""
    normalized = copy.deepcopy(base_context)

    normalized["trigger_event"] = {
        "event_uid": str(trigger_event.get("event_uid") or ""),
        "event_type": str(trigger_event.get("event_type") or "incident_review_status_change"),
        "rule_id": str(trigger_event.get("rule_id") or ""),
        "status": str(trigger_event.get("status") or ""),
        "status_label": str(trigger_event.get("status_label") or ""),
        "status_end": str(trigger_event.get("status_end") or ""),
        "review_epoch": str(trigger_event.get("review_epoch") or ""),
        "review_time_iso": str(trigger_event.get("review_time_iso") or ""),
        "user": str(trigger_event.get("user") or ""),
        "owner": str(trigger_event.get("owner") or ""),
        "comment": str(trigger_event.get("comment") or ""),
    }

    normalized["raw"]["trigger"] = copy.deepcopy(trigger_event)

    return normalized