# pylint: disable=too-many-lines
"""Map internal normalized Splunk alert context to IDMEFv2 V08.

Input:
    normalized internal object produced by normalizer.py

Output:
    IDMEFv2 V08 alert payload

Important notes:
- IDMEFv2 Category is mapped from the static Splunk ES category lookup
  when a matching correlation search name is available.
- If no approved mapping is found, Category falls back to ["Other.Undetermined"].
- Splunk/CIM category-like values are preserved in ext-Category when available.
- Optional empty fields are removed from the final payload.
- Required/minimum fields are always populated with controlled fallbacks.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from common_helpers import to_list as _to_list
from idmefv2_category_mapping import find_category_mapping

IDMEFV2_VERSION = "2.D.V08"

DEFAULT_ORGANISATION_NAME = "CHANGE-ME"
DEFAULT_ORGANISATION_ID = "CHANGE-ME"
DEFAULT_ENTITY_NAME = "CHANGE-ME"
DEFAULT_ENTITY_ID = "CHANGE-ME"

DEFAULT_ANALYZER_NAME = "Splunk ES"
DEFAULT_ANALYZER_MODEL = "Splunk Enterprise Security"

DEFAULT_TYPE = ["Cyber"]
DEFAULT_CATEGORY = ["Other.Undetermined"]
DEFAULT_CAUSE = "Unknown"
DEFAULT_STATUS = ["Incident"]
DEFAULT_PRIORITY = "Medium"
DEFAULT_DESCRIPTION = "Splunk ES alert"

STATUS_CODE_TO_NAME = {
    "0": "unassigned",
    "1": "new",
    "2": "in progress",
    "3": "pending",
    "4": "resolved",
    "5": "closed",
}

STATUS_NAME_TO_IDMEF = {
    "unassigned": "Incident",
    "new": "Incident",
    "in progress": "Open",
    "pending": "Open",
    "resolved": "Closed",
    "closed": "Closed",
}

PRIORITY_NORMALIZATION = {
    "critical": "High",
    "high": "High",
    "medium": "Medium",
    "med": "Medium",
    "low": "Low",
    "informational": "Info",
    "info": "Info",
    "unknown": "Unknown",
}

VALID_PRIORITY = {"Unknown", "Info", "Low", "Medium", "High"}
VALID_CAUSE = {"Normal", "Error", "Malicious", "Malfunction", "Hazard", "Unknown"}

IPV4_RE = re.compile(
    r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PROTOCOL_RE = re.compile(r"^[a-zA-Z0-9](-?[a-zA-Z0-9])*$")
HASH_RE = re.compile(r"^[a-zA-Z0-9-]+:([a-fA-F0-9]{2})+$")


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _config_get(config: Any, name: str, default: Any = "") -> Any:
    """Read a value from a dict-like or dataclass/object config."""
    if config is None:
        return default

    if isinstance(config, dict):
        value = config.get(name, default)
    else:
        value = getattr(config, name, default)

    return default if value in (None, "") else value


def _first(value: Any) -> str:
    values = _to_list(value)
    return values[0] if values else ""


def _first_from(*values: Any) -> str:
    """Return first non-empty scalar from multiple possible values."""
    for value in values:
        scalar = _first(value)

        if scalar:
            return scalar

    return ""


def _get_any(
    technical: dict[str, Any],
    notable: dict[str, Any],
    *field_names: str,
) -> str:
    """Read first available field from technical_alert, then notable_best_candidate."""
    for field_name in field_names:
        value = _first(technical.get(field_name))

        if value:
            return value

    for field_name in field_names:
        value = _first(notable.get(field_name))

        if value:
            return value

    return ""


def _get_any_raw(
    technical: dict[str, Any],
    notable: dict[str, Any],
    *field_names: str,
) -> Any:
    """Read first available raw field from technical_alert, then notable_best_candidate."""
    for field_name in field_names:
        value = technical.get(field_name)

        if value not in (None, "", []):
            return value

    for field_name in field_names:
        value = notable.get(field_name)

        if value not in (None, "", []):
            return value

    return None


def _is_ipv4(value: Any) -> bool:
    text = str(value or "").strip()
    return bool(IPV4_RE.match(text))


def _looks_like_email(value: Any) -> bool:
    text = str(value or "").strip()
    return bool(EMAIL_RE.match(text))


def _to_rfc3339(
    value: Any,
    fallback: str | None = None,
) -> str:
    """Convert common Splunk timestamp representations to RFC3339 UTC.

    Supports:
    - epoch seconds;
    - epoch milliseconds;
    - ISO/RFC3339-like strings;
    - strings ending with Z.
    """
    if value in (None, ""):
        return fallback or _utc_now()

    text = str(value).strip()

    try:
        timestamp = float(text)

        # Handle epoch milliseconds defensively.
        if timestamp > 10_000_000_000:
            timestamp = timestamp / 1000.0

        return _format_rfc3339(
            datetime.fromtimestamp(
                timestamp,
                tz=timezone.utc,
            )
        )

    except (
        TypeError,
        ValueError,
        OSError,
        OverflowError,
    ):
        pass

    normalized = text

    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return fallback or _utc_now()

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    else:
        parsed = parsed.astimezone(timezone.utc)

    return _format_rfc3339(parsed)

def _format_rfc3339(value: datetime) -> str:
    """Format an aware datetime as RFC3339 UTC, preserving fractions."""
    normalized = value.astimezone(timezone.utc)

    if normalized.microsecond:
        return normalized.isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z")

    return normalized.strftime("%Y-%m-%dT%H:%M:%SZ")

def _rule_id_epoch(
    normalized: dict[str, Any],
) -> str:
    """Extract the original notable epoch from a Splunk ES review key."""
    join_keys = normalized.get("join_keys") or {}
    trigger = normalized.get("trigger_event") or {}

    rule_id = _first_from(
        join_keys.get("rule_id"),
        trigger.get("rule_id"),
    )

    match = re.search(
        r"@@notable@@time(?P<epoch>\d+(?:\.\d+)?)",
        rule_id,
    )

    return match.group("epoch") if match else ""

def _normalize_priority(value: Any) -> str:
    raw = str(value or "").strip().lower()

    if not raw:
        return ""

    mapped = PRIORITY_NORMALIZATION.get(raw)

    if mapped in VALID_PRIORITY:
        return mapped

    return ""


def _priority_from_context(
    lifecycle: dict[str, Any],
    technical: dict[str, Any],
    notable: dict[str, Any],
) -> str:
    """Priority order:
    1. Splunk priority;
    2. severity;
    3. urgency;
    4. Medium.
    """
    priority = _normalize_priority(_get_any(technical, notable, "priority"))

    if priority:
        return priority

    severity = _normalize_priority(_get_any(technical, notable, "severity"))

    if severity:
        return severity

    urgency = _normalize_priority(lifecycle.get("urgency"))

    if urgency:
        return urgency

    return DEFAULT_PRIORITY


def _status_to_idmef(status: Any, status_label: Any = "") -> list[str]:
    raw = str(status_label or status or "").strip().lower()
    raw = STATUS_CODE_TO_NAME.get(raw, raw)

    mapped = STATUS_NAME_TO_IDMEF.get(raw)

    if not mapped:
        return list(DEFAULT_STATUS)

    return [mapped]


def _confidence_from_context(
    technical: dict[str, Any],
    notable: dict[str, Any],
) -> float | None:
    """Prefer confidence. Fallback to risk_score/100.

    Return None when no meaningful confidence signal exists.
    """
    raw_confidence = _get_any_raw(technical, notable, "confidence")

    if raw_confidence not in (None, "", []):
        try:
            value = float(str(raw_confidence))
        except (TypeError, ValueError):
            value = None

        if value is not None:
            if value > 1:
                value = value / 100.0

            return round(max(0.0, min(1.0, value)), 4)

    raw_risk_score = _get_any_raw(technical, notable, "risk_score")

    if raw_risk_score in (None, "", []):
        return None

    try:
        value = float(str(raw_risk_score))
    except (TypeError, ValueError):
        return None

    if value > 1:
        value = value / 100.0

    return round(max(0.0, min(1.0, value)), 4)


def _description(
    normalized: dict[str, Any],
    notable: dict[str, Any],
) -> str:
    technical = normalized.get("technical_alert") or {}
    lifecycle = normalized.get("lifecycle") or {}

    value = _first_from(
        notable.get("description"),
        notable.get("message"),
        technical.get("description"),
        technical.get("name"),
        technical.get("rule_title"),
        technical.get("rule_name"),
        technical.get("rule_description"),
        notable.get("search_name"),
        lifecycle.get("status_name"),
        DEFAULT_DESCRIPTION,
    )

    return value or DEFAULT_DESCRIPTION


def _category_mapping_from_context(
    technical: dict[str, Any],
    notable: dict[str, Any],
):
    """Find an IDMEFv2 category using the static Splunk ES mapping CSV."""
    candidates = [
        (
            "technical_alert.search_name",
            technical.get("search_name"),
        ),
        (
            "notable_best_candidate.search_name",
            notable.get("search_name"),
        ),
        (
            "technical_alert.rule_name",
            technical.get("rule_name"),
        ),
        (
            "notable_best_candidate.rule_name",
            notable.get("rule_name"),
        ),
        (
            "technical_alert.rule_title",
            technical.get("rule_title"),
        ),
        (
            "notable_best_candidate.rule_title",
            notable.get("rule_title"),
        ),
    ]

    return find_category_mapping(candidates)


def _category_from_context(
    technical: dict[str, Any],
    notable: dict[str, Any],
) -> list[str]:
    """Map Splunk ES correlation search context to IDMEFv2 Category.

    The static CSV lookup is the source of truth.

    If no mapping is found, keep the IDMEFv2-required fallback category.
    """
    mapping_result = _category_mapping_from_context(
        technical=technical,
        notable=notable,
    )

    if mapping_result is not None:
        return [mapping_result.idmefv2_category]

    return list(DEFAULT_CATEGORY)


def _cause_from_category(categories: list[str]) -> str:
    """Map IDMEFv2 Category to IDMEFv2 Cause.

    Conservative policy:
    - unclear/generic/operational categories remain Unknown;
    - clear security detections are treated as Malicious.
    """
    category_set = {
        str(category or "").strip()
        for category in categories
        if str(category or "").strip()
    }

    if not category_set:
        return DEFAULT_CAUSE

    non_malicious_or_unclear_categories = {
        "Other.Undetermined",
        "Operational.Policy Violation",
        "Availability.HeartBeat",
        "Availability.Misconfiguration",
    }

    if category_set.issubset(non_malicious_or_unclear_categories):
        return DEFAULT_CAUSE

    return "Malicious"


def _ext_category_from_context(
    technical: dict[str, Any],
    notable: dict[str, Any],
) -> list[str]:
    """Preserve Splunk/CIM category-like values that are not mapped to Category."""
    values: list[str] = []

    fields = (
        "category",
        "threat_category",
        "src_category",
        "dest_category",
        "risk_object_category",
        "user_category",
        "dvc_category",
        "security_domain",
    )

    for field_name in fields:
        for value in _to_list(technical.get(field_name)):
            values.append(f"{field_name}:{value}")

        for value in _to_list(notable.get(field_name)):
            values.append(f"{field_name}:{value}")

    return _unique(values)


def _compose_note(normalized: dict[str, Any], notable: dict[str, Any]) -> str:
    join_keys = normalized.get("join_keys") or {}
    lifecycle = normalized.get("lifecycle") or {}
    technical = normalized.get("technical_alert") or {}
    trigger = normalized.get("trigger_event") or {}

    parts = [
        ("event_uid", trigger.get("event_uid")),
        ("investigation_id", join_keys.get("investigation_id")),
        ("investigation_guid", join_keys.get("investigation_guid")),
        ("rule_id", join_keys.get("rule_id")),
        ("ir_lookup_key", join_keys.get("ir_lookup_key")),
        ("event_id", join_keys.get("event_id")),
        ("detection_id", join_keys.get("detection_id")),
        ("search_name", _get_any(technical, notable, "search_name")),
        (
            "status",
            trigger.get("status_label")
            or lifecycle.get("status_name")
            or lifecycle.get("status"),
        ),
        ("owner", trigger.get("owner") or lifecycle.get("owner")),
        ("urgency", lifecycle.get("urgency")),
        ("disposition", lifecycle.get("disposition_name") or lifecycle.get("disposition")),
        ("priority", _get_any(technical, notable, "priority")),
        ("severity", _get_any(technical, notable, "severity")),
        ("risk_score", _get_any(technical, notable, "risk_score")),
        ("risk_object", _get_any(technical, notable, "risk_object")),
        ("risk_object_type", _get_any(technical, notable, "risk_object_type")),
        ("security_domain", _get_any(technical, notable, "security_domain")),
        ("comment", trigger.get("comment")),
    ]

    return " | ".join(
        f"{name}={value}"
        for name, value in parts
        if str(value or "").strip()
    )


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []

    for value in values:
        normalized = str(value or "").strip()

        if not normalized or normalized in seen:
            continue

        seen.add(normalized)
        result.append(normalized)

    return result


def _build_alt_names(normalized: dict[str, Any], notable: dict[str, Any]) -> list[str]:
    join_keys = normalized.get("join_keys") or {}
    trigger = normalized.get("trigger_event") or {}
    technical = normalized.get("technical_alert") or {}

    values = [
        ("event_uid", trigger.get("event_uid")),
        ("investigation_id", join_keys.get("investigation_id")),
        ("investigation_guid", join_keys.get("investigation_guid")),
        ("rule_id", join_keys.get("rule_id")),
        ("ir_lookup_key", join_keys.get("ir_lookup_key")),
        ("event_id", join_keys.get("event_id")),
        ("detection_id", join_keys.get("detection_id")),
        ("search_name", _get_any(technical, notable, "search_name")),
    ]

    return _unique(
        [
            f"{name}={value}"
            for name, value in values
            if str(value or "").strip()
        ]
    )


def _build_alt_category(normalized: dict[str, Any]) -> list[str]:
    technical = normalized.get("technical_alert") or {}

    values: list[str] = []

    for value in _to_list(technical.get("mitre_attack")):
        values.append(f"MITRE ATT&CK:{value}")

    for value in _to_list(technical.get("mitre_tactic")):
        values.append(f"MITRE ATT&CK Tactic:{value}")

    for value in _to_list(technical.get("mitre_technique")):
        values.append(f"MITRE ATT&CK Technique:{value}")

    return _unique(values)


def _build_analyzer(
    config: Any = None,
) -> dict[str, Any]:
    """Build the IDMEFv2 Analyzer object.

    Analyzer represents the system that analyzed the data and generated
    the IDMEFv2 alert. In this app, that system is Splunk ES.

    Do not use event fields such as host/dvc_host as automatic fallback
    for Analyzer.Hostname, because those fields may refer to the event source,
    target, or device, not necessarily to the Splunk analyzer itself.
    """
    analyzer_name = _first_from(
        _config_get(config, "analyzer_name", ""),
        DEFAULT_ANALYZER_NAME,
    )

    analyzer_model = _first_from(
        _config_get(config, "analyzer_model", ""),
        DEFAULT_ANALYZER_MODEL,
    )

    analyzer: dict[str, Any] = {
        "Name": analyzer_name,
        "Model": analyzer_model,
        "Category": ["SIEM.SIEM"],
    }

    analyzer_hostname = _first_from(
        _config_get(config, "analyzer_hostname", ""),
    )

    if analyzer_hostname:
        analyzer["Hostname"] = analyzer_hostname

    return analyzer


def _port_list(value: Any) -> list[int]:
    ports: list[int] = []

    for raw in _to_list(value):
        try:
            port = int(raw)
        except (TypeError, ValueError):
            continue

        if 1 <= port <= 65535:
            ports.append(port)

    return ports


def _protocol_list(value: Any) -> list[str]:
    protocols: list[str] = []

    for raw in _to_list(value):
        protocol = raw.strip()

        if PROTOCOL_RE.match(protocol):
            protocols.append(protocol)

    return _unique(protocols)


def _resolve_ip(*candidates: str) -> str:
    for candidate in candidates:
        if _is_ipv4(candidate):
            return candidate

    return ""


def _resolve_hostname(host_field: str, *fallback_candidates: str) -> str:
    if host_field:
        return host_field

    for candidate in fallback_candidates:
        if candidate and not _is_ipv4(candidate):
            return candidate

    return ""


def _build_source(
    technical: dict[str, Any],
    notable: dict[str, Any],
) -> list[dict[str, Any]]:
    src_ip = _get_any(technical, notable, "src_ip")
    src_host = _get_any(technical, notable, "src_host")
    src = _get_any(technical, notable, "src")
    src_user = _get_any(technical, notable, "src_user", "user")

    source: dict[str, Any] = {
        "ID": str(uuid.uuid4()),
    }

    ip = _resolve_ip(src_ip, src)

    if ip:
        source["IP"] = ip

    hostname = _resolve_hostname(src_host, src)

    if hostname:
        source["Hostname"] = hostname

    if src_user:
        source["User"] = src_user

        if _looks_like_email(src_user):
            source["Email"] = src_user

    protocols = _protocol_list(_get_any_raw(technical, notable, "protocol"))

    if protocols:
        source["Protocol"] = protocols

    ports = _port_list(_get_any_raw(technical, notable, "src_port"))

    if ports:
        source["Port"] = ports

    # Do not create Source if the only populated field is its generated ID.
    if set(source.keys()) == {"ID"}:
        return []

    return [source]


def _build_target(
    technical: dict[str, Any],
    notable: dict[str, Any],
    attachment_names: list[str],
) -> list[dict[str, Any]]:
    dest_ip = _get_any(technical, notable, "dest_ip")
    dest_host = _get_any(technical, notable, "dest_host")
    dest = _get_any(technical, notable, "dest")
    risk_object = _get_any(technical, notable, "risk_object")
    target_user = _get_any(technical, notable, "dest_user", "recipient")
    service = _get_any(technical, notable, "service", "app")

    target: dict[str, Any] = {
        "ID": str(uuid.uuid4()),
    }

    ip = _resolve_ip(dest_ip, dest, risk_object)

    if ip:
        target["IP"] = ip

    hostname = _resolve_hostname(dest_host, dest, risk_object)

    if hostname:
        target["Hostname"] = hostname

    if target_user:
        target["User"] = target_user

        if _looks_like_email(target_user):
            target["Email"] = target_user

    ports = _port_list(_get_any_raw(technical, notable, "dest_port"))

    if ports:
        target["Port"] = ports

    if service:
        target["Service"] = service

    if attachment_names:
        target["Attachment"] = attachment_names

    # Do not create Target if the only populated field is its generated ID.
    if set(target.keys()) == {"ID"}:
        return []

    return [target]


def _sanitize_attachment_name(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9]", "", value or "")

    if cleaned:
        return cleaned[:64]

    return f"attachment{uuid.uuid4().hex[:16]}"


def _hash_value(value: Any) -> str:
    raw = _first(value)

    if HASH_RE.match(raw):
        return raw

    return ""


def _build_attachments(
    technical: dict[str, Any],
    notable: dict[str, Any],
) -> list[dict[str, Any]]:
    file_hash = _get_any(technical, notable, "file_hash")
    file_name = _get_any(technical, notable, "file_name")
    file_size = _get_any(technical, notable, "file_size")

    if not any([file_hash, file_name, file_size]):
        return []

    name_source = file_hash or file_name or f"attachment{uuid.uuid4().hex[:16]}"
    attachment: dict[str, Any] = {
        "Name": _sanitize_attachment_name(name_source),
    }

    if file_name:
        attachment["FileName"] = file_name

    valid_hash = _hash_value(file_hash)

    if valid_hash:
        attachment["Hash"] = [valid_hash]
    elif file_hash:
        attachment["Note"] = (
            "Original file_hash value did not include a supported "
            f"algorithm prefix: {file_hash}"
        )

    try:
        size = int(str(file_size))
    except (TypeError, ValueError):
        size = None

    if size is not None and size >= 0:
        attachment["Size"] = size

    return [attachment]


def _build_sensor(
    technical: dict[str, Any],
    notable: dict[str, Any],
) -> list[dict[str, Any]]:
    """Build Sensor only when a meaningful Sensor.Name exists."""
    name = _get_any(technical, notable, "dvc_name", "dvc")

    if not name:
        return []

    sensor: dict[str, Any] = {
        "Name": name,
    }

    hostname = _get_any(technical, notable, "dvc_host", "host", "src_host")

    if hostname:
        sensor["Hostname"] = hostname

    ip = _get_any(technical, notable, "dvc_ip", "src_ip")

    if _is_ipv4(ip):
        sensor["IP"] = ip

    vendor_product = _get_any(technical, notable, "vendor_product")
    product_version = _get_any(technical, notable, "product_version")

    if vendor_product and product_version:
        sensor["Model"] = f"{vendor_product} {product_version}"
    elif vendor_product:
        sensor["Model"] = vendor_product

    location = _get_any(technical, notable, "location", "dvc_bunit")

    if location:
        sensor["Location"] = location

    return [sensor]


def _create_time(
    normalized: dict[str, Any],
    notable: dict[str, Any],
    is_update: bool,
) -> str:
    """Return when this specific IDMEF message was created.

    For the opening payload, use the original finding time.
    For lifecycle updates, use the timestamp of the status change.
    """
    trigger = normalized.get("trigger_event") or {}
    lifecycle = normalized.get("lifecycle") or {}

    if is_update:
        value = _first_from(
            trigger.get("review_epoch"),
            trigger.get("review_time_iso"),
            lifecycle.get("update_time"),
        )
    else:
        value = _first_from(
            notable.get("orig_time"),
            notable.get("firstTime"),
            notable.get("_time"),
            trigger.get("review_epoch"),
            lifecycle.get("create_time"),
            _rule_id_epoch(normalized),
        )

    return _to_rfc3339(value)


def _start_time(
    normalized: dict[str, Any],
    notable: dict[str, Any],
    create_time: str,
    original_start_time: str = "",
) -> str:
    """Return the deduced start of the original event and keep it stable."""
    lifecycle = normalized.get("lifecycle") or {}

    value = _first_from(
        original_start_time,
        notable.get("firstTime"),
        notable.get("orig_time"),
        notable.get("_time"),
        lifecycle.get("create_time"),
        _rule_id_epoch(normalized),
    )

    return _to_rfc3339(
        value,
        fallback=create_time,
    )


def _end_time(
    normalized: dict[str, Any],
    notable: dict[str, Any],
) -> str:
    """Return the deduced end time from the closing lifecycle event."""
    trigger = normalized.get("trigger_event") or {}
    lifecycle = normalized.get("lifecycle") or {}

    return _to_rfc3339(
        _first_from(
            trigger.get("review_epoch"),
            trigger.get("review_time_iso"),
            lifecycle.get("update_time"),
            notable.get("lastTime"),
        )
    )


def _clean_empty_values(value: Any) -> Any:
    """Recursively remove empty optional values.

    Removed:
    - None
    - ""
    - []
    - {}

    Preserved:
    - 0
    - 0.0
    - False
    """
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}

        for key, item in value.items():
            cleaned_item = _clean_empty_values(item)

            if cleaned_item in (None, "", [], {}):
                continue

            cleaned[key] = cleaned_item

        return cleaned

    if isinstance(value, list):
        cleaned_list = []

        for item in value:
            cleaned_item = _clean_empty_values(item)

            if cleaned_item in (None, "", [], {}):
                continue

            cleaned_list.append(cleaned_item)

        return cleaned_list

    return value


def map_to_idmefv2(  # pylint: disable=too-many-locals
    normalized: dict[str, Any],
    config: Any = None,
    pred_id: str = "",
    original_start_time: str = "",
) -> dict[str, Any]:
    """Map normalized internal alert object to an IDMEFv2 V08 payload.

    When pred_id is provided, the generated payload is an update for the
    same logical alert and includes root PredID=[pred_id]. The generated
    ID remains new for every payload; PredID points to the immediately
    previous emitted IDMEFv2 payload for the same correlation key.
    """
    lifecycle = normalized.get("lifecycle") or {}
    technical = normalized.get("technical_alert") or {}
    trigger = normalized.get("trigger_event") or {}
    notable = technical.get("notable_best_candidate") or {}

    if not isinstance(notable, dict):
        notable = {}

    description = _description(
        normalized,
        notable,
    )

    status = _status_to_idmef(
        trigger.get("status") or lifecycle.get("status"),
        trigger.get("status_label")
        or lifecycle.get("status_name"),
    )

    categories = _category_from_context(
        technical=technical,
        notable=notable,
    )

    cause = _cause_from_category(categories)

    previous_id = str(pred_id or "").strip()

    create_time = _create_time(
        normalized,
        notable,
        is_update=bool(previous_id),
    )

    start_time = _start_time(
        normalized,
        notable,
        create_time=create_time,
        original_start_time=original_start_time,
    )

    end_time = _end_time(
        normalized,
        notable,
    )

    attachments = _build_attachments(
        technical,
        notable,
    )

    attachment_names = [
        str(item.get("Name"))
        for item in attachments
        if (
            isinstance(item, dict)
            and str(item.get("Name") or "").strip()
        )
    ]

    alert: dict[str, Any] = {
        "Version": IDMEFV2_VERSION,
        "ID": str(uuid.uuid4()),
        "OrganisationName": str(
            _config_get(
                config,
                "organisation_name",
                DEFAULT_ORGANISATION_NAME,
            )
        ),
        "OrganisationId": str(
            _config_get(
                config,
                "organisation_id",
                DEFAULT_ORGANISATION_ID,
            )
        ),
        "EntityName": str(
            _config_get(
                config,
                "entity_name",
                DEFAULT_ENTITY_NAME,
            )
        ),
        "EntityId": str(
            _config_get(
                config,
                "entity_id",
                DEFAULT_ENTITY_ID,
            )
        ),
        "Type": list(DEFAULT_TYPE),
        "Category": categories,
        "ext-Category": _ext_category_from_context(
            technical,
            notable,
        ),
        "Cause": cause,
        "Description": description,
        "Status": status,
        "Priority": _priority_from_context(
            lifecycle,
            technical,
            notable,
        ),
        "Confidence": _confidence_from_context(
            technical,
            notable,
        ),
        "Note": _compose_note(
            normalized,
            notable,
        ),
        "CreateTime": create_time,
        "StartTime": start_time,
        "ReportTime": _utc_now(),
        "Analyzer": _build_analyzer(
            config=config,
        ),
        "Sensor": _build_sensor(
            technical,
            notable,
        ),
        "AltNames": _build_alt_names(
            normalized,
            notable,
        ),
        "AltCategory": _build_alt_category(
            normalized,
        ),
        "Source": _build_source(
            technical,
            notable,
        ),
        "Target": _build_target(
            technical,
            notable,
            attachment_names,
        ),
        "Attachment": attachments,
    }

    if previous_id:
        alert["PredID"] = [previous_id]

    if status == ["Closed"]:
        alert["EndTime"] = end_time

    return _clean_empty_values(alert)


def to_pretty_json(alert: dict[str, Any]) -> str:
    """Return a stable pretty JSON representation, useful for logs/tests."""
    return json.dumps(alert, indent=2, ensure_ascii=False, sort_keys=True, default=str)
