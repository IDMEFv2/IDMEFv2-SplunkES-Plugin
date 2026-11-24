"""Static IDMEFv2 V09 validation.

This is intentionally NOT a full JSON Schema validation: it checks the
essential fields so incomplete or malformed alerts are never delivered.
Full schema validation is optional and lives in idmefv2_schema_validator.py.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID


IDMEFV2_VERSION = "2.D.V09"

VALID_TYPE = {"Cyber", "Physical", "Availability", "Hazards", "Combined"}
VALID_CAUSE = {"Normal", "Error", "Malicious", "Malfunction", "Hazard", "Unknown"}
VALID_STATUS = {"Event", "Incident", "Open", "Closed", "FalsePositive", "Obsolete"}
VALID_PRIORITY = {"Unknown", "Info", "Low", "Medium", "High", "Critical"}

INTERNAL_ONLY_TOP_LEVEL_FIELDS = {
    "source_model",
    "trigger_event",
    "join_keys",
    "lifecycle",
    "technical_alert",
    "raw",
}


@dataclass
class ValidationResult:
    """Outcome of a static IDMEFv2 payload validation pass."""

    is_valid: bool
    errors: list[str]
    warnings: list[str]


def _is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_non_empty_list(value: Any) -> bool:
    return isinstance(value, list) and len(value) > 0


def _is_uuid(value: Any) -> bool:
    if not _is_non_empty_string(value):
        return False

    try:
        UUID(str(value))
        return True
    except (TypeError, ValueError):
        return False


def _is_timestamp_like(value: Any) -> bool:
    """Minimal RFC3339-like timestamp check.

    This intentionally remains lightweight. Full validation will be delegated
    to the future JSON Schema validation step.
    """
    if not _is_non_empty_string(value):
        return False

    text = str(value).strip()

    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    try:
        datetime.fromisoformat(text)
        return True
    except ValueError:
        return False


def _validate_string_field(
    alert: dict[str, Any],
    field_name: str,
    errors: list[str],
) -> None:
    if not _is_non_empty_string(alert.get(field_name)):
        errors.append(f"Missing or empty required string field: {field_name}")


def _validate_list_field(
    alert: dict[str, Any],
    field_name: str,
    errors: list[str],
) -> None:
    if not _is_non_empty_list(alert.get(field_name)):
        errors.append(f"Missing or empty required list field: {field_name}")


def _validate_enum_list(
    alert: dict[str, Any],
    field_name: str,
    allowed_values: set[str],
    errors: list[str],
) -> None:
    value = alert.get(field_name)

    if not isinstance(value, list) or not value:
        errors.append(f"Missing or empty required list field: {field_name}")
        return

    invalid = [item for item in value if item not in allowed_values]

    if invalid:
        errors.append(
            f"Invalid value(s) for {field_name}: {invalid}. "
            f"Allowed values: {sorted(allowed_values)}"
        )


def _validate_enum_string(
    alert: dict[str, Any],
    field_name: str,
    allowed_values: set[str],
    errors: list[str],
) -> None:
    value = alert.get(field_name)

    if value not in allowed_values:
        errors.append(
            f"Invalid value for {field_name}: {value!r}. "
            f"Allowed values: {sorted(allowed_values)}"
        )


def _validate_endpoint_entities(
    alert: dict[str, Any],
    field_name: str,
    errors: list[str],
) -> None:
    value = alert.get(field_name)

    if value is None:
        return

    if not isinstance(value, list):
        errors.append(f"{field_name} must be a list when present.")
        return

    for index, item in enumerate(value):
        if not isinstance(item, dict):
            errors.append(f"{field_name}[{index}] must be an object.")
            continue

        if not _is_non_empty_string(item.get("ID")):
            errors.append(f"{field_name}[{index}].ID is required when {field_name} is present.")


def _validate_pred_id(alert: dict[str, Any], errors: list[str]) -> None:
    pred_id = alert.get("PredID")

    if pred_id is None:
        return

    if not isinstance(pred_id, list):
        errors.append("PredID must be a list of UUID strings when present.")
        return

    if not pred_id:
        errors.append("PredID must not be empty when present.")
        return

    invalid_pred_ids = [item for item in pred_id if not _is_uuid(item)]

    if invalid_pred_ids:
        errors.append(
            "PredID contains invalid UUID value(s): "
            f"{invalid_pred_ids}."
        )


def _validate_analyzer(alert: dict[str, Any], errors: list[str]) -> None:
    analyzer = alert.get("Analyzer")

    if not isinstance(analyzer, dict):
        errors.append("Missing or invalid Analyzer object.")
    elif not _is_non_empty_string(analyzer.get("Name")):
        errors.append("Missing or empty Analyzer.Name.")


def _validate_confidence(alert: dict[str, Any], errors: list[str]) -> None:
    confidence = alert.get("Confidence")

    if confidence is None:
        return

    try:
        confidence_value = float(confidence)
    except (TypeError, ValueError):
        errors.append("Confidence must be a number between 0 and 1 when present.")
        return

    if confidence_value < 0 or confidence_value > 1:
        errors.append("Confidence must be between 0 and 1 when present.")


def validate_idmefv2_static(alert: dict[str, Any]) -> ValidationResult:
    """Validate only the essential fields needed before delivery.

    This validator is deliberately conservative:
    if an essential field is missing, the alert must not be sent.
    """
    errors: list[str] = []
    warnings: list[str] = []

    if not isinstance(alert, dict):
        return ValidationResult(
            is_valid=False,
            errors=["Alert payload is not a JSON object."],
            warnings=warnings,
        )

    internal_fields = sorted(INTERNAL_ONLY_TOP_LEVEL_FIELDS.intersection(alert.keys()))
    if internal_fields:
        errors.append(
            "Payload appears to be the internal normalized object, not the final IDMEFv2 alert. "
            f"Internal fields found: {internal_fields}"
        )

    if alert.get("Version") != IDMEFV2_VERSION:
        errors.append(
            f"Invalid or missing Version. Expected {IDMEFV2_VERSION!r}, "
            f"got {alert.get('Version')!r}."
        )

    if not _is_uuid(alert.get("ID")):
        errors.append("Missing or invalid ID. Expected UUID string.")

    _validate_pred_id(alert, errors)

    if not _is_timestamp_like(alert.get("CreateTime")):
        errors.append("Missing or invalid CreateTime. Expected RFC3339-like timestamp.")

    _validate_analyzer(alert, errors)

    _validate_enum_list(alert, "Type", VALID_TYPE, errors)
    _validate_enum_list(alert, "Status", VALID_STATUS, errors)
    _validate_enum_string(alert, "Cause", VALID_CAUSE, errors)
    _validate_enum_string(alert, "Priority", VALID_PRIORITY, errors)

    _validate_list_field(alert, "Category", errors)
    _validate_string_field(alert, "Description", errors)

    _validate_confidence(alert, errors)

    _validate_endpoint_entities(alert, "Source", errors)
    _validate_endpoint_entities(alert, "Target", errors)

    return ValidationResult(
        is_valid=len(errors) == 0,
        errors=errors,
        warnings=warnings,
    )
