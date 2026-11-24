"""Optional full JSON Schema validation of IDMEFv2 alerts.

The jsonschema library is not bundled: it is installed on demand into
bin/lib (see install-optional-deps.sh). Without it, only the static
validation of idmefv2_validator.py runs.
"""

from __future__ import annotations

import json
import os
import sys
from importlib import metadata
from typing import Any

from idmefv2_validator import (
    INTERNAL_ONLY_TOP_LEVEL_FIELDS,
    ValidationResult,
    validate_idmefv2_static,
)

BIN_DIR = os.path.dirname(os.path.abspath(__file__))
LIB_DIR = os.path.join(BIN_DIR, "lib")
SCHEMA_PATH = os.path.join(BIN_DIR, "schemas", "V09.json")
MAX_REPORTED_ERRORS = 20
README_HINT = (
    "See the README, section 'Optional full schema validation', "
    "to enable full validation."
)

_backend: tuple[Any, str] | None = None  # pylint: disable=invalid-name


def _load_backend() -> tuple[Any, str]:
    """Return (schema validator or None, status message); cached per process."""
    global _backend  # pylint: disable=global-statement
    if _backend is not None:
        return _backend

    if os.path.isdir(LIB_DIR) and LIB_DIR not in sys.path:
        sys.path.insert(0, LIB_DIR)

    try:
        import jsonschema  # pylint: disable=import-outside-toplevel
    except ImportError:
        _backend = (
            None,
            "Only static IDMEFv2 validation is active: jsonschema is not "
            f"installed in bin/lib. {README_HINT}",
        )
        return _backend
    except Exception as exc:  # pylint: disable=broad-exception-caught
        _backend = (
            None,
            "Only static IDMEFv2 validation is active: jsonschema could not "
            f"be imported ({exc}). {README_HINT}",
        )
        return _backend

    try:
        with open(SCHEMA_PATH, encoding="utf-8") as schema_file:
            schema = json.load(schema_file)
        validator_class = jsonschema.validators.validator_for(
            schema, default=jsonschema.Draft4Validator
        )
        validator_class.check_schema(schema)
        validator = validator_class(schema, format_checker=jsonschema.FormatChecker())
    except Exception as exc:  # pylint: disable=broad-exception-caught
        _backend = (
            None,
            "Only static IDMEFv2 validation is active: the schema "
            f"{SCHEMA_PATH} could not be loaded ({exc}). {README_HINT}",
        )
        return _backend

    try:
        library_version = metadata.version("jsonschema")
    except metadata.PackageNotFoundError:
        library_version = "unknown version"

    _backend = (
        validator,
        f"Full V09 JSON Schema validation is active (jsonschema {library_version}).",
    )
    return _backend


def describe_validation_mode() -> tuple[bool, str]:
    """Return (full validation active, message to log once per run)."""
    validator, message = _load_backend()
    return validator is not None, message


def _format_schema_errors(validator: Any, alert: dict[str, Any]) -> list[str]:
    schema_errors = sorted(
        validator.iter_errors(alert),
        key=lambda error: [str(part) for part in error.absolute_path],
    )
    messages = []
    for error in schema_errors[:MAX_REPORTED_ERRORS]:
        location = "/".join(str(part) for part in error.absolute_path) or "(root)"
        messages.append(f"Schema: {location}: {error.message}")
    if len(schema_errors) > MAX_REPORTED_ERRORS:
        messages.append(
            f"Schema: {len(schema_errors) - MAX_REPORTED_ERRORS} more errors not shown."
        )
    return messages


def validate_idmefv2(alert: dict[str, Any]) -> ValidationResult:
    """Static validation plus full schema validation when jsonschema is available.

    A failure of the library itself (not of the data) never blocks the alert:
    the static result is returned with a warning.
    """
    result = validate_idmefv2_static(alert)
    validator, _ = _load_backend()

    if validator is None or not isinstance(alert, dict):
        return result
    if INTERNAL_ONLY_TOP_LEVEL_FIELDS.intersection(alert.keys()):
        return result

    try:
        schema_errors = _format_schema_errors(validator, alert)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        result.warnings.append(
            f"Schema validation could not be completed, static result used: {exc}"
        )
        return result

    result.errors.extend(schema_errors)
    result.is_valid = not result.errors
    return result
