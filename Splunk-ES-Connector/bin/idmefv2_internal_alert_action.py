#!/usr/bin/env python3
"""Splunk custom alert action entrypoint: IDMEFv2 internal alert processing.

Reads the Splunk alert action JSON payload from stdin, coordinates all
service modules, builds normalized alert objects and sends or logs them.
"""

from __future__ import annotations

import os
import sys
import uuid
import copy
import json
from pathlib import Path
from typing import Any

# Ensure bin/ is on sys.path (required for Splunk alert action execution)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# pylint: disable=wrong-import-position
# These local modules only become importable after the sys.path.insert above,
# so they cannot be moved to the top of the file.
from action_payload import (
    extract_results,
    group_by_rule_id,
    read_stdin_json,
    validate_trigger_events,
)
from config_loader import load_config
from incident_review_service import get_history
from logging_utils import get_logger
from mission_control_client import find_investigation_by_rule_id
from notable_search_service import find_candidates
from normalizer import attach_trigger_event, build_alert_context
from sender import send_or_log
from idmefv2_mapper import map_to_idmefv2
from idmefv2_schema_validator import describe_validation_mode, validate_idmefv2
from splunk_rest_client import SplunkRestClient
from state_store import StateStore
from alert_state_store import AlertStateStore

APP_FOLDER_NAME = "Splunk-ES-Connector"


def _lookups_dir() -> str:
    splunk_home = os.environ.get("SPLUNK_HOME", "/opt/splunk")
    return os.path.join(splunk_home, "etc", "apps", APP_FOLDER_NAME, "lookups")


def dump_debug_payload(payload: dict[str, Any]) -> None:
    """Write a redacted copy of the Splunk alert action payload for debugging."""
    splunk_home = os.environ.get("SPLUNK_HOME", "/opt/splunk")
    debug_path = Path(splunk_home) / "var" / "log" / "splunk" / "idmefv2_action_payload_debug.json"

    safe_payload = copy.deepcopy(payload)

    sensitive_keys = {
        "session_key",
        "sessionKey",
        "auth_token",
        "authToken",
        "auth_password",
        "authPassword",
        "password",
        "token",
    }

    def redact(obj: Any) -> Any:
        if isinstance(obj, dict):
            return {
                key: "***REDACTED***" if key in sensitive_keys else redact(value)
                for key, value in obj.items()
            }

        if isinstance(obj, list):
            return [redact(item) for item in obj]

        return obj

    safe_payload = redact(safe_payload)

    debug_path.write_text(
        json.dumps(safe_payload, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )


def main() -> int:  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
    """Entry point: read the alert action payload from stdin and process it."""
    run_id = str(uuid.uuid4())[:8]

    try:
        payload = read_stdin_json()
    except RuntimeError as exc:
        sys.stderr.write(
            f"FATAL: could not read stdin payload: {exc}\n"
        )
        return 1

    config = load_config(payload)
    log_level = 10 if os.environ.get("DEBUG") else 20
    logger = get_logger(
        run_id=run_id,
        level=log_level,
    )

    if config.debug_dump_payload:
        try:
            dump_debug_payload(payload)
            logger.info(
                "Debug payload dumped successfully."
            )
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.warning(
                "Could not dump debug payload: %s",
                exc,
            )

    logger.info(
        "Alert action started run_id=%s",
        run_id,
    )

    full_validation_active, validation_mode_message = describe_validation_mode()
    if full_validation_active:
        logger.info(validation_mode_message)
    else:
        logger.warning(validation_mode_message)

    trigger_events = extract_results(payload)

    if not trigger_events:
        logger.info(
            "No trigger events in payload. run_id=%s",
            run_id,
        )
        return 0

    valid_events = validate_trigger_events(
        trigger_events
    )

    logger.info(
        "Trigger events total=%d valid=%d",
        len(trigger_events),
        len(valid_events),
    )

    if not valid_events:
        logger.warning(
            "No valid trigger events after validation. "
            "run_id=%s",
            run_id,
        )
        return 0

    if not config.session_key:
        logger.error(
            "Missing session_key in alert action payload. "
            "Cannot call Splunk REST APIs."
        )
        return 1

    # Internal Splunk REST calls usually target localhost:8089,
    # which often uses a self-signed certificate.
    client = SplunkRestClient(
        server_uri=config.server_uri,
        session_key=config.session_key,
        verify_ssl=False,
        timeout=config.timeout_seconds,
    )

    lookups_dir = _lookups_dir()

    store = StateStore(
        os.path.join(
            lookups_dir,
            "idmefv2_processed_events.csv",
        )
    )

    alert_state_store = AlertStateStore(
        os.path.join(
            lookups_dir,
            "idmefv2_alert_state.csv",
        )
    )

    grouped = group_by_rule_id(valid_events)

    logger.info(
        "Unique rule_id(s) to process: %d",
        len(grouped),
    )

    total_sent = 0
    total_skipped = 0
    total_failed = 0

    for rule_id, events in grouped.items():
        if config.dedup_enabled:
            unprocessed = [
                event
                for event in events
                if not store.is_processed(
                    str(event.get("event_uid", ""))
                )
            ]
        else:
            unprocessed = list(events)

        if not unprocessed:
            logger.debug(
                "All events already processed "
                "for rule_id=%s",
                rule_id,
            )

            total_skipped += len(events)
            continue

        logger.info(
            "rule_id=%s events=%d unprocessed=%d",
            rule_id,
            len(events),
            len(unprocessed),
        )

        investigation = find_investigation_by_rule_id(
            client,
            rule_id,
        )

        if investigation:
            logger.info(
                "Matched investigation %s for rule_id=%s",
                investigation.get("investigation_id"),
                rule_id,
            )
        else:
            logger.warning(
                "No investigation found for rule_id=%s; "
                "continuing with empty context",
                rule_id,
            )

        history = get_history(
            client,
            rule_id,
        )

        logger.debug(
            "History records for rule_id=%s: %d",
            rule_id,
            len(history),
        )

        notable_candidates = [
            {
                **event,
                "match_score": 1000,
            }
            for event in events
            if str(
                event.get("event_type") or ""
            ).strip() == "finding_created"
        ]

        if notable_candidates:
            logger.info(
                "Using %d inline finding_created row(s) "
                "for rule_id=%s",
                len(notable_candidates),
                rule_id,
            )

        if config.enable_notable_enrichment:
            fallback_candidates = find_candidates(
                client=client,
                rule_id=rule_id,
                investigation=investigation,
                earliest=config.notable_earliest,
                min_score=(
                    config.minimum_notable_match_score
                ),
            )

            notable_candidates.extend(
                fallback_candidates
            )

            logger.debug(
                "Notable candidates for rule_id=%s: "
                "inline=%d fallback=%d total=%d",
                rule_id,
                (
                    len(notable_candidates)
                    - len(fallback_candidates)
                ),
                len(fallback_candidates),
                len(notable_candidates),
            )

        base_context = build_alert_context(
            rule_id=rule_id,
            investigation=investigation,
            history=history,
            notable_candidates=notable_candidates,
        )

        sorted_events = sorted(
            unprocessed,
            key=lambda event: float(
                event.get("review_epoch") or 0
            ),
        )

        for event in sorted_events:
            event_uid = str(
                event.get("event_uid") or ""
            )

            correlation_key = str(
                rule_id
                or event.get("rule_id")
                or ""
            ).strip()

            previous_id = (
                alert_state_store.get_previous_id(
                    correlation_key
                )
            )

            original_start_time = (
                alert_state_store.get_start_time(
                    correlation_key
                )
            )

            if previous_id:
                logger.info(
                    "Preparing IDMEFv2 update "
                    "event_uid=%s correlation_key=%s "
                    "PredID=%s",
                    event_uid,
                    correlation_key,
                    previous_id,
                )
            else:
                logger.info(
                    "Preparing first IDMEFv2 payload "
                    "event_uid=%s correlation_key=%s",
                    event_uid,
                    correlation_key,
                )

            normalized = attach_trigger_event(
                base_context,
                event,
            )

            try:
                idmefv2_alert = map_to_idmefv2(
                    normalized=normalized,
                    config=config,
                    pred_id=previous_id,
                    original_start_time=(
                        original_start_time
                    ),
                )

            except Exception as exc:  # pylint: disable=broad-exception-caught
                logger.exception(
                    "IDMEFv2 mapping failed "
                    "event_uid=%s rule_id=%s: %s",
                    event_uid,
                    rule_id,
                    exc,
                )

                total_failed += 1
                continue

            validation = validate_idmefv2(
                idmefv2_alert
            )

            for warning in validation.warnings:
                logger.warning(
                    "IDMEFv2 validation warning "
                    "event_uid=%s: %s",
                    event_uid,
                    warning,
                )

            if not validation.is_valid:
                logger.error(
                    "IDMEFv2 validation failed "
                    "event_uid=%s rule_id=%s errors=%s",
                    event_uid,
                    rule_id,
                    validation.errors,
                )

                total_failed += 1
                continue

            success = send_or_log(
                payload=idmefv2_alert,
                config=config,
                client=client,
                event_uid=event_uid,
            )

            if success:
                current_id = str(
                    idmefv2_alert.get("ID") or ""
                ).strip()

                state_updated = (
                    alert_state_store.upsert_success(
                        correlation_key=correlation_key,
                        current_id=current_id,
                        event_uid=event_uid,
                        status=str(
                            event.get("status") or ""
                        ),
                        review_epoch=str(
                            event.get("review_epoch") or ""
                        ),
                        start_time=str(
                            idmefv2_alert.get(
                                "StartTime"
                            )
                            or ""
                        ),
                    )
                )

                if not state_updated:
                    logger.error(
                        "Alert sent/logged but alert state "
                        "could not be persisted. "
                        "event_uid=%s correlation_key=%s "
                        "idmefv2_id=%s",
                        event_uid,
                        correlation_key,
                        current_id,
                    )

                    total_failed += 1
                    continue

                marked = store.mark_processed(
                    event_uid=event_uid,
                    rule_id=rule_id,
                    status=str(
                        event.get("status") or ""
                    ),
                    review_epoch=str(
                        event.get("review_epoch") or ""
                    ),
                    result="ok",
                )

                if marked:
                    total_sent += 1
                else:
                    logger.warning(
                        "Alert sent/logged but event_uid "
                        "could not be persisted. "
                        "event_uid=%s",
                        event_uid,
                    )

                    total_failed += 1
            else:
                total_failed += 1

    logger.info(
        "Alert action complete "
        "run_id=%s sent=%d skipped=%d failed=%d",
        run_id,
        total_sent,
        total_skipped,
        total_failed,
    )

    return 0 if total_failed == 0 else 1

if __name__ == "__main__":
    raise SystemExit(main())
