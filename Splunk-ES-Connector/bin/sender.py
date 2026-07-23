"""Sender: POST normalized alert to target_url or write it locally.

No IDMEFv2 conversion is implemented here.
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config_loader import Config
from splunk_rest_client import SplunkRestClient

logger = logging.getLogger(__name__)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _splunk_log_dir() -> Path:
    splunk_home = os.environ.get("SPLUNK_HOME", "/opt/splunk")
    return Path(splunk_home) / "var" / "log" / "splunk"


def _safe_filename_fragment(value: str, fallback: str = "unknown") -> str:
    """Return a filesystem-safe filename fragment for event-specific JSON files."""
    text = str(value or "").strip() or fallback
    text = re.sub(r"[^A-Za-z0-9._-]+", "_", text)
    return text[:180] or fallback


def _write_json_atomic(path: Path, data: Any) -> None:
    """Write JSON atomically enough for Splunk local debug artifacts."""
    path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=str(path.parent),
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    ) as tmp_file:
        tmp_path = Path(tmp_file.name)
        json.dump(
            data,
            tmp_file,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            default=str,
        )
        tmp_file.write("\n")

    tmp_path.replace(path)


def _append_payload_history(history_path: Path, entry: dict[str, Any]) -> None:
    """Append an entry to a valid JSON array document.

    This is intended for local dry-run/debug use. If an existing history file is
    corrupt or not a JSON list, preserve it with a .corrupt timestamp suffix and
    start a new history document rather than failing the alert action.
    """
    history: list[dict[str, Any]] = []

    if history_path.exists() and history_path.stat().st_size > 0:
        try:
            existing = json.loads(history_path.read_text(encoding="utf-8"))
            if isinstance(existing, list):
                history = [item for item in existing if isinstance(item, dict)]
            else:
                raise ValueError("history JSON root is not a list")
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            corrupt_path = history_path.with_suffix(
                f".corrupt.{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
            )
            logger.warning(
                "Existing local IDMEFv2 payload history is invalid; preserving it as %s. error=%s",
                corrupt_path,
                exc,
            )
            try:
                history_path.replace(corrupt_path)
            except OSError as replace_exc:
                logger.warning(
                    "Could not preserve invalid local IDMEFv2 payload history path=%s error=%s",
                    history_path,
                    replace_exc,
                )
            history = []

    history.append(entry)
    _write_json_atomic(history_path, history)


def _write_local_payload_documents(payload: dict[str, Any], event_uid: str) -> dict[str, str]:
    """Write the final IDMEFv2 payload as local JSON documents.

    Files written:
    - idmefv2_generated_payload_latest.json: raw latest IDMEFv2 payload.
    - idmefv2_generated_payload_<event_uid>.json: raw event-specific payload.
    - idmefv2_generated_payloads.json: valid JSON array history with metadata.
    """
    log_dir = _splunk_log_dir()
    generated_at = _utc_now()
    safe_event_uid = _safe_filename_fragment(event_uid, fallback="event")

    latest_path = log_dir / "idmefv2_generated_payload_latest.json"
    event_path = log_dir / f"idmefv2_generated_payload_{safe_event_uid}.json"
    history_path = log_dir / "idmefv2_generated_payloads.json"

    history_entry = {
        "event_uid": event_uid,
        "generated_at": generated_at,
        "payload_file": str(event_path),
        "payload": payload,
    }

    _write_json_atomic(latest_path, payload)
    _write_json_atomic(event_path, payload)
    _append_payload_history(history_path, history_entry)

    return {
        "latest": str(latest_path),
        "event": str(event_path),
        "history": str(history_path),
    }


def send_or_log(  # pylint: disable=too-many-return-statements
    payload: dict[str, Any],
    config: Config,
    client: SplunkRestClient,
    event_uid: str = "",
) -> bool:
    """Send the final IDMEFv2 payload or write it locally.

    Behavior:
    - enable_http_delivery = false:
        write the final IDMEFv2 payload to local JSON files.

    - enable_http_delivery = true and target_url is empty:
        log an error and return False.

    - enable_http_delivery = true and target_url is set:
        POST the payload to the configured receiver and log the complete
        outcome without exposing authentication secrets.
    """
    app_logger = logging.getLogger(
        "idmefv2_internal_alert_app"
    )

    event_uid = str(event_uid or "").strip()
    target_url = str(config.target_url or "").strip()

    if not config.enable_http_delivery:
        app_logger.info(
            "HTTP delivery disabled. "
            "Writing final IDMEFv2 payload locally. "
            "event_uid=%s",
            event_uid,
        )

        try:
            paths = _write_local_payload_documents(
                payload,
                event_uid,
            )
        except Exception as exc:  # pylint: disable=broad-exception-caught
            app_logger.exception(
                "Could not write local IDMEFv2 payload "
                "JSON documents. "
                "event_uid=%s exception_type=%s error=%r",
                event_uid,
                type(exc).__name__,
                exc,
            )
            return False

        app_logger.info(
            "Final IDMEFv2 payload written locally. "
            "event_uid=%s latest=%s "
            "event_file=%s history=%s",
            event_uid,
            paths["latest"],
            paths["event"],
            paths["history"],
        )

        app_logger.debug(
            "Generated IDMEFv2 payload "
            "event_uid=%s payload=%s",
            event_uid,
            json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                default=str,
            ),
        )

        return True

    if not target_url:
        app_logger.error(
            "HTTP delivery is enabled but target_url "
            "is empty. event_uid=%s",
            event_uid,
        )
        return False

    app_logger.info(
        "Sending IDMEFv2 payload. "
        "event_uid=%s target_url=%s "
        "auth_type=%s verify_ssl=%s "
        "timeout_seconds=%s",
        event_uid,
        target_url,
        str(config.auth_type or "none"),
        bool(config.verify_ssl),
        config.timeout_seconds,
    )

    try:
        status_code, response_body = client.post_json(
            url=target_url,
            payload=payload,
            config=config,
        )

    except Exception as exc:  # pylint: disable=broad-exception-caught
        app_logger.exception(
            "Failed to send IDMEFv2 payload. "
            "event_uid=%s target_url=%s "
            "exception_type=%s error=%r",
            event_uid,
            target_url,
            type(exc).__name__,
            exc,
        )
        return False

    try:
        status_code = int(status_code)
    except (TypeError, ValueError):
        app_logger.error(
            "IDMEFv2 receiver returned an invalid "
            "HTTP status code. "
            "event_uid=%s target_url=%s "
            "status_code=%r response=%r",
            event_uid,
            target_url,
            status_code,
            response_body,
        )
        return False

    response_text = str(
        response_body
        if response_body is not None
        else ""
    )

    # Avoid letting a very large response body flood the log.
    max_response_length = 4000

    if len(response_text) > max_response_length:
        response_for_log = (
            response_text[:max_response_length]
            + "...[response truncated]"
        )
    else:
        response_for_log = response_text

    if 200 <= status_code < 300:
        app_logger.info(
            "IDMEFv2 payload sent successfully. "
            "event_uid=%s target_url=%s "
            "status_code=%s response=%r",
            event_uid,
            target_url,
            status_code,
            response_for_log,
        )
        return True

    app_logger.error(
        "IDMEFv2 payload delivery failed. "
        "event_uid=%s target_url=%s "
        "status_code=%s response=%r",
        event_uid,
        target_url,
        status_code,
        response_for_log,
    )

    return False
