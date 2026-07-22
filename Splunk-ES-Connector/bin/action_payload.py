"""Parses Splunk custom alert action payload from stdin."""

from __future__ import annotations

import csv
import gzip
import io
import json
import logging
import sys
from pathlib import Path
from typing import Any

REQUIRED_FIELDS = ("event_uid", "rule_id", "status", "review_epoch")

logger = logging.getLogger(__name__)


def read_stdin_json() -> dict[str, Any]:
    """Read the Splunk custom alert action JSON payload from stdin."""
    raw = sys.stdin.read()

    if not raw.strip():
        raise RuntimeError("Empty stdin payload received from Splunk alert action.")

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Failed to parse stdin JSON: {exc}") from exc

    if not isinstance(payload, dict):
        raise RuntimeError(f"Expected stdin JSON object, got {type(payload).__name__}.")

    return payload


def read_results_file(path: str) -> list[dict[str, Any]]:
    """
    Read Splunk search results from a results file.

    Supported formats:
    - gzipped CSV;
    - plain CSV;
    - JSON array;
    - JSON object with result/results;
    - JSONL where each line may contain a Splunk jobs/export object with result.
    """
    path_value = str(path or "").strip()
    if not path_value:
        return []

    file_path = Path(path_value)

    if not file_path.exists():
        logger.warning("results_file does not exist: %s", file_path)
        return []

    try:
        text = _read_text_file(file_path)
        return _parse_results_text(text, source=str(file_path))
    except Exception as exc:
        logger.warning("Could not read results_file %s: %s", file_path, exc)
        return []


def extract_results(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Extract trigger event rows from the alert action payload.

    Priority:
    1. payload["results_file"] -> preferred because it may contain all search rows.
    2. payload["results"]      -> inline list/dict, if present.
    3. payload["result"]       -> single result dict, compatible with the old app.
    """
    rows: list[dict[str, Any]] = []

    results_file = str(payload.get("results_file") or "").strip()
    if results_file:
        rows = read_results_file(results_file)
        if rows:
            logger.debug("Extracted %d rows from results_file.", len(rows))
            return _deduplicate_rows(rows)

        logger.warning(
            "results_file was present but no rows could be extracted: %s",
            results_file,
        )

    inline_rows = _extract_inline_results(payload)
    if inline_rows:
        logger.debug("Extracted %d inline result rows from payload.", len(inline_rows))
        return _deduplicate_rows(inline_rows)

    logger.warning(
        "No search results found in alert action payload. "
        "Expected results_file, results, or result."
    )
    return []


def validate_trigger_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return only events with all required fields present and non-empty."""
    valid: list[dict[str, Any]] = []

    for ev in events:
        missing = [field for field in REQUIRED_FIELDS if not str(ev.get(field, "")).strip()]

        if missing:
            logger.debug("Skipping event missing fields %s: %s", missing, ev)
            continue

        valid.append(ev)

    return valid


def group_by_rule_id(events: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Group valid trigger events by rule_id."""
    groups: dict[str, list[dict[str, Any]]] = {}

    for ev in events:
        rule_id = str(ev.get("rule_id", "")).strip()

        if not rule_id:
            logger.debug("Skipping event without rule_id during grouping: %s", ev)
            continue

        groups.setdefault(rule_id, []).append(ev)

    return groups


def _read_text_file(file_path: Path) -> str:
    """Read either gzip-compressed or plain text file."""
    is_gzip = False

    try:
        with file_path.open("rb") as fh:
            magic = fh.read(2)
            is_gzip = magic == b"\x1f\x8b"
    except Exception:
        is_gzip = file_path.suffix.lower() == ".gz"

    if is_gzip:
        with gzip.open(file_path, "rt", encoding="utf-8", errors="replace") as fh:
            return fh.read()

    with file_path.open("rt", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _parse_results_text(text: str, source: str = "<results_file>") -> list[dict[str, Any]]:
    """Parse results text as JSON, JSONL, or CSV."""
    stripped = text.strip()

    if not stripped:
        return []

    # JSON array/object
    if stripped.startswith("[") or stripped.startswith("{"):
        try:
            parsed = json.loads(stripped)
            return _rows_from_json_value(parsed)
        except json.JSONDecodeError:
            # It may still be JSONL.
            pass

    # JSONL, for example jobs/export output:
    # {"preview":false,"offset":0,"result":{...}}
    jsonl_rows = _parse_jsonl(stripped)
    if jsonl_rows:
        return jsonl_rows

    # Fallback: CSV
    try:
        reader = csv.DictReader(io.StringIO(text))
        rows = [dict(row) for row in reader if row]
        return rows
    except Exception as exc:
        logger.warning("Could not parse %s as CSV: %s", source, exc)
        return []


def _parse_jsonl(text: str) -> list[dict[str, Any]]:
    """Parse JSONL and extract Splunk result objects when present."""
    rows: list[dict[str, Any]] = []

    for line in text.splitlines():
        line = line.strip()

        if not line:
            continue

        if not line.startswith("{"):
            return []

        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return []

        rows.extend(_rows_from_json_value(obj))

    return rows


def _extract_inline_results(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract inline result/results from the Splunk payload."""
    rows: list[dict[str, Any]] = []

    results = payload.get("results")
    if isinstance(results, list):
        rows.extend(item for item in results if isinstance(item, dict))
    elif isinstance(results, dict):
        rows.append(results)

    result = payload.get("result")
    if isinstance(result, dict) and result:
        rows.append(result)

    return rows


def _rows_from_json_value(value: Any) -> list[dict[str, Any]]:
    """
    Convert a JSON value into result rows.

    Handles:
    - [{...}, {...}]
    - {"result": {...}}
    - {"results": [{...}]}
    - plain {"event_uid": "...", "rule_id": "..."}
    """
    rows: list[dict[str, Any]] = []

    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                rows.extend(_rows_from_json_value(item))
        return rows

    if not isinstance(value, dict):
        return rows

    result = value.get("result")
    if isinstance(result, dict) and result:
        rows.append(result)

    results = value.get("results")
    if isinstance(results, list):
        rows.extend(item for item in results if isinstance(item, dict))
    elif isinstance(results, dict):
        rows.append(results)

    # If this object itself looks like a search result row, keep it.
    if _looks_like_trigger_row(value):
        rows.append(value)

    return rows


def _looks_like_trigger_row(value: dict[str, Any]) -> bool:
    """Return true if a dict looks like one of our scheduled-search result rows."""
    return any(field in value for field in REQUIRED_FIELDS)


def _deduplicate_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Remove duplicate rows while preserving order.

    Prefer event_uid when available. Otherwise use a stable JSON representation.
    """
    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()

    for row in rows:
        if not isinstance(row, dict):
            continue

        event_uid = str(row.get("event_uid") or "").strip()

        if event_uid:
            key = f"event_uid::{event_uid}"
        else:
            try:
                key = json.dumps(row, sort_keys=True, ensure_ascii=False)
            except TypeError:
                key = str(row)

        if key in seen:
            continue

        seen.add(key)
        deduped.append(row)

    return deduped