"""Configuration loader for the IDMEFv2 internal alert action."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class Config:
    enable_http_delivery: bool = False
    target_url: str = ""
    auth_type: str = "none"
    auth_token: str = ""
    auth_username: str = ""
    auth_password: str = ""
    verify_ssl: bool = True
    timeout_seconds: int = 30
    enable_notable_enrichment: bool = True
    notable_earliest: str = "-365d"
    minimum_notable_match_score: int = 70
    dedup_enabled: bool = True
    debug_dump_payload: bool = False

    organisation_name: str = "CHANGE-ME"
    organisation_id: str = "CHANGE-ME"
    entity_name: str = "CHANGE-ME"
    entity_id: str = "CHANGE-ME"
    analyzer_name: str = "Splunk ES"
    analyzer_model: str = "Splunk Enterprise Security"
    analyzer_hostname: str = ""

    server_uri: str = "https://localhost:8089"
    session_key: str = ""
    
def load_config(payload: dict[str, Any]) -> Config:
    cfg = payload.get("configuration") or {}

    if not isinstance(cfg, dict):
        cfg = {}

    def _bool(val: Any, default: bool) -> bool:
        if val is None:
            return default

        if isinstance(val, bool):
            return val

        normalized = str(val).strip().lower()

        if normalized in ("1", "true", "yes", "y", "on", "checked"):
            return True

        if normalized in ("0", "false", "no", "n", "off", "unchecked", ""):
            return False

        return default

    def _int(
        val: Any,
        default: int,
        minimum: int | None = None,
        maximum: int | None = None,
    ) -> int:
        try:
            parsed = int(str(val).strip())
        except (TypeError, ValueError):
            parsed = default

        if minimum is not None:
            parsed = max(parsed, minimum)

        if maximum is not None:
            parsed = min(parsed, maximum)

        return parsed

    return Config(
        enable_http_delivery=_bool(
            cfg.get("enable_http_delivery"),
            False,
        ),
        target_url=str(
            cfg.get("target_url") or ""
        ).strip(),
        auth_type=str(
            cfg.get("auth_type") or "none"
        ).strip().lower(),
        auth_token=str(
            cfg.get("auth_token") or ""
        ).strip(),
        auth_username=str(
            cfg.get("auth_username") or ""
        ).strip(),
        auth_password=str(
            cfg.get("auth_password") or ""
        ).strip(),
        verify_ssl=_bool(
            cfg.get("verify_ssl"),
            True,
        ),
        timeout_seconds=int(
            cfg.get("timeout_seconds") or 30
        ),
        enable_notable_enrichment=_bool(
            cfg.get("enable_notable_enrichment"),
            True,
        ),
        notable_earliest=str(
            cfg.get("notable_earliest") or "-365d"
        ).strip(),
        minimum_notable_match_score=int(
            cfg.get("minimum_notable_match_score") or 70
        ),
        dedup_enabled=_bool(
            cfg.get("dedup_enabled"),
            True,
        ),
        debug_dump_payload=_bool(
            cfg.get("debug_dump_payload"),
            False,
        ),

        organisation_name=str(
            cfg.get("organisation_name") or "CHANGE-ME"
        ).strip(),
        organisation_id=str(
            cfg.get("organisation_id") or "CHANGE-ME"
        ).strip(),
        entity_name=str(
            cfg.get("entity_name") or "CHANGE-ME"
        ).strip(),
        entity_id=str(
            cfg.get("entity_id") or "CHANGE-ME"
        ).strip(),
        analyzer_name=str(
            cfg.get("analyzer_name") or "Splunk ES"
        ).strip(),
        analyzer_model=str(
            cfg.get("analyzer_model") or "Splunk Enterprise Security"
        ).strip(),
        analyzer_hostname=str(
            cfg.get("analyzer_hostname") or ""
        ).strip(),

        server_uri=str(
            payload.get("server_uri")
            or payload.get("serverUri")
            or "https://localhost:8089"
        ).rstrip("/"),
        session_key=str(
            payload.get("session_key")
            or payload.get("sessionKey")
            or ""
        ).strip(),
    )