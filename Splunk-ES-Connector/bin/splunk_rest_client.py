"""Splunk REST client for local API and Search REST API calls.

Inside Splunk, the app uses the session key from the alert action payload.
All requests target the local Splunk instance (https://localhost:8089).
"""

from __future__ import annotations

import json
import logging
import ssl
import base64
from typing import Any
from urllib import error, parse, request

logger = logging.getLogger(__name__)


class SplunkRestClient:
    def __init__(
        self,
        server_uri: str,
        session_key: str,
        verify_ssl: bool = False,
        timeout: int = 30,
    ) -> None:
        self.server_uri = server_uri.rstrip("/")
        self.session_key = session_key
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._ctx = ssl.create_default_context()
        if not verify_ssl:
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE

    def _auth_header(self) -> str:
        return f"Splunk {self.session_key}"

    def _url(self, path: str) -> str:
        return f"{self.server_uri}/{path.lstrip('/')}"

    def get_json(self, path: str, params: dict[str, Any] | None = None) -> Any:
        url = self._url(path)
        if params:
            filtered = {k: v for k, v in params.items() if v is not None}
            url = f"{url}?{parse.urlencode(filtered)}"
        req = request.Request(
            url,
            headers={"Authorization": self._auth_header(), "Accept": "application/json"},
        )
        try:
            with request.urlopen(req, timeout=self.timeout, context=self._ctx) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
        except error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP {exc.code} GET {url}: {body}") from exc
        except error.URLError as exc:
            raise RuntimeError(f"Connection error GET {url}: {exc}") from exc
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Invalid JSON from GET {url}: {exc}") from exc

    def search_export(self, spl: str) -> list[dict[str, Any]]:
        """POST to /services/search/jobs/export and parse NDJSON result rows."""
        url = self._url("/services/search/jobs/export")
        body = parse.urlencode({"search": spl, "output_mode": "json"}).encode("utf-8")

        req = request.Request(
            url,
            data=body,
            headers={
                "Authorization": self._auth_header(),
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            method="POST",
        )

        try:
            with request.urlopen(req, timeout=self.timeout, context=self._ctx) as resp:
                raw = resp.read().decode("utf-8", errors="replace")

        except error.HTTPError as exc:
            body_resp = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP {exc.code} POST search/export: {body_resp}") from exc

        except error.URLError as exc:
            raise RuntimeError(f"Connection error POST search/export: {exc}") from exc

        results: list[dict[str, Any]] = []

        for line in raw.splitlines():
            line = line.strip()

            if not line:
                continue

            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                logger.debug("Ignoring non-JSON search/export line: %s", line[:500])
                continue

            if not isinstance(obj, dict):
                continue

            if "messages" in obj and obj["messages"]:
                logger.debug("search/export messages: %s", obj["messages"])

            result = obj.get("result")

            if isinstance(result, dict):
                results.append(result)

        return results

    def post_json(
        self,
        url: str,
        payload: dict[str, Any],
        auth_type: str = "none",
        auth_token: str = "",
        auth_username: str = "",
        auth_password: str = "",
        verify_ssl: bool | None = None,
        timeout_seconds: int | None = None,
    ) -> tuple[int, Any]:
        """POST JSON to an arbitrary external URL."""
        body = json.dumps(payload, default=str).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "Accept": "*/*",
        }

        normalized_auth_type = str(auth_type or "none").strip().lower()

        if normalized_auth_type == "bearer" and auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        elif normalized_auth_type == "basic" and auth_username:
            raw_credentials = f"{auth_username}:{auth_password}".encode("utf-8")
            encoded_credentials = base64.b64encode(raw_credentials).decode("ascii")
            headers["Authorization"] = f"Basic {encoded_credentials}"

        use_ssl = verify_ssl if verify_ssl is not None else self.verify_ssl
        timeout = timeout_seconds if timeout_seconds is not None else self.timeout

        ctx = ssl.create_default_context()
        if not use_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        req = request.Request(
            url,
            data=body,
            headers=headers,
            method="POST",
        )

        try:
            with request.urlopen(req, timeout=timeout, context=ctx) as resp:
                raw = resp.read().decode("utf-8", errors="replace")

                if not raw.strip():
                    return int(resp.status), {}

                try:
                    return int(resp.status), json.loads(raw)
                except json.JSONDecodeError:
                    return int(resp.status), raw

        except error.HTTPError as exc:
            body_resp = exc.read().decode("utf-8", errors="replace")
            return exc.code, body_resp

        except error.URLError as exc:
            raise RuntimeError(f"Connection error POST {url}: {exc}") from exc
