"""CSV-based state store for IDMEFv2 alert update chaining.

Persisted in: lookups/idmefv2_alert_state.csv

Purpose:
- correlate lifecycle updates for the same logical Splunk ES alert/finding;
- remember the last IDMEFv2 payload ID emitted for that alert;
- allow the next payload for the same alert to include root PredID=[previous_id].

This is intentionally separate from state_store.py:
- state_store.py tracks processed lifecycle event_uid values;
- alert_state_store.py tracks the latest emitted IDMEFv2 ID per logical alert.
"""

from __future__ import annotations

import csv
import logging
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

COLUMNS = [
    "correlation_key",
    "last_id",
    "last_event_uid",
    "last_status",
    "last_review_epoch",
    "start_time",
    "created_at",
    "updated_at",
]


@dataclass(frozen=True)
class AlertStateRecord:
    correlation_key: str
    last_id: str
    last_event_uid: str
    last_status: str
    last_review_epoch: str
    start_time: str
    created_at: str
    updated_at: str


class AlertStateStore:
    """Store latest emitted IDMEFv2 ID for each logical Splunk alert."""

    def __init__(self, csv_path: str) -> None:
        self.csv_path = csv_path
        self._records: dict[str, AlertStateRecord] = {}
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self.csv_path):
            return

        try:
            with open(self.csv_path, "r", encoding="utf-8", newline="") as fh:
                reader = csv.DictReader(fh)

                for row in reader:
                    correlation_key = str(
                        row.get("correlation_key") or ""
                    ).strip()

                    if not correlation_key:
                        continue

                    self._records[correlation_key] = AlertStateRecord(
                        correlation_key=correlation_key,
                        last_id=str(
                            row.get("last_id") or ""
                        ).strip(),
                        last_event_uid=str(
                            row.get("last_event_uid") or ""
                        ).strip(),
                        last_status=str(
                            row.get("last_status") or ""
                        ).strip(),
                        last_review_epoch=str(
                            row.get("last_review_epoch") or ""
                        ).strip(),
                        start_time=str(
                            row.get("start_time") or ""
                        ).strip(),
                        created_at=str(
                            row.get("created_at") or ""
                        ).strip(),
                        updated_at=str(
                            row.get("updated_at") or ""
                        ).strip(),
                    )

            logger.debug(
                "Loaded %d alert state record(s) from %s",
                len(self._records),
                self.csv_path,
            )

        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Could not load alert state store from %s: %s",
                self.csv_path,
                exc,
            )

    def get_previous_id(self, correlation_key: str) -> str:
        """Return the latest IDMEFv2 ID emitted for this correlation key."""
        key = str(correlation_key or "").strip()

        if not key:
            return ""

        record = self._records.get(key)
        return record.last_id if record else ""
    
    def get_start_time(self, correlation_key: str) -> str:
        """Return the original IDMEFv2 StartTime stored for this alert."""
        key = str(correlation_key or "").strip()

        if not key:
            return ""

        record = self._records.get(key)
        return record.start_time if record else ""

    def upsert_success(
        self,
        correlation_key: str,
        current_id: str,
        event_uid: str,
        status: str = "",
        review_epoch: str = "",
        start_time: str = "",
    ) -> bool:
        """Persist the current emitted IDMEFv2 ID after successful delivery/logging.

        The state advances only after the final IDMEFv2 payload has been
        successfully sent or written locally. This preserves the PredID chain
        expected by receivers.
        """
        key = str(correlation_key or "").strip()
        current_id = str(current_id or "").strip()

        if not key:
            logger.warning(
                "Cannot update alert state with empty correlation_key."
            )
            return False

        if not current_id:
            logger.warning(
                "Cannot update alert state for correlation_key=%s "
                "with empty current_id.",
                key,
            )
            return False

        now = datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

        existing = self._records.get(key)

        record = AlertStateRecord(
            correlation_key=key,
            last_id=current_id,
            last_event_uid=str(event_uid or ""),
            last_status=str(status or ""),
            last_review_epoch=str(review_epoch or ""),
            start_time=(
                str(start_time or "").strip()
                or (existing.start_time if existing else "")
            ),
            created_at=(
                existing.created_at
                if existing and existing.created_at
                else now
            ),
            updated_at=now,
        )

        self._records[key] = record

        try:
            self._write_all()
        except Exception as exc:  # noqa: BLE001
            # Restore the previous in-memory state if persistence fails.
            if existing is not None:
                self._records[key] = existing
            else:
                self._records.pop(key, None)

            logger.error(
                "Could not persist alert state for "
                "correlation_key=%s to %s: %s",
                key,
                self.csv_path,
                exc,
            )
            return False

        logger.debug(
            "Updated alert state "
            "correlation_key=%s last_id=%s event_uid=%s",
            key,
            current_id,
            event_uid,
        )

        return True

    def _write_all(self) -> None:
        csv_path = Path(self.csv_path)
        csv_path.parent.mkdir(parents=True, exist_ok=True)

        rows = [
            {
                "correlation_key": record.correlation_key,
                "last_id": record.last_id,
                "last_event_uid": record.last_event_uid,
                "last_status": record.last_status,
                "last_review_epoch": record.last_review_epoch,
                "start_time": record.start_time,
                "created_at": record.created_at,
                "updated_at": record.updated_at,
            }
            for record in sorted(
                self._records.values(),
                key=lambda item: item.correlation_key,
            )
        ]

        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            dir=str(csv_path.parent),
            prefix=f".{csv_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as tmp_file:
            tmp_path = Path(tmp_file.name)

            writer = csv.DictWriter(
                tmp_file,
                fieldnames=COLUMNS,
            )

            writer.writeheader()
            writer.writerows(rows)

        tmp_path.replace(csv_path)