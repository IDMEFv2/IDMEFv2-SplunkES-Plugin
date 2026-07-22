"""CSV-based deduplication store for processed lifecycle events.

Persisted in: lookups/idmefv2_processed_events.csv
An event_uid is marked processed only after successful send/log.
"""

from __future__ import annotations

import csv
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

COLUMNS = ["event_uid", "rule_id", "status", "review_epoch", "processed_at", "result"]


class StateStore:
    def __init__(self, csv_path: str) -> None:
        self.csv_path = csv_path
        self._processed: set[str] = set()
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self.csv_path):
            return

        try:
            with open(self.csv_path, "r", encoding="utf-8", newline="") as fh:
                reader = csv.DictReader(fh)

                for row in reader:
                    uid = str(row.get("event_uid") or "").strip()

                    if uid:
                        self._processed.add(uid)

            logger.debug(
                "Loaded %d processed event_uid(s) from %s",
                len(self._processed),
                self.csv_path,
            )

        except Exception as exc:
            logger.warning(
                "Could not load state store from %s: %s",
                self.csv_path,
                exc,
            )

    def is_processed(self, event_uid: str) -> bool:
        uid = str(event_uid or "").strip()
        return uid in self._processed

    def mark_processed(
        self,
        event_uid: str,
        rule_id: str = "",
        status: str = "",
        review_epoch: str = "",
        result: str = "ok",
    ) -> bool:
        uid = str(event_uid or "").strip()

        if not uid:
            logger.warning("Cannot mark processed event with empty event_uid.")
            return False

        if uid in self._processed:
            logger.debug("event_uid=%s already present in state store.", uid)
            return True

        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        row = {
            "event_uid": uid,
            "rule_id": str(rule_id or ""),
            "status": str(status or ""),
            "review_epoch": str(review_epoch or ""),
            "processed_at": now,
            "result": str(result or "ok"),
        }

        try:
            csv_dir = os.path.dirname(self.csv_path)

            if csv_dir:
                os.makedirs(csv_dir, exist_ok=True)

            file_exists = (
                os.path.isfile(self.csv_path)
                and os.path.getsize(self.csv_path) > 0
            )

            with open(self.csv_path, "a", encoding="utf-8", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=COLUMNS)

                if not file_exists:
                    writer.writeheader()

                writer.writerow(row)

            self._processed.add(uid)

            logger.debug(
                "Marked event_uid=%s as processed in %s",
                uid,
                self.csv_path,
            )

            return True

        except Exception as exc:
            logger.warning(
                "Could not write event_uid=%s to state store %s: %s",
                uid,
                self.csv_path,
                exc,
            )
            return False