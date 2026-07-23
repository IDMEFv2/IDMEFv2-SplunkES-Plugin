"""Logging utilities for the IDMEFv2 internal alert app."""

from __future__ import annotations

import logging
import os
import sys

APP_NAME = "idmefv2_internal_alert_app"
DEFAULT_LOG_FILE = os.path.join(
    os.environ.get("SPLUNK_HOME", "/opt/splunk"),
    "var",
    "log",
    "splunk",
    f"{APP_NAME}.log",
)


def get_logger(
    name: str = APP_NAME,
    run_id: str = "",
    level: int = logging.INFO,
) -> logging.Logger:
    """Create or return the application logger.

    The logger writes both to Splunk's log directory and to stderr.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False

    if logger.handlers:
        for handler in logger.handlers:
            handler.setLevel(level)
        return logger

    fmt = f"%(asctime)s run_id={run_id} %(levelname)s [%(name)s] %(message)s"
    formatter = logging.Formatter(fmt=fmt, datefmt="%Y-%m-%dT%H:%M:%S")

    try:
        log_dir = os.path.dirname(DEFAULT_LOG_FILE)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

        file_handler = logging.FileHandler(DEFAULT_LOG_FILE)
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except OSError as exc:
        stderr_handler = logging.StreamHandler(sys.stderr)
        stderr_handler.setLevel(level)
        stderr_handler.setFormatter(formatter)
        logger.addHandler(stderr_handler)
        logger.warning("Could not initialize file logging at %s: %s", DEFAULT_LOG_FILE, exc)
        return logger

    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(level)
    stderr_handler.setFormatter(formatter)
    logger.addHandler(stderr_handler)

    return logger
