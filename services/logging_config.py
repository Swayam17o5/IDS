"""
services/logging_config.py
---------------------------
Centralised structured logging configuration for AegisNIDS.

Call configure_logging() once at application startup.

Log levels can be controlled via the LOG_LEVEL environment variable.
Default: INFO.

Format example:
  2026-10-02 20:45:12.345 INFO  [aegis.inference] Prediction: PortScan confidence=0.987
  2026-10-02 20:45:12.346 INFO  [aegis.alert_engine] Alert generated: ALT-12345 ...
  2026-10-02 20:45:12.347 ERROR [aegis.validator] Feature validation failed: missing Flow Duration
"""

import os
import logging
import logging.config
from typing import Optional


def configure_logging(level: Optional[str] = None) -> None:
    """
    Configure Python's logging module for AegisNIDS.

    Parameters
    ----------
    level : str, optional
        Override log level (DEBUG, INFO, WARNING, ERROR).
        Falls back to LOG_LEVEL env var, then INFO.
    """
    log_level = (level or os.getenv("LOG_LEVEL", "INFO")).upper()

    fmt = "%(asctime)s.%(msecs)03d %(levelname)-7s [%(name)s] %(message)s"
    date_fmt = "%Y-%m-%d %H:%M:%S"

    logging.config.dictConfig({
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "standard": {
                "format": fmt,
                "datefmt": date_fmt,
            }
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout",
                "formatter": "standard",
                "level": log_level,
            }
        },
        "loggers": {
            # AegisNIDS namespace
            "aegis": {
                "handlers": ["console"],
                "level": log_level,
                "propagate": False,
            },
            # Silence noisy third-party libraries
            "scapy": {
                "level": "WARNING",
                "propagate": True,
            },
            "uvicorn.access": {
                "level": "WARNING",
                "propagate": True,
            },
        },
        "root": {
            "handlers": ["console"],
            "level": "WARNING",
        },
    })

    logging.getLogger("aegis").info(
        "Logging configured: level=%s", log_level
    )
