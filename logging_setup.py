"""Local debug log with secret redaction."""
from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler

from config.app_config import app_data_dir
from core.redaction import redact_text


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = redact_text(record.getMessage())
            record.args = ()
        except Exception:  # never let logging break the app
            pass
        return True


def setup_logging() -> logging.Logger:
    logger = logging.getLogger("cyberscope")
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG)
    try:
        log_dir = app_data_dir() / "logs"
        log_dir.mkdir(exist_ok=True)
        handler = RotatingFileHandler(log_dir / "cyberscope.log", maxBytes=512_000,
                                      backupCount=3, encoding="utf-8")
    except OSError:
        handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    handler.addFilter(RedactingFilter())
    logger.addHandler(handler)
    return logger
