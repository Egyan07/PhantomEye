# =============================================================================
#   logger.py — PhantomEye v1.2
#   Red Parrot Accounting Ltd
#
#   Centralised logging setup with log rotation.
#   Import `log` from this module everywhere.
# =============================================================================

import logging
import os
import sys
from logging.handlers import RotatingFileHandler

from config import FEEDS_DIR, LOG_DIR, LOG_FILE

# Ensure directories exist before attaching file handler
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(FEEDS_DIR, exist_ok=True)

_fmt = logging.Formatter("[%(asctime)s] %(levelname)s — %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

_file_handler = RotatingFileHandler(LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8")
_file_handler.setFormatter(_fmt)

_console_handler = logging.StreamHandler(sys.stdout)
_console_handler.setFormatter(_fmt)

log = logging.getLogger("PhantomEye")
log.setLevel(logging.INFO)
log.addHandler(_file_handler)
log.addHandler(_console_handler)
