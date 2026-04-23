"""
Centralized logging configuration for SSL Cert Manager.
Provides file + console logging with runtime-configurable log path and level.
"""

import os
import logging
from logging.handlers import RotatingFileHandler

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Defaults
DEFAULT_LOG_DIR = os.path.join(BASE_DIR, 'logs')
DEFAULT_LOG_FILE = 'certmanager.log'
DEFAULT_LOG_LEVEL = 'INFO'
DEFAULT_LOG_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
DEFAULT_LOG_BACKUP_COUNT = 5
LOG_FORMAT = '%(asctime)s [%(levelname)s] %(name)s (%(filename)s:%(lineno)d): %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

# Module-level reference so we can swap the file handler at runtime
_file_handler = None


def setup_logging(app):
    """
    Configure application-wide logging.
    Call once during app creation, *after* DB is initialised so we can
    read the user's preferred log path from the settings table.
    """
    global _file_handler

    # Try to read persisted settings from DB
    log_dir = DEFAULT_LOG_DIR
    log_level_name = DEFAULT_LOG_LEVEL
    try:
        from models import Setting
        row = Setting.query.filter_by(key='log_file_path').first()
        if row and row.value:
            log_dir = row.value
        row = Setting.query.filter_by(key='log_level').first()
        if row and row.value:
            log_level_name = row.value
    except Exception:
        pass  # DB may not be ready on very first run

    log_level = getattr(logging, log_level_name.upper(), logging.INFO)

    # Ensure log directory exists
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, DEFAULT_LOG_FILE)

    # Root logger
    root = logging.getLogger()
    root.setLevel(log_level)

    # Remove existing handlers to avoid duplicates on reload
    for h in root.handlers[:]:
        root.removeHandler(h)

    # Rotating file handler
    _file_handler = RotatingFileHandler(
        log_file,
        maxBytes=DEFAULT_LOG_MAX_BYTES,
        backupCount=DEFAULT_LOG_BACKUP_COUNT,
        encoding='utf-8',
    )
    _file_handler.setLevel(log_level)
    _file_handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT))
    root.addHandler(_file_handler)

    # Console handler
    console = logging.StreamHandler()
    console.setLevel(log_level)
    console.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT))
    root.addHandler(console)

    # Quieten noisy third-party loggers
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    logging.getLogger('apscheduler').setLevel(logging.WARNING)

    app_logger = logging.getLogger('certmanager')
    app_logger.info('Logging initialised  |  file=%s  level=%s', log_file, log_level_name)

    return app_logger


def reconfigure_logging(log_dir=None, log_level_name=None):
    """
    Swap the file handler at runtime when the user changes settings.
    Returns (success: bool, message: str).
    """
    global _file_handler

    root = logging.getLogger()

    if log_level_name:
        level = getattr(logging, log_level_name.upper(), None)
        if level is None:
            return False, f'Invalid log level: {log_level_name}'
        root.setLevel(level)
        for h in root.handlers:
            h.setLevel(level)

    if log_dir:
        try:
            os.makedirs(log_dir, exist_ok=True)
            new_log_file = os.path.join(log_dir, DEFAULT_LOG_FILE)

            # Create and test new handler before removing old one
            new_handler = RotatingFileHandler(
                new_log_file,
                maxBytes=DEFAULT_LOG_MAX_BYTES,
                backupCount=DEFAULT_LOG_BACKUP_COUNT,
                encoding='utf-8',
            )
            level = root.level
            new_handler.setLevel(level)
            new_handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT))

            # Swap handlers
            if _file_handler in root.handlers:
                root.removeHandler(_file_handler)
                _file_handler.close()
            root.addHandler(new_handler)
            _file_handler = new_handler

            logging.getLogger('certmanager').info(
                'Log file path changed to %s', new_log_file
            )
        except Exception as e:
            return False, f'Failed to change log path: {e}'

    return True, 'Logging configuration updated successfully.'


def get_logger(name):
    """Get a child logger under the certmanager namespace."""
    return logging.getLogger(f'certmanager.{name}')
