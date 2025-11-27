# -*- coding: utf-8 -*-

"""
HTCAP - Enhanced Logging Module
Provides comprehensive logging capabilities for the htcap scanner.

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.
"""

import logging
import sys
import os
from datetime import datetime
from typing import Optional, Union
from enum import Enum


class LogLevel(Enum):
    """Enumeration of available log levels."""
    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARNING = logging.WARNING
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL


class ColoredFormatter(logging.Formatter):
    """Custom formatter with color support for terminal output."""

    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
        'RESET': '\033[0m'
    }

    def __init__(self, fmt: Optional[str] = None, datefmt: Optional[str] = None,
                 use_colors: bool = True):
        super().__init__(fmt, datefmt)
        self.use_colors = use_colors and sys.stdout.isatty()

    def format(self, record: logging.LogRecord) -> str:
        if self.use_colors:
            levelname = record.levelname
            color = self.COLORS.get(levelname, self.COLORS['RESET'])
            record.levelname = f"{color}{levelname}{self.COLORS['RESET']}"
            record.msg = f"{color}{record.msg}{self.COLORS['RESET']}"
        return super().format(record)


class HtcapLogger:
    """
    Centralized logging facility for HTCAP.

    Provides structured logging with support for:
    - Console output with colors
    - File logging
    - Different log levels per component
    - Performance metrics
    """

    _instance: Optional['HtcapLogger'] = None
    _initialized: bool = False

    def __new__(cls) -> 'HtcapLogger':
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if HtcapLogger._initialized:
            return

        self.loggers: dict = {}
        self.log_file: Optional[str] = None
        self.console_level = logging.INFO
        self.file_level = logging.DEBUG

        # Create root htcap logger
        self.root_logger = logging.getLogger('htcap')
        self.root_logger.setLevel(logging.DEBUG)

        # Console handler
        self.console_handler = logging.StreamHandler(sys.stdout)
        self.console_handler.setLevel(self.console_level)
        console_format = ColoredFormatter(
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            datefmt='%H:%M:%S'
        )
        self.console_handler.setFormatter(console_format)
        self.root_logger.addHandler(self.console_handler)

        HtcapLogger._initialized = True

    def set_log_file(self, filepath: str) -> None:
        """Enable file logging to the specified path."""
        self.log_file = filepath

        # Create directory if needed
        log_dir = os.path.dirname(filepath)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)

        # File handler
        file_handler = logging.FileHandler(filepath)
        file_handler.setLevel(self.file_level)
        file_format = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s (%(filename)s:%(lineno)d): %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_format)
        self.root_logger.addHandler(file_handler)

    def set_console_level(self, level: Union[LogLevel, int, str]) -> None:
        """Set the console output log level."""
        if isinstance(level, LogLevel):
            level = level.value
        elif isinstance(level, str):
            level = getattr(logging, level.upper())
        self.console_level = level
        self.console_handler.setLevel(level)

    def get_logger(self, name: str) -> logging.Logger:
        """Get or create a logger for a specific component."""
        full_name = f'htcap.{name}'
        if full_name not in self.loggers:
            self.loggers[full_name] = logging.getLogger(full_name)
        return self.loggers[full_name]

    def enable_verbose(self) -> None:
        """Enable verbose (debug) output."""
        self.set_console_level(logging.DEBUG)

    def disable_verbose(self) -> None:
        """Disable verbose output (back to INFO)."""
        self.set_console_level(logging.INFO)

    def quiet(self) -> None:
        """Set quiet mode (only warnings and errors)."""
        self.set_console_level(logging.WARNING)


# Global logger instance
_logger = HtcapLogger()


def get_logger(name: str = 'main') -> logging.Logger:
    """
    Get a logger for a specific component.

    Args:
        name: Component name (e.g., 'crawler', 'scanner', 'fuzzer')

    Returns:
        A configured logging.Logger instance
    """
    return _logger.get_logger(name)


def set_log_file(filepath: str) -> None:
    """Enable file logging."""
    _logger.set_log_file(filepath)


def set_verbose(enabled: bool = True) -> None:
    """Enable or disable verbose output."""
    if enabled:
        _logger.enable_verbose()
    else:
        _logger.disable_verbose()


def set_quiet(enabled: bool = True) -> None:
    """Enable or disable quiet mode."""
    if enabled:
        _logger.quiet()
    else:
        _logger.disable_verbose()


def set_level(level: Union[LogLevel, int, str]) -> None:
    """Set the console log level."""
    _logger.set_console_level(level)


# Convenience functions for quick logging
def debug(msg: str, *args, **kwargs) -> None:
    """Log a debug message."""
    get_logger().debug(msg, *args, **kwargs)


def info(msg: str, *args, **kwargs) -> None:
    """Log an info message."""
    get_logger().info(msg, *args, **kwargs)


def warning(msg: str, *args, **kwargs) -> None:
    """Log a warning message."""
    get_logger().warning(msg, *args, **kwargs)


def error(msg: str, *args, **kwargs) -> None:
    """Log an error message."""
    get_logger().error(msg, *args, **kwargs)


def critical(msg: str, *args, **kwargs) -> None:
    """Log a critical message."""
    get_logger().critical(msg, *args, **kwargs)
