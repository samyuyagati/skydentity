"""
Logging functions for use in the serverless proxy.
"""
import enum
from functools import cache
from pprint import pprint

from google.cloud import logging

class LogLevel(enum.Enum):
    DEBUG = 1
    INFO = 2
    NOTICE = 3
    WARNING = 4
    ERROR = 5
    CRITICAL = 6
    ALERT = 7
    EMERGENCY = 8
    def __lt__(self, other):
        if self.__class__ is other.__class__:
           return self.value < other.value
        return NotImplemented

log_level_map = {
    LogLevel.DEBUG: "DEBUG",
    LogLevel.INFO: "INFO",
    LogLevel.NOTICE: "NOTICE",
    LogLevel.WARNING: "WARNING",
    LogLevel.ERROR: "ERROR",
    LogLevel.CRITICAL: "CRITICAL",
    LogLevel.ALERT: "ALERT",
    LogLevel.EMERGENCY: "EMERGENCY"
}

LOG_LEVEL = LogLevel.WARNING

@cache
def get_logger():
    """
    Retrieve the logger from the logging module.
    """
    logging_client = logging.Client()
    return logging_client.logger("app_proxy")

def print_and_log(logger, text, severity=LogLevel.DEBUG):
    """
    Print text to stdout, and log it using the provided logger.
    Uses built-in pprint.pprint to print the content.
    """
    if (severity < LOG_LEVEL):
        return
    if isinstance(text, str):
        print(text)
    else:
        pprint(text)
    logger.log_text(text, severity=log_level_map[severity])
