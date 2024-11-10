"""
Logging functions for use in the serverless proxy.
"""
import os
from functools import cache
from pprint import pprint

from google.cloud import logging

# check whether gcp logging should be enabled (default yes)
# useful to disable if the active GCP account does not have permissions
ENABLE_GCP_LOGGING = bool(int(os.environ.get("ENABLE_GCP_LOGGING", 1)))


@cache
def get_logger():
    """
    Retrieve the logger from the logging module.
    """
    if ENABLE_GCP_LOGGING:
        logging_client = logging.Client()
        return logging_client.logger("app_proxy")
    return None


def print_and_log(logger, text, severity="WARNING"):
    """
    Print text to stdout, and log it using the provided logger.
    Uses built-in pprint.pprint to print the content.
    """
    if isinstance(text, str):
        print(text)
    else:
        pprint(text)

    if logger:
        logger.log_text(text, severity=severity)
