"""
Logging functions for use in the serverless proxy.
"""
from functools import cache
from pprint import pprint

from google.cloud import logging


@cache
def get_logger():
    """
    Retrieve the logger from the logging module.
    """
    logging_client = logging.Client()
    return logging_client.logger("app_proxy")


def print_and_log(logger, text, severity="WARNING"):
    """
    Print text to stdout, and log it using the provided logger.
    Uses built-in pprint.pprint to print the content.
    """
    if isinstance(text, str):
        print(text)
    else:
        pprint(text)
    logger.log_text(text, severity=severity)
