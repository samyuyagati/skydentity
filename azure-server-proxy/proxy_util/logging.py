"""
Logging functions for use in the serverless proxy.
"""
from functools import cache
from pprint import pprint
import logging

@cache
def get_logger():
    """
    Retrieve the logger from the logging module.
    """
    return logging.getLogger("app_proxy")


def print_and_log(logger, text, severity="WARNING"):
    """
    Print text to stdout, and log it using the provided logger.
    Uses built-in pprint.pprint to print the content.
    """
    if isinstance(text, str):
        print(text)
    else:
        pprint(text)
    logger.warn(text)

def build_time_logging_string(event, caller, called, start, end):
    return f"{event} {caller} << {called} -- {end-start}"