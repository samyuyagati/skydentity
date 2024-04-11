import logging as py_logging
from typing import Optional


def build_file_handler(filename: str):
    """
    Build a file handler with a default formatter, saving to the given filename.
    """
    file_handler = py_logging.FileHandler(filename)
    formatter = py_logging.Formatter(
        fmt="%(asctime)s %(levelname)s %(filename)s:%(lineno)d - %(message)s"
    )
    file_handler.setFormatter(formatter)

    return file_handler


def build_time_logging_string(
    event: Optional[str],
    caller: Optional[str],
    called: Optional[str],
    start: float,
    end: float,
):
    return f"{event} {caller} << {called} -- {end-start}"
