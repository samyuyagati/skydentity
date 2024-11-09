"""
Functions to handle request session management.
"""

import logging as py_logging
import random
import threading

import requests
from requests.adapters import HTTPAdapter

NUM_SESSIONS = 1

_REQUEST_SESSIONS = [requests.Session() for _ in range(NUM_SESSIONS)]

# set up sessions
_SESSION_ADAPTER = HTTPAdapter(pool_connections=20, pool_maxsize=20)
for _session in _REQUEST_SESSIONS:
    _session.mount("http://", _SESSION_ADAPTER)
    _session.mount("https://", _SESSION_ADAPTER)
    # disable keep-alive
    _session.headers["Connection"] = "close"

# thread local data
_THREAD_LOCAL = threading.local()

LOGGER = py_logging.getLogger(__name__)


def _initialize_thread_local():
    """
    Initialize the thread local object with a random session index.
    """
    _THREAD_LOCAL.session_idx = random.randint(0, NUM_SESSIONS - 1)


def get_session():
    """
    Return the corresponding session for this thread.
    """
    if "session_idx" not in _THREAD_LOCAL.__dict__:
        _initialize_thread_local()

    session_idx = _THREAD_LOCAL.session_idx

    session = _REQUEST_SESSIONS[session_idx]
    LOGGER.info(f"Current session index: {session_idx}")
    return session
