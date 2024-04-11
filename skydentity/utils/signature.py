"""
Utility functions for handling and verifying signatures in a request.
"""

import base64
import datetime
import logging as py_logging
import time
from typing import Optional

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

from .log_util import build_time_logging_string

LOGGER = py_logging.getLogger(__name__)


def sign_request(request, private_key_path: str):
    """
    Sign a request using the given private key file.
    Used in the redirector proxy.

    Returns the modified request headers, with added headers for the signature.
    """
    new_headers = {k: v for k, v in request.headers}

    with open(private_key_path, "rb") as key_file:
        contents = key_file.read()
        private_key = RSA.import_key(contents)

    # assume set, predetermined/agreed upon tolerance on client proxy/receiving end
    # use utc for consistency if server runs in cloud in different region
    timestamp = datetime.datetime.now(datetime.timezone.utc).timestamp()
    public_key_string = private_key.public_key().export_key()

    # message = f"{str(request.method)}-{timestamp}-{public_key_string}"
    message = f"{str(request.method)}-{timestamp}-{public_key_string}"
    message_bytes = message.encode("utf-8")

    h = SHA256.new(message_bytes)
    # TODO should we be using PSS?
    signature = pkcs1_15.new(private_key).sign(h)

    # base64 encode the signature and public key
    encoded_signature = base64.b64encode(signature)
    encoded_public_key_string = base64.b64encode(public_key_string)

    new_headers["X-Signature"] = encoded_signature
    new_headers["X-Timestamp"] = str(timestamp)
    new_headers["X-PublicKey"] = encoded_public_key_string

    if "Host" in new_headers:
        del new_headers["Host"]

    return new_headers


def verify_request_signature(
    request, request_name: Optional[str] = None, caller_name: Optional[str] = None
) -> bool:
    caller = (
        caller_name + "<< verify_request_signature"
        if caller_name
        else "verify_request_signature"
    )

    start = time.perf_counter()
    encoded_signature = request.headers["X-Signature"]
    timestamp = request.headers["X-Timestamp"]
    encoded_public_key_string = request.headers["X-PublicKey"]

    try:
        timestamp = float(timestamp)
        timestamp_datetime = datetime.datetime.fromtimestamp(
            timestamp, tz=datetime.timezone.utc
        )
    except ValueError:
        # invalid timestamp
        LOGGER.warning(
            build_time_logging_string(
                request_name,
                caller,
                "total (Invalid timestamp)",
                start,
                time.perf_counter(),
            )
        )
        return False

    # decode signature and public key using base64
    signature = base64.b64decode(encoded_signature, validate=True)
    public_key_bytes = base64.b64decode(encoded_public_key_string, validate=True)

    now = datetime.datetime.now(datetime.timezone.utc)
    if now - datetime.timedelta(seconds=60) > timestamp_datetime:
        # if timestamp when request was sent is > 60 seconds old, deny the request
        LOGGER.warning(
            build_time_logging_string(
                request_name,
                caller,
                "total (Timestamp of request > 60s old)",
                start,
                time.perf_counter(),
            )
        )
        return False

    # reformed_message = f"{str(request.method)}-{timestamp}-{public_key_bytes}"
    reformed_message = f"{str(request.method)}-{timestamp}-{public_key_bytes}"
    reformed_message_bytes = reformed_message.encode("utf-8")

    public_key = RSA.import_key(public_key_bytes)
    h = SHA256.new(reformed_message_bytes)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
    except (ValueError, TypeError):
        LOGGER.warning(
            build_time_logging_string(
                request_name,
                caller,
                "total (Invalid signature, unable to verify)",
                start,
                time.perf_counter(),
            )
        )
        return False

    return True


def strip_signature_headers(headers: dict) -> dict:
    signature_headers = set(["X-Signature", "X-Timestamp", "X-PublicKey"])
    new_headers = {k: v for k, v in headers.items() if k not in signature_headers}
    return new_headers
