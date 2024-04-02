"""
Utility functions for handling and verifying signatures in a request.
"""

import base64
import datetime
import time

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

from ..proxy_util.gcp.logging import LogLevel, print_and_log
from .log_util import build_time_logging_string

def verify_request_signature(request, logger=None, request_name=None, caller_name=None) -> bool:
    caller = caller_name + "<< verify_request_signature" if caller_name else "verify_request_signature"
    
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
        if logger:
            print_and_log(logger, 
                          build_time_logging_string(request_name, caller, "total (Invalid timestamp)", start, time.perf_counter()), 
                          severity=LogLevel.INFO)
        return False

    # decode signature and public key using base64
    signature = base64.b64decode(encoded_signature, validate=True)
    public_key_bytes = base64.b64decode(encoded_public_key_string, validate=True)

    now = datetime.datetime.now(datetime.timezone.utc)
    if now - datetime.timedelta(seconds=60) > timestamp_datetime:
        # if timestamp when request was sent is > 60 seconds old, deny the request
        print_and_log(logger,
                      build_time_logging_string(request_name, caller, "total (Timestamp of request > 60s old)", start, time.perf_counter()),
                      severity=LogLevel.INFO)
        return False

    # reformed_message = f"{str(request.method)}-{timestamp}-{public_key_bytes}"
    reformed_message = f"{str(request.method)}-{timestamp}-{public_key_bytes}"
    reformed_message_bytes = reformed_message.encode("utf-8")

    public_key = RSA.import_key(public_key_bytes)
    h = SHA256.new(reformed_message_bytes)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
    except (ValueError, TypeError):
        print_and_log(logger,
                      build_time_logging_string(request_name, caller, "total (Invalid signature, unable to verify)", start, time.perf_counter()),
                      severity=LogLevel.INFO)
        return False

    return True


def strip_signature_headers(headers: dict) -> dict:
    signature_headers = set(["X-Signature", "X-Timestamp", "X-PublicKey"])
    new_headers = {k: v for k, v in headers.items() if k not in signature_headers}
    return new_headers
