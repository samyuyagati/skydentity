"""
Utility functions for handling and verifying signatures in a request.
"""

import base64
import datetime

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

def verify_request_signature(request) -> bool:
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
        return False

    # decode signature and public key using base64
    signature = base64.b64decode(encoded_signature, validate=True)
    public_key_bytes = base64.b64decode(encoded_public_key_string, validate=True)

    now = datetime.datetime.now(datetime.timezone.utc)
    if now - datetime.timedelta(seconds=60) > timestamp_datetime:
        # if timestamp when request was sent is > 60 seconds old, deny the request
        return False

    reformed_message = f"{str(request.method)}-{timestamp}-{public_key_bytes}"
    reformed_message_bytes = reformed_message.encode("utf-8")

    # Verify signature
    public_key = RSA.import_key(public_key_bytes)
    h = SHA256.new(reformed_message_bytes)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
    except (ValueError, TypeError):
        return False

    return True


def strip_signature_headers(headers: dict) -> dict:
    signature_headers = set(["X-Signature", "X-Timestamp", "X-PublicKey"])
    new_headers = {k: v for k, v in headers.items() if k not in signature_headers}
    return new_headers
