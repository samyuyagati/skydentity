import base64
import datetime
import os

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

# global constants
PRIVATE_KEY_PATH = os.environ.get("PRIVATE_KEY_PATH", "proxy_util/private_key.pem")


def get_headers_with_signature(request):
    new_headers = {k: v for k, v in request.headers}

    with open(PRIVATE_KEY_PATH, "rb") as key_file:
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
