import os

from skydentity.utils.signature import sign_request

# global constants
PRIVATE_KEY_PATH = os.environ.get("PRIVATE_KEY_PATH", "proxy_util/private_key.pem")


def get_headers_with_signature(request, private_key):
    return sign_request(request, private_key)
