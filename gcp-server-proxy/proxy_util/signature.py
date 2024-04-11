import os

from skydentity.utils.signature import sign_request

# global constants
PRIVATE_KEY_PATH = os.environ.get("PRIVATE_KEY_PATH", "proxy_util/private_key.pem")


def get_headers_with_signature(request):
    return sign_request(request, PRIVATE_KEY_PATH)
