"""
Utility methods for fetching credentials.
"""

import json
import os
import subprocess
import base64
from functools import cache
from typing import Tuple
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# Global file variables; underscore to prevent external imports
_CAPABILITY_ENC_KEY_FILE = os.environ.get("CAPABILITY_ENC_KEY_FILE", None)
_DB_INFO_FILE = os.environ.get("AZURE_DB_INFO_FILE", None)

_CAPABILITY_ENC_KEY = os.environ.get("CAPABILITY_ENC_KEY", None)
_DB_ENDPOINT = os.environ.get("AZURE_DB_ENDPOINT", None)
_DB_KEY = os.environ.get("AZURE_DB_KEY", None)

_TENANT_ID = os.environ.get("TENANT_ID", None)
_APP_SECRET = os.environ.get("APP_SECRET", None)
_APP_ID = os.environ.get("APP_ID", None)

# validate global constants from environment variables
assert (_CAPABILITY_ENC_KEY_FILE is not None and os.path.isfile(_CAPABILITY_ENC_KEY_FILE)) \
    or _CAPABILITY_ENC_KEY is not None
assert (_DB_INFO_FILE is not None) or (_DB_ENDPOINT is not None and _DB_KEY is not None)

@cache
def get_managed_identity_auth_token() -> bytes:
    """
    Retrieve the service account authorization token through the gcloud CLI.
    """
    auth_token_command = "az account get-access-token"
    auth_token_process = subprocess.Popen(
        auth_token_command.split(), stdout=subprocess.PIPE
    )
    auth_token_process_out_bytes, _ = auth_token_process.communicate()

    auth_token_dict = json.loads(auth_token_process_out_bytes)

    return auth_token_dict['accessToken']

@cache
def get_db_info_file() -> str:
    """
    Retrieve the endpoint for the Azure Cosmos DB.
    """
    return _DB_INFO_FILE

@cache
def get_capability_enc_key() -> str:
    """
    Retrieve the key for capability encoding.
    """
    return _CAPABILITY_ENC_KEY_FILE

def get_capability_enc_key_bytes() -> bytes:
    """
    Retrieve the capability encoding key as bytes.
    """
    return _CAPABILITY_ENC_KEY.encode("utf-8")

@cache
def get_capability_enc_key_base64() -> bytes:
    """
    Retrieve the capability encoding key as bytes.
    """
    if _CAPABILITY_ENC_KEY is None:
        return None
    return base64.b64decode(_CAPABILITY_ENC_KEY)

def get_db_endpoint() -> str:
    """
    Retrieve the endpoint for the Azure Cosmos DB.
    """
    return _DB_ENDPOINT

def get_db_key() -> str:
    """
    Retrieve the key for the Azure Cosmos DB.
    """
    return _DB_KEY

def get_tenant_id() -> str:
    """
    Retrieve the tenant id for the Azure AD.
    """
    return _TENANT_ID

def get_app_secret() -> str:
    """
    Retrieve the app secret for the Azure AD.
    """
    return _APP_SECRET

def get_app_id() -> str:
    """
    Retrieve the app id for the Azure AD.
    """
    return _APP_ID

def _generate_rsa_key_pair() -> Tuple[str, str]:
    key = rsa.generate_private_key(backend=default_backend(),
                                   public_exponent=65537,
                                   key_size=2048)

    private_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()).decode(
            'utf-8').strip()

    public_key = key.public_key().public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH).decode('utf-8').strip()

    return public_key, private_key