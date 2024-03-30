"""
Utility methods for fetching credentials.
"""

import json
import os
import subprocess
from functools import cache

# Global file variables; underscore to prevent external imports
_CAPABILITY_ENC_KEY_FILE = os.environ.get("CAPABILITY_ENC_KEY_FILE", None)
_DB_INFO_FILE = os.environ.get("AZURE_DB_INFO_FILE", None)

_CAPABILITY_ENC_KEY = os.environ.get("CAPABILITY_ENC_KEY", None)
_DB_ENDPOINT = os.environ.get("AZURE_DB_ENDPOINT", None)
_DB_KEY = os.environ.get("AZURE_DB_KEY", None)

_CONNECTION_STRING = os.environ.get("AZURE_STORAGE_CONNECTION_STRING", None)

# validate global constants from environment variables
assert (_CAPABILITY_ENC_KEY_FILE is not None and os.path.isfile(_CAPABILITY_ENC_KEY_FILE)) \
    or _CAPABILITY_ENC_KEY is not None
assert (_DB_INFO_FILE is not None) or (_DB_ENDPOINT is not None and _DB_KEY is not None)
assert _CONNECTION_STRING is not None

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

@cache
def get_capability_enc_key_bytes() -> bytes:
    """
    Retrieve the capability encoding key as bytes.
    """
    return _CAPABILITY_ENC_KEY.encode("utf-8")

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

def get_storage_connection_string() -> str:
    """
    Retrieve the connection string for the Azure Storage Account.
    """
    return _CONNECTION_STRING