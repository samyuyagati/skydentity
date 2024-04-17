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
# The secrets folder contains the files for each of the secrets below in the following names:
# Folder in serverless instance: /cloud_creds
# APP_ID: app-id
# APP_SECRET: app-secret
# DB_INFO_FILE: (the actual value here should be) /cloud_creds/azure-db-info
# CONNECTION_STRING: azure-storage-connection-string
# CAPABILITY_ENC_KEY: capability-enc-key
# TENANT_ID: tenant-id
_SECRETS_FOLDER = os.environ.get("SECRETS_FOLDER", None)
_DB_INFO_FILE = os.environ.get("AZURE_DB_INFO_FILE", None)

_CAPABILITY_ENC_KEY_FILE = os.environ.get("CAPABILITY_ENC_KEY_FILE", None)
_CAPABILITY_ENC_KEY = os.environ.get("CAPABILITY_ENC_KEY", None)
_DB_ENDPOINT = os.environ.get("AZURE_DB_ENDPOINT", None)
_DB_KEY = os.environ.get("AZURE_DB_KEY", None)

_TENANT_ID = os.environ.get("TENANT_ID", None)
_APP_SECRET = os.environ.get("APP_SECRET", None)
_APP_ID = os.environ.get("APP_ID", None)

_CONNECTION_STRING = os.environ.get("AZURE_STORAGE_CONNECTION_STRING", None)

loaded_secrets = False
def load_secrets():
    """
    Load secrets from the secrets folder.
    """
    global _CAPABILITY_ENC_KEY
    global _DB_INFO_FILE
    global _DB_ENDPOINT
    global _TENANT_ID
    global _APP_SECRET
    global _APP_ID
    global _CONNECTION_STRING
    global loaded_secrets

    if loaded_secrets:
        return

    with open(os.path.join(_SECRETS_FOLDER, "app-id"), "r") as f:
        _APP_ID = f.read().strip()

    with open(os.path.join(_SECRETS_FOLDER, "app-secret"), "r") as f:
        _APP_SECRET = f.read().strip()

    _DB_INFO_FILE = os.path.join(_SECRETS_FOLDER, "azure-db-info")

    with open(os.path.join(_SECRETS_FOLDER, "capability-enc-key"), "r") as f:
        _CAPABILITY_ENC_KEY = f.read().strip()

    with open(os.path.join(_SECRETS_FOLDER, "tenant-id"), "r") as f:
        _TENANT_ID = f.read().strip()

    with open(os.path.join(_SECRETS_FOLDER, "azure-storage-connection-string"), "r") as f:
        _CONNECTION_STRING = f.read().strip()

    loaded_secrets = True
    print("Loaded secrets")    

if _SECRETS_FOLDER is not None:
    load_secrets()

# validate global constants from environment variables
assert _CAPABILITY_ENC_KEY is not None
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

def get_storage_connection_string() -> str:
    """
    Retrieve the connection string for the Azure Storage Account.
    """
    return _CONNECTION_STRING