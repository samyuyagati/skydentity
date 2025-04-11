"""
Utility methods for fetching credentials.
"""

import json
import logging
import os
import subprocess
from functools import cache

from skydentity.policies.iam.gcp_crosscloud_service_account_manager import (
    GCPCrossCloudServiceAccountManager,
)
from skydentity.policies.managers.crosscloud_policy_manager import (
    CrossCloudPolicyManager,
)
from skydentity.policies.managers.gcp_global_state_manager import GCPGlobalStateManager

LOGGER = logging.getLogger(__name__)

# Global file variables; underscore to prevent external imports
# Must provide these environment variables if running locally
_SERVICE_ACCT_INFO_FILE = os.environ.get(
    "SERVICE_ACCOUNT_INFO_FILE", "/cloud_creds/gcp/proxy_service_account_key.json"
)
_CAPABILITY_ENC_KEY_FILE = os.environ.get(
    "CAPABILITY_ENC_KEY_FILE", "/cloud_creds/enc/capability_enc.key"
)

# validate global constants from environment variables
assert _SERVICE_ACCT_INFO_FILE is not None and os.path.isfile(_SERVICE_ACCT_INFO_FILE)
assert _CAPABILITY_ENC_KEY_FILE is not None and os.path.isfile(_CAPABILITY_ENC_KEY_FILE)

_GLOBAL_STATE_ACCT_INFO_FILE = os.environ.get(
    "GLOBAL_STATE_ACCOUNT_INFO_FILE",
    "/cloud_creds/gcp/proxy_service_account_key.json",
)
assert _GLOBAL_STATE_ACCT_INFO_FILE is not None and os.path.isfile(
    _GLOBAL_STATE_ACCT_INFO_FILE
)


@cache  # shouldn't change throughout the proxy lifespan
def get_service_account_path() -> str:
    """
    Retrieve the service account email and credentials file from the filesystem.

    Returns a tuple of the form (email, credentials_filename),
    where `credentials_filename` is the path to the file containing the service account credentials,
    relative to the `gcp-client-proxy` directory.
    """
    return _SERVICE_ACCT_INFO_FILE
    # with open(_SERVICE_ACCT_INFO_FILE, "r", encoding="utf-8") as service_account_file:
    #     service_account_file_json = json.load(service_account_file)

    # assert "email" in service_account_file_json.keys()
    # assert "credentials" in service_account_file_json.keys()

    # service_account_creds = service_account_file_json["credentials"]
    # assert os.path.isfile(
    #     service_account_creds
    # ), f"Service account credentials file (from JSON: {service_account_creds}) does not exist."

    # return (
    #     service_account_file_json["email"],
    #     service_account_creds,
    # )


@cache
def activate_service_account(credential_file: str) -> None:
    """
    Activate a service account, given the file containing the service account credentials.
    """
    auth_command = f"gcloud auth activate-service-account --key-file={credential_file}"
    auth_process = subprocess.Popen(auth_command.split())
    auth_process.wait()


@cache
def get_service_account_auth_token() -> bytes:
    """
    Retrieve the service account authorization token through the gcloud CLI.
    """
    auth_token_command = "gcloud auth print-access-token"
    auth_token_process = subprocess.Popen(
        auth_token_command.split(), stdout=subprocess.PIPE
    )
    auth_token_process_out_bytes, _ = auth_token_process.communicate()

    return auth_token_process_out_bytes


@cache
def get_capability_enc_key() -> str:
    """
    Retrieve the key for capability encoding.
    """
    return _CAPABILITY_ENC_KEY_FILE


@cache
def get_global_state_account_info() -> dict:
    with open(_GLOBAL_STATE_ACCT_INFO_FILE, "r", encoding="utf-8") as cred_file:
        cred_info = json.load(cred_file)

    return cred_info


@cache
def get_global_state_manager() -> GCPGlobalStateManager:
    return GCPGlobalStateManager(get_global_state_account_info())


@cache
def get_crosscloud_policy_manager() -> CrossCloudPolicyManager:
    cred_info = get_global_state_account_info()
    return CrossCloudPolicyManager(creds=cred_info)


@cache
def get_crosscloud_service_account_manager() -> GCPCrossCloudServiceAccountManager:
    return GCPCrossCloudServiceAccountManager(
        credentials_path=get_service_account_path()
    )
