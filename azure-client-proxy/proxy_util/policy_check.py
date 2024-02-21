"""
Utility functions for handling policy checking.
"""

from functools import cache
from typing import Tuple, Union

from skydentity.policies.managers.azure_authorization_policy_manager import (
    AzureAuthorizationPolicyManager,
)
from skydentity.policies.managers.azure_policy_manager import AzurePolicyManager

from .credentials import get_capability_enc_key, get_db_endpoint, get_db_key
from .logging import get_logger, print_and_log


@cache
def get_policy_manager() -> AzurePolicyManager:
    # TODO(kdharmarajan): Create this AzurePolicyManager properly
    return AzurePolicyManager(
        db_endpoint=get_db_endpoint(),
        db_key=get_db_key()
    )


@cache
def get_authorization_policy_manager() -> AzureAuthorizationPolicyManager:
    capability_enc_key_file = get_capability_enc_key()
    print("CREATING AUTH POLICY MANAGER")
    return AzureAuthorizationPolicyManager(
        db_endpoint=get_db_endpoint(),
        db_key=get_db_key(),
        capability_enc_path=capability_enc_key_file
    )


def check_request_from_policy(public_key, request) -> Tuple[bool, Union[str, None]]:
    """
    Check the request using the predefined policy manager.

    Returns a tuple
    """
    # TODO: don't hard code public key
    public_key = "skypilot_eval"
    logger = get_logger()
    print_and_log(
        logger, f"Check request public key: {public_key} (request: {request})"
    )

    policy_manager = get_policy_manager()
    authorization_policy_manager = get_authorization_policy_manager()
    policy = policy_manager.get_policy(public_key)
    print_and_log(logger, f"Got policy {policy}")
    policy.set_authorization_manager(authorization_policy_manager)

    valid = policy.check_request(request)
    if not valid:
        return (False, None)
    # Check if a service account should be attached to the VM
    if policy.valid_authorization:
        return (True, policy.valid_authorization)
    # If no service account should be attached, return True
    print(">>> CHECK REQUEST: No service account should be attached")
    return (True, None)
