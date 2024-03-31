"""
Utility functions for handling policy checking.
"""

from functools import cache
from typing import Tuple, Union

from skydentity.policies.managers.azure_authorization_policy_manager import (
    AzureAuthorizationPolicyManager,
)
from skydentity.policies.managers.azure_policy_manager import AzurePolicyManager
from skydentity.utils.hash_util import hash_public_key

from .credentials import get_capability_enc_key, get_db_info_file, get_db_endpoint, get_db_key
from .logging import get_logger, print_and_log


@cache
def get_policy_manager() -> AzurePolicyManager:
    return AzurePolicyManager(
        db_info_file=get_db_info_file(),
        db_endpoint=get_db_endpoint(),
        db_key=get_db_key()
    )


@cache
def get_authorization_policy_manager() -> AzureAuthorizationPolicyManager:
    capability_enc_key_file = get_capability_enc_key()
    print("CREATING AUTH POLICY MANAGER")
    return AzureAuthorizationPolicyManager(
        capability_enc_path=capability_enc_key_file,
        db_info_file=get_db_info_file(),
        db_endpoint=get_db_endpoint(),
        db_key=get_db_key()
    )


def check_request_from_policy(public_key_bytes, request) -> Tuple[bool, Union[str, None]]:
    """
    Check the request using the predefined policy manager.

    Returns a tuple
    """
    logger = get_logger()
    print_and_log(
        logger, f"Check request public key: {public_key_bytes} (request: {request})"
    )

    policy_manager = get_policy_manager()
    authorization_policy_manager = get_authorization_policy_manager()
    
    # Compute the hash of the public key
    public_key_hash = hash_public_key(public_key_bytes)
    print_and_log(logger, f"Public key hash: {public_key_hash}")

    # Retrieve policy from CosmosDB
    policy = policy_manager.get_policy(public_key_hash)
    if not policy:
        return (False, None)

    print_and_log(logger, f"Got policy {policy}")
    policy.set_authorization_manager(authorization_policy_manager)

    # Check if the request is valid against the policy
    valid = policy.check_request(request)
    if not valid:
        return (False, None)
    # Check if a managed identity should be attached to the VM
    if policy.valid_authorization:
        return (True, policy.valid_authorization)
    # If no managed identity should be attached, return True
    print(">>> CHECK REQUEST: No managed identity should be attached")
    return (True, None)
