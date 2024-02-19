"""
Utility functions for handling policy checking.
"""

from functools import cache
from typing import Tuple, Union

from skydentity.policies.managers.gcp_authorization_policy_manager import (
    GCPAuthorizationPolicyManager,
)
from skydentity.policies.managers.gcp_policy_manager import GCPPolicyManager
from skydentity.utils.hash_util import hash_public_key

from .credentials import get_capability_enc_key, get_service_account_path
from .logging import get_logger, print_and_log


@cache
def get_policy_manager() -> GCPPolicyManager:
    service_acct_cred_file = get_service_account_path()
    return GCPPolicyManager(service_acct_cred_file)


@cache
def get_authorization_policy_manager() -> GCPAuthorizationPolicyManager:
    service_acct_cred_file = get_service_account_path()
    capability_enc_key_file = get_capability_enc_key()
    print("CREATING AUTH POLICY MANAGER")
    print("CRED FILE", service_acct_cred_file)
    return GCPAuthorizationPolicyManager(
        service_acct_cred_file, capability_enc_key_file
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

    # Compute hash of public key
    public_key_hash = hash_public_key(public_key_bytes)
    print_and_log(logger, f"Public key hash: {public_key_hash}")

    # Retrieve policy from firestore with public key hash
    policy = policy_manager.get_policy(public_key_hash, None)
    if not policy:
        return (False, None)
    print_and_log(logger, f"Got policy {policy}")
    policy.set_authorization_manager(authorization_policy_manager)

    # Check if the request is valid against the policy
    valid = policy.check_request(request)
    if not valid:
        return (False, None)
    
    # Check if a service account should be attached to the VM
    if policy.valid_authorization:
        return (True, policy.valid_authorization)
    
    # If no service account should be attached, return True
    print(">>> CHECK REQUEST: No service account should be attached")
    return (True, None)
