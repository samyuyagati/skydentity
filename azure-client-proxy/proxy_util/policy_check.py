"""
Utility functions for handling policy checking.
"""
import time

from functools import cache
from typing import Tuple, Union

from skydentity.policies.managers.azure_authorization_policy_manager import (
    AzureAuthorizationPolicyManager,
)
from skydentity.policies.managers.azure_policy_manager import AzurePolicyManager
from skydentity.utils.hash_util import hash_public_key

from .credentials import get_capability_enc_key, get_db_info_file, get_db_endpoint, get_db_key, get_capability_enc_key_base64
from .logging import get_logger, print_and_log, build_time_logging_string


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
    capability_enc_key = get_capability_enc_key_base64()
    return AzureAuthorizationPolicyManager(
        capability_enc_path=capability_enc_key_file,
        capability_enc=capability_enc_key,
        db_info_file=get_db_info_file(),
        db_endpoint=get_db_endpoint(),
        db_key=get_db_key()
    )


def check_request_from_policy(public_key_bytes, request, request_id=None, caller_name=None) -> Tuple[bool, Union[str, None]]:
    """
    Check the request using the predefined policy manager.

    Returns a tuple
    """
    caller = f"{caller_name} << check_request_from_policy"

    start = time.time()

    logger = get_logger()
    # print_and_log(
    #     logger, f"Check request public key: {public_key_bytes} (request: {request})"
    # )

    print_and_log(logger, build_time_logging_string(request_id, caller, "setup_logs", start, time.time()))

    start_get_policy_managers = time.time()
    policy_manager = get_policy_manager()
    authorization_policy_manager = get_authorization_policy_manager()
    print_and_log(logger, build_time_logging_string(request_id, caller, "get_policy_managers", start_get_policy_managers, time.time()))

    # Compute the hash of the public key
    public_key_hash = hash_public_key(public_key_bytes)
    # print_and_log(logger, f"Public key hash: {public_key_hash}")

    # Retrieve policy from CosmosDB
    start_get_policy = time.time()
    policy = policy_manager.get_policy(public_key_hash)
    if not policy:
        print_and_log(logger, build_time_logging_string(request_id, caller, "total (no policy found)", start, time.time()))
        return (False, None)
    # print_and_log(logger, f"Got policy {policy}")
    print_and_log(logger, build_time_logging_string(request_id, caller, "get_policy", start_get_policy, time.time()))
    start_set_authorization_manager = time.time()
    policy.set_authorization_manager(authorization_policy_manager)
    print_and_log(logger, build_time_logging_string(request_id, caller, "set_authorization_manager", start_set_authorization_manager, time.time()))

    # Check if the request is valid against the policy
    start_check_request = time.time()
    valid = policy.check_request(request)
    if not valid:
        print_and_log(logger, build_time_logging_string(request_id, caller, "total (policy check failed)", start, time.time()))
        return (False, None)
    print_and_log(logger, build_time_logging_string(request_id, caller, "check_request", start_check_request, time.time()))

    # Check if a managed identity should be attached to the VM
    if policy.valid_authorization:
        print_and_log(logger, build_time_logging_string(request_id, caller, "total (policy check passed, w/ SA attach)", start, time.time()))
        return (True, policy.valid_authorization)
    # If no managed identity should be attached, return True
    # print(">>> CHECK REQUEST: No managed identity should be attached")
    print_and_log(logger, build_time_logging_string(request_id, caller, "total (policy check passed, no SA attach)", start, time.time()))
    return (True, None)
