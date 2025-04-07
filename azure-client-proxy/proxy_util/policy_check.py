"""
Utility functions for handling policy checking.
"""

import time
from functools import cache
from typing import Optional, Tuple, Union

from flask import Request

from skydentity.policies.checker.azure_resource_policy import AzurePolicy
from skydentity.policies.checker.crosscloud_resources.crosscloud_resource_policy import (
    CrossCloudPolicy,
)
from skydentity.policies.managers.azure_authorization_policy_manager import (
    AzureAuthorizationPolicyManager,
)
from skydentity.policies.managers.azure_policy_manager import AzurePolicyManager
from skydentity.policies.managers.azure_storage_policy_manager import (
    AzureStoragePolicyManager,
)
from skydentity.policies.managers.crosscloud_policy_manager import (
    CrossCloudPolicyManager,
)
from skydentity.proxy_util.crosscloud_resources.signature import (
    KeyPair,
    generate_vm_keypair,
)
from skydentity.utils.hash_util import hash_public_key

from .credentials import (
    get_capability_enc_key,
    get_capability_enc_key_base64,
    get_crosscloud_state_credentials,
    get_db_endpoint,
    get_db_info_file,
    get_db_key,
    get_storage_connection_string,
)
from .logging import build_time_logging_string, get_logger, print_and_log


@cache
def get_policy_manager() -> AzurePolicyManager:
    return AzurePolicyManager(
        db_info_file=get_db_info_file(),
        db_endpoint=get_db_endpoint(),
        db_key=get_db_key(),
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
        db_key=get_db_key(),
    )


@cache
def get_storage_policy_manager() -> AzureStoragePolicyManager:
    return AzureStoragePolicyManager(
        db_info_file=get_db_info_file(),
        db_endpoint=get_db_endpoint(),
        db_key=get_db_key(),
        storage_account_connection_string=get_storage_connection_string(),
    )


@cache
def get_crosscloud_policy_manager() -> CrossCloudPolicyManager:
    return CrossCloudPolicyManager(credentials_path=get_crosscloud_state_credentials())


def check_request_from_policy(
    public_key_bytes: bytes, request: Request, request_id=None, caller_name=None
) -> Tuple[bool, Union[str, None]]:
    """
    Check the request using the predefined policy manager.

    If the request is valid, returns various metadata about the policy:
        - managed identity ID
        - request resource types (for future reference)
    If the request is invalid, returns None.
    """
    caller = f"{caller_name} << check_request_from_policy"

    start = time.time()

    logger = get_logger()
    # print_and_log(
    #     logger, f"Check request public key: {public_key_bytes} (request: {request})"
    # )

    print_and_log(
        logger,
        build_time_logging_string(request_id, caller, "setup_logs", start, time.time()),
    )

    start_get_policy_managers = time.time()
    policy_manager = get_policy_manager()
    authorization_policy_manager = get_authorization_policy_manager()
    print_and_log(
        logger,
        build_time_logging_string(
            request_id,
            caller,
            "get_policy_managers",
            start_get_policy_managers,
            time.time(),
        ),
    )

    # Compute the hash of the public key
    public_key_hash = hash_public_key(public_key_bytes)
    # print_and_log(logger, f"Public key hash: {public_key_hash}")

    # Retrieve policy from CosmosDB
    start_get_policy = time.time()
    policy = policy_manager.get_policy(public_key_hash)
    if not policy:
        print_and_log(
            logger,
            build_time_logging_string(
                request_id, caller, "total (no policy found)", start, time.time()
            ),
        )
        return (False, None)
    # print_and_log(logger, f"Got policy {policy}")
    print_and_log(
        logger,
        build_time_logging_string(
            request_id, caller, "get_policy", start_get_policy, time.time()
        ),
    )
    start_set_authorization_manager = time.time()
    policy.set_authorization_manager(authorization_policy_manager)
    print_and_log(
        logger,
        build_time_logging_string(
            request_id,
            caller,
            "set_authorization_manager",
            start_set_authorization_manager,
            time.time(),
        ),
    )

    # Check if the request is valid against the policy
    start_check_request = time.time()
    valid = policy.check_request(request)
    if not valid:
        print_and_log(
            logger,
            build_time_logging_string(
                request_id, caller, "total (policy check failed)", start, time.time()
            ),
        )
        return (False, None)
    print_and_log(
        logger,
        build_time_logging_string(
            request_id, caller, "check_request", start_check_request, time.time()
        ),
    )

    # Check if a managed identity should be attached to the VM
    if policy.valid_authorization:
        print_and_log(
            logger,
            build_time_logging_string(
                request_id,
                caller,
                "total (policy check passed, w/ SA attach)",
                start,
                time.time(),
            ),
        )
        return (True, policy.valid_authorization)
    # If no managed identity should be attached, return True
    # print(">>> CHECK REQUEST: No managed identity should be attached")
    print_and_log(
        logger,
        build_time_logging_string(
            request_id,
            caller,
            "total (policy check passed, no SA attach)",
            start,
            time.time(),
        ),
    )
    return (True, None)


def check_request_for_crosscloud_resources(
    public_key_bytes: bytes, request: Request
) -> Optional[tuple[CrossCloudPolicy, KeyPair]]:
    """
    Check the given VM creation request to extract roles relevant to the cross-cloud policy
    for the orchestrator specified by the given public key.

    If a valid role is specified, a new key-pair is created,
    and various pieces of metadata about the policy is returned.

    Otherwise, this method returns None, and no further action needs to be taken,
    since the VM does not rqeuire cross-cloud resource access.
    """
    # compute hash of the public key, to fetch the crosscloud policy
    public_key_hash = hash_public_key(public_key_bytes)

    crosscloud_policy_manager = get_crosscloud_policy_manager()
    policy_dict = crosscloud_policy_manager.get_policy_dict(public_key_hash)

    crosscloud_policy = CrossCloudPolicy(policy_dict)
    vm_role = crosscloud_policy.get_vm_role_from_request("azure", request)

    if vm_role is None:
        # no role specified on VM creation
        return None

    # otherwise, role specified on VM creation;
    # generate a new key pair, and return it
    keypair = generate_vm_keypair()
    return (crosscloud_policy, keypair)
