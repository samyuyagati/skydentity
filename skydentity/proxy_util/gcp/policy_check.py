"""
Utility functions for handling policy checking.
"""

import logging as py_logging
import time
from functools import cache
from typing import Tuple, Union

from skydentity.policies.managers.gcp_storage_policy_manager import (
    GCPStoragePolicyManager,
)

from ...policies.managers.gcp_authorization_policy_manager import (
    GCPAuthorizationPolicyManager,
)
from ...policies.managers.gcp_policy_manager import GCPPolicyManager
from ...utils.hash_util import hash_public_key
from ...utils.log_util import build_time_logging_string
from .credentials import get_capability_enc_key, get_service_account_path

LOGGER = py_logging.getLogger(__name__)


@cache
def get_policy_manager() -> GCPPolicyManager:
    service_acct_cred_file = get_service_account_path()
    return GCPPolicyManager(service_acct_cred_file)


@cache
def get_authorization_policy_manager() -> GCPAuthorizationPolicyManager:
    service_acct_cred_file = get_service_account_path()
    capability_enc_key_file = get_capability_enc_key()
    LOGGER.debug("CREATING AUTH POLICY MANAGER")
    LOGGER.debug(f"CRED FILE {service_acct_cred_file}")
    return GCPAuthorizationPolicyManager(
        service_acct_cred_file, capability_enc_key_file
    )


@cache
def get_storage_policy_manager() -> GCPStoragePolicyManager:
    service_acct_cred_file = get_service_account_path()
    return GCPStoragePolicyManager(service_acct_cred_file)


def check_request_from_policy(
    public_key_bytes, request, request_id=None, caller_name=None
) -> Tuple[bool, Union[str, None]]:
    """
    Check the request using the predefined policy manager.

    Returns a tuple
    """
    caller = f"{caller_name} << check_request_from_policy"

    start = time.time()

    LOGGER.debug(f"Check request public key: {public_key_bytes} (request: {request})")

    LOGGER.info(
        build_time_logging_string(request_id, caller, "setup_logs", start, time.time()),
    )

    start_get_policy_managers = time.time()
    policy_manager = get_policy_manager()
    authorization_policy_manager = get_authorization_policy_manager()
    LOGGER.info(
        build_time_logging_string(
            request_id,
            caller,
            "get_policy_managers",
            start_get_policy_managers,
            time.time(),
        ),
    )

    # Compute hash of public key
    public_key_hash = hash_public_key(public_key_bytes)
    LOGGER.debug(f"Public key hash: {public_key_hash}")

    # Retrieve policy from firestore with public key hash
    start_get_policy = time.time()
    policy = policy_manager.get_policy(public_key_hash)
    if not policy:
        LOGGER.info(
            build_time_logging_string(
                request_id, caller, "total (no policy found)", start, time.time()
            ),
        )
        return (False, None)
    LOGGER.debug(f"Got policy {policy}")
    LOGGER.info(
        build_time_logging_string(
            request_id, caller, "get_policy", start_get_policy, time.time()
        ),
    )
    start_set_authorization_manager = time.time()
    policy.set_authorization_manager(authorization_policy_manager)
    LOGGER.info(
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
        LOGGER.info(
            build_time_logging_string(
                request_id, caller, "total (policy check failed)", start, time.time()
            ),
        )
        return (False, None)
    LOGGER.info(
        build_time_logging_string(
            request_id, caller, "check_request", start_check_request, time.time()
        ),
    )

    # Check if a service account should be attached to the VM
    if policy.valid_authorization:
        LOGGER.info(
            build_time_logging_string(
                request_id,
                caller,
                "total (policy check passed, w/ SA attach)",
                start,
                time.time(),
            ),
        )
        return (True, policy.valid_authorization)

    # If no service account should be attached, return True
    LOGGER.debug(">>> CHECK REQUEST: No service account should be attached")

    LOGGER.info(
        build_time_logging_string(
            request_id,
            caller,
            "total (policy check passed, no SA attach)",
            start,
            time.time(),
        ),
    )
    return (True, None)
