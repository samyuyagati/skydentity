from typing import Dict

from skydentity.policies.managers.policy_manager import PolicyManager

class PolicyChecker:
    """
    A policy checker is responsible for appropriately checking a policy.
    """

    def __init__(self, policy_manager: PolicyManager):
        """
        Initializes the policy checker.
        :param policy_manager: The policy manager.
        """
        self._policy_manager = policy_manager

    def check_request(self, public_key: str, request: Dict) -> bool:
        """
        Checks a request against a policy.
        :param public_key: The public key of the policy.
        :param request: The request data to check.
        :return: True if the request is allowed, False otherwise.
        """
        policy = self._policy_manager.get_policy(public_key)
        if policy is None:
            return False
        return policy.check_request(request)