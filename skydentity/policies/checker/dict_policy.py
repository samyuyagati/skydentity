from typing import Dict, List

from skydentity.policies.checker.policy import CloudPolicy

class DictPolicy(CloudPolicy):
    """
    A policy that is defined by a dictionary, used for mocking up policies,
    but should not be used in production.
    """
    
    def __init__(self, policy: Dict):
        self.policy_dict = policy

    def get_request_resource_types(self, request) -> List[str]:
        """
        Gets the resource types that the request is trying to access / create / delete.
        :param request: The request to get the resource types from.
        :return: The resource types that the request is trying to access as a list of names.
        """
        raise NotImplementedError
    
    def check_resource_type(self, resource_type: str, request) -> bool:
        """
        Enforces the policy on a resource type.
        :param resource_type: The resource type to enforce the policy on.
        :param request: The request to enforce the policy on.
        :return: True if the request is allowed, False otherwise.
        """
        raise NotImplementedError

    def to_dict(self) -> Dict:
        """
        Converts the policy to a dictionary so that it can be stored.
        :return: The dictionary representation of the policy.
        """
        return self.policy_dict
    
    @staticmethod
    def from_dict(policy_dict: Dict):
        """
        Converts a dictionary to a policy.
        :param policy_dict: The dictionary representation of the policy.
        :return: The policy representation of the dict.
        """
        return DictPolicy(policy_dict)