from typing import Dict

from skydentity.policies.checker.policy import Policy

class GCPPolicy(Policy):
    """
    Defines methods for GCP policies.
    """

    def __init__(self, policy: Dict):
        pass

    def to_dict(self) -> Dict:
        """
        Converts the policy to a dictionary so that it can be stored.
        :return: The dictionary representation of the policy.
        """
        raise NotImplementedError
    
    @staticmethod
    def from_dict(policy_dict: Dict):
        """
        Converts a dictionary to a policy.
        :param policy_dict: The dictionary representation of the policy.
        :return: The policy representation of the dict.
        """
        raise NotImplementedError