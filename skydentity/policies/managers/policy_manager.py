from abc import ABC
from skydentity.policies.checker.policy import Policy

class PolicyManager(ABC):
    """
    A policy manager is repsonsible for setting and retrieving policies for a particular cloud vendor.
    """

    def upload_policy(self, public_key: str, policy: Policy):
        """
        Uploads a policy to the cloud vendor.
        :param public_key: The public key of the policy.
        :param policy: The policy to upload.
        """
        raise NotImplementedError
    
    def get_policy(self, public_key: str) -> Policy:
        """
        Gets a policy from the cloud vendor.
        :param public_key: The public key of the policy.
        :return: The policy.
        """
        raise NotImplementedError