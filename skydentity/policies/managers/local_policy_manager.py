import os
import yaml

from skydentity.policies.managers.policy_manager import PolicyManager
from skydentity.policies.checker.policy import Policy

class LocalPolicyManager(PolicyManager):
    """
    Uses local storage to store / update policies. 
    """

    def __init__(self, policy_dir: str):
        self._policy_dir = policy_dir

    def upload_policy(self, public_key: str, policy: Policy):
        """
        Writes / updates a policy to the local filesystem.
        :param public_key: The public key of the policy.
        :param policy: The policy to upload.
        """
        base_file_name = public_key + '.yaml'
        policy_file_name = os.path.join(self._policy_dir, base_file_name)
        policy_dict = policy.to_dict()
        with open(policy_file_name, 'w') as f:
            yaml.dump(policy_dict, f)

    def get_policy(self, public_key: str) -> Policy:
        """
        Gets a policy from the cloud vendor.
        :param public_key: The public key of the policy.
        :return: The policy.
        """
        base_file_name = public_key + '.yaml'
        policy_file_name = os.path.join(self._policy_dir, base_file_name)
        with open(policy_file_name, 'r') as f:
            policy_dict = yaml.load(f)
        