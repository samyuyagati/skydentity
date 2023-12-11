import os
import yaml
from typing import Type

from pathlib import Path

from skydentity.policies.managers.policy_manager import PolicyManager
from skydentity.policies.checker.policy import CloudPolicy

class LocalPolicyManager(PolicyManager):
    """
    Uses local storage to store / update policies. 
    """

    def __init__(self, policy_dir: str, return_policy_type: Type[CloudPolicy]):
        self._policy_dir = policy_dir
        self._return_policy_type = return_policy_type

    def upload_policy(self, public_key: str, policy: CloudPolicy):
        """
        Writes / updates a policy to the local filesystem.
        :param public_key: The public key of the policy.
        :param policy: The policy to upload.
        """
        base_file_name = Path(public_key).with_suffix('.yaml')
        policy_file_name = os.path.join(self._policy_dir, base_file_name)
        policy_dict = policy.to_dict()
        with open(policy_file_name, 'w') as f:
            yaml.dump(policy_dict, f)

    def get_policy(self, public_key: str) -> CloudPolicy:
        """
        Gets a policy from the cloud vendor.
        :param public_key: The public key of the policy.
        :return: The policy.
        """
        base_file_name = Path(public_key).with_suffix('.yaml')
        policy_file_name = os.path.join(self._policy_dir, base_file_name)
        print("base file name:", base_file_name)
        print("policy file name:", policy_file_name)
        print("policy_dir:", self._policy_dir)
        print("public key:", public_key)
        with open(policy_file_name, 'r') as f:
            policy_dict = yaml.load(f, Loader=yaml.SafeLoader)
        return self._return_policy_type.from_dict(policy_dict)
        
