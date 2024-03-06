import os
import yaml
from typing import Type

from pathlib import Path

from skydentity.policies.managers.policy_manager import PolicyManager
from skydentity.policies.checker.resource_policy import CloudPolicy

class LocalPolicyManager(PolicyManager):
    """
    Uses local storage to store / update policies. 
    """

    def __init__(self, return_policy_type: Type[CloudPolicy]):
        self._return_policy_type = return_policy_type

    def upload_policy(self, filepath: str, policy: CloudPolicy):
        """
        Writes / updates a policy to the local filesystem.
        :param public_key: The public key of the policy.
        :param policy: The policy to upload.
        """
        policy_dict = policy.to_dict()
        with open(filepath, 'w') as f:
            yaml.dump(policy_dict, f)

    def get_policy(self, filepath: str) -> CloudPolicy:
        """
        Gets a policy from the local filesystem.
        :param public_key: The public key of the policy.
        :return: The policy.
        """
        print("--------LOCAL POLICY MANAGER--------")
        print("Opening file:", filepath)
        with open(filepath, 'r') as f:
            policy_dict = yaml.load(f, Loader=yaml.SafeLoader)
        print("get_policy", policy_dict)
        print("policy type:", self._return_policy_type) 
        print("--------END LOCAL POLICY MANAGER--------")
        return self._return_policy_type.from_dict(policy_dict)
        
