import unittest
import os

from skydentity.policies.checker.azure_resource_policy import AzurePolicy
from skydentity.policies.managers.azure_policy_manager import AzurePolicyManager
from skydentity.policies.managers.local_policy_manager import LocalPolicyManager

class AzurePolicyManagerSuite(unittest.TestCase):

    def setUp(self):
        """
        Set up code run once before this test suite.
        """
        self._policy_dir = os.path.join(os.path.dirname(__file__), 
                                    '..', # For moving out of the current directory
                                    'resources', 
                                    'policies', 
                                    'azure')
        self._policy_manager = AzurePolicyManager(
            db_endpoint = os.environ['AZURE_DB_ENDPOINT'],
            db_key = os.environ['AZURE_DB_KEY'],
            db_name = os.environ['AZURE_DB_NAME'],
            db_container_name = os.environ['AZURE_DB_CONTAINER_NAME']
        )
        self._local_policy_manager = LocalPolicyManager(AzurePolicy)

    def get_local_policy(self, policy_path: str) -> AzurePolicy:
        """
        Reads the policy from a file, from policy_path
        """
        return self._local_policy_manager.get_policy(policy_path)

    def test_write_get_policy(self):
        """
        Tests a simple write / get policy.
        """
        print('Testing write / get policy.')
        policy_path = os.path.join(self._policy_dir, 'loose_vm.yaml')
        test_policy = self.get_local_policy(policy_path)
        self._policy_manager.upload_policy('skypilot', test_policy)
        out_policy = self._policy_manager.get_policy('skypilot')
        self.assertEqual(out_policy.to_dict(), test_policy.to_dict())