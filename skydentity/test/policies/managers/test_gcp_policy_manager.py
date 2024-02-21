import unittest
import os

from skydentity.policies.checker.gcp_policy import GCPPolicy
from skydentity.policies.managers.gcp_policy_manager import GCPPolicyManager
from skydentity.policies.managers.local_policy_manager import LocalPolicyManager

class GCPPolicyManagerSuite(unittest.TestCase):

    def setUp(self):
        """
        Set up code run once before this test suite.
        """
        self._policy_dir = os.path.join(os.path.dirname(__file__), 
                                    '..', # For moving out of the current directory
                                    'resources', 
                                    'policies', 
                                    'gcp')
        self._policy_manager = GCPPolicyManager(
            credentials_path = os.environ['GCP_CREDENTIALS'],
        )
        self._local_policy_manager = LocalPolicyManager(GCPPolicy)

    def get_local_policy(self, policy_path: str) -> GCPPolicy:
        """
        Reads the policy from a file, from policy_path
        """
        return self._local_policy_manager.get_policy(policy_path)

    def test_write_get_policy(self):
        """
        Tests a simple write / get policy.
        """
        print('Testing write / get policy.')
        local_policy_location = os.path.join(self._policy_dir, 'loose_vm.yaml')
        test_policy = self.get_local_policy(local_policy_location)
        self._policy_manager.upload_policy('skypilot', test_policy)
        out_policy = self._policy_manager.get_policy('skypilot')
        self.assertEqual(out_policy.to_dict(), test_policy.to_dict())