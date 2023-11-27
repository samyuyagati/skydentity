import unittest
import os
import shutil

from skydentity.policies.managers.local_policy_manager import LocalPolicyManager
from skydentity.policies.checker.dict_policy import DictPolicy

class LocalPolicyManagerSuite(unittest.TestCase):

    def setUp(self):
        """
        Set up code run once before this test suite.
        """
        self._policy_dir = './local_policies'
        os.mkdir(self._policy_dir)
        self._policy_manager = LocalPolicyManager(self._policy_dir, DictPolicy)

    def test_write_get_policy(self):
        """
        Tests a simple write / get policy.
        """
        print('Testing write / get policy.')
        test_policy_dict = {
            'test': 'test'
        }
        test_policy = DictPolicy(test_policy_dict)
        self._policy_manager.upload_policy('skypilot', test_policy)
        out_policy = self._policy_manager.get_policy('skypilot')
        self.assertEqual(out_policy.to_dict(), test_policy_dict)

    def tearDown(self):
        """
        Clean up code run once after this test suite.
        """
        shutil.rmtree(self._policy_dir)