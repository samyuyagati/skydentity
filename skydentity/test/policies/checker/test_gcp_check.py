import unittest
import os
import json
from typing import Dict
from flask import Request

from skydentity.policies.checker.gcp_policy import GCPVMPolicy, GCPPolicy
from skydentity.policies.managers.local_policy_manager import LocalPolicyManager

class GCPPolicyCheckSuite(unittest.TestCase):
    """
    Tests cases related to the GCP policies
    """

    def setUp(self):
        """
        Set up code run once before this test suite.
        """
        self._policy_dir = os.path.join(os.path.dirname(__file__), 
                                    '..', # For moving out of the current directory
                                    'resources', 
                                    'policies', 
                                    'gcp')
        self._policy_manager = LocalPolicyManager(self._policy_dir, GCPPolicy)

    def get_request_body(self, request_name: str) -> Dict:
        """
        Reads the request body from a file, from resources/requests/gcp/{request_name}.json
        """
        request_path = os.path.join(os.path.dirname(__file__), 
                                    '..', # For moving out of the current directory
                                    'resources', 
                                    'requests', 
                                    'gcp', 
                                    request_name + '.json')
        with open(request_path, 'r') as request_file:
            request_body = json.load(request_file)
        return request_body

    def get_policy(self, policy_name: str) -> GCPPolicy:
        """
        Reads the policy from a file, from resources/policies/gcp/{policy_name}.json
        """
        return self._policy_manager.get_policy(policy_name)
    
    def test_gcp_vm_loose_check(self):
        """
        Tests a loose GCP Policy, which allows all actions.
        """
        loose_policy = self.get_policy('loose_vm')
        request_body = self.get_request_body('gcp_vm_creation')

        successful_request = Request.from_values(json=request_body, method='POST')
        self.assertTrue(loose_policy.check_request(successful_request))

        # Should also work for reads
        successful_request = Request.from_values(json=request_body, method='GET')
        self.assertTrue(loose_policy.check_request(successful_request))

        # Should fail to work for wrong regions
        request_body["machineType"] = "zones/asia-east1-b/machineTypes/n1-standard-1"
        failed_request = Request.from_values(json=request_body, method='POST')
        self.assertFalse(loose_policy.check_request(failed_request))

        # Should fail to work for wrong machine type
        # A2 yikes!
        request_body["machineType"] = "zones/us-west1-b/machineTypes/a2-standard-1"
        failed_request = Request.from_values(json=request_body, method='POST')
        self.assertFalse(loose_policy.check_request(failed_request))

    def test_gcp_vm_image_check(self):
        """
        Tests the checking of GCP VM images
        """
        loose_policy = self.get_policy('loose_vm')
        request_body = self.get_request_body('gcp_vm_creation')

        request_body["disks"][0]["initializeParams"]["sourceImage"] = "projects/debian-cloud/global/images/family/debian-9"
        failed_request = Request.from_values(json=request_body, method='POST')
        self.assertFalse(loose_policy.check_request(failed_request))

    def test_gcp_vm_strict_check(self):
        """
        Tests a stricter GCP Policy, which only allows reads.
        """
        strict_policy = self.get_policy('strict_vm')
        request_body = self.get_request_body('gcp_vm_creation')

        successful_request = Request.from_values(json=request_body, method='GET')
        self.assertTrue(strict_policy.check_request(successful_request))

        # Should not work for creates
        failed_request = Request.from_values(json=request_body, method='POST')
        self.assertFalse(strict_policy.check_request(failed_request))

        # Should fail to work for wrong regions
        request_body["machineType"] = "zones/asia-east1-b/machineTypes/n1-standard-1"
        failed_request = Request.from_values(json=request_body, method='GET')
        self.assertFalse(strict_policy.check_request(failed_request))

    def test_gcp_attached_policy_strict_check(self):
        """
        Tests a stricter GCP Policy, which only allows reads, and we now enable attaching service accounts
        """
        strict_policy = self.get_policy('strict_attach_policy')
        request_body = self.get_request_body('gcp_vm_creation_attached_policy')

        successful_request = Request.from_values(json=request_body, method='GET')
        self.assertTrue(strict_policy.check_request(successful_request))

        # Attach a different policy to the machine that should be successful
        request_body["serviceAccounts"][0]["email"] = "service_account_2@project.iam.gserviceaccount.com"
        failed_request = Request.from_values(json=request_body, method='GET')
        self.assertTrue(strict_policy.check_request(failed_request))

        # Attach a different policy to the machine that should fail
        request_body["serviceAccounts"][0]["email"] = "malicious_account@project.iam.gserviceaccount.com"
        failed_request = Request.from_values(json=request_body, method='GET')
        self.assertFalse(strict_policy.check_request(failed_request))