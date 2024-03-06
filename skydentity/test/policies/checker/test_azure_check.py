import unittest
import os
import json
from typing import Dict
from flask import Request

from skydentity.policies.checker.azure_policy import AzurePolicy
from skydentity.policies.managers.local_policy_manager import LocalPolicyManager

class AzurePolicyCheckSuite(unittest.TestCase):
    """
    Tests cases related to the Azure policies
    """

    def setUp(self):
        """
        Set up code run once before this test suite.
        """
        self._policy_dir = os.path.join(os.path.dirname(__file__), 
                                    '..', # For moving out of the current directory
                                    'resources', 
                                    'policies', 
                                    'azure')
        self._policy_manager = LocalPolicyManager(AzurePolicy)

    def get_request_body(self, request_name: str) -> Dict:
        """
        Reads the request body from a file, from resources/requests/azure/{request_name}.json
        """
        request_path = os.path.join(os.path.dirname(__file__), 
                                    '..', # For moving out of the current directory
                                    'resources', 
                                    'requests', 
                                    'azure', 
                                    request_name + '.json')
        with open(request_path, 'r') as request_file:
            request_body = json.load(request_file)
        return request_body

    def get_policy(self, policy_path: str) -> AzurePolicy:
        """
        Reads the policy from a file, from policy_path
        """
        return self._policy_manager.get_policy(policy_path)
    
    def test_azure_vm_loose_check(self):
        """
        Tests a loose Azure Policy, which allows all actions.
        """
        policy_path = os.path.join(self._policy_dir, 'loose_vm.yaml')
        loose_policy = self.get_policy(policy_path)
        request_body = self.get_request_body('azure_vm_creation')

        successful_request = Request.from_values(json=request_body, method='POST')
        self.assertTrue(loose_policy.check_request(successful_request))

        # Should also work for reads
        successful_request = Request.from_values(json=request_body, method='GET')
        self.assertTrue(loose_policy.check_request(successful_request))

        # Should fail to work for wrong regions
        request_body["location"] = "eastus2"
        failed_request = Request.from_values(json=request_body, method='POST')
        self.assertFalse(loose_policy.check_request(failed_request))

        # Should fail to work for wrong machine type
        request_body["properties"]["hardwareProfile"]["vmSize"] = "Standard_D2s_v3"
        failed_request = Request.from_values(json=request_body, method='POST')
        self.assertFalse(loose_policy.check_request(failed_request))

    def test_azure_vm_image_check(self):
        """
        Tests the checking of Azure VM images
        """
        policy_path = os.path.join(self._policy_dir, 'loose_vm.yaml')
        loose_policy = self.get_policy(policy_path)
        request_body = self.get_request_body('azure_vm_creation')

        request_body["properties"]["storageProfile"]["imageReference"]["offer"] = "WindowsServer"
        request_body["properties"]["storageProfile"]["imageReference"]["sku"] = "2019-Datacenter"
        request_body["properties"]["storageProfile"]["imageReference"]["version"] = "latest"
        failed_request = Request.from_values(json=request_body, method='POST')
        self.assertFalse(loose_policy.check_request(failed_request))

    def test_azure_vm_strict_check(self):
        """
        Tests a stricter Azure Policy, which only allows reads.
        """
        policy_path = os.path.join(self._policy_dir, 'strict_vm.yaml')
        strict_policy = self.get_policy(policy_path)
        request_body = self.get_request_body('azure_vm_creation')

        successful_request = Request.from_values(json=request_body, method='GET')
        self.assertTrue(strict_policy.check_request(successful_request))

        # Should not work for creates
        failed_request = Request.from_values(json=request_body, method='POST')
        self.assertFalse(strict_policy.check_request(failed_request))

        # Should fail to work for wrong regions
        request_body["location"] = "eastus2"
        failed_request = Request.from_values(json=request_body, method='POST')
        self.assertFalse(strict_policy.check_request(failed_request))

    def test_azure_attached_policy_strict_check(self):
        """
        Tests a stricter Azure Policy, which only allows reads, and we now enable attaching service accounts
        """
        policy_path = os.path.join(self._policy_dir, 'strict_attach_policy.yaml')
        strict_policy = self.get_policy(policy_path)
        request_body = self.get_request_body('azure_vm_creation_attached_policy')

        successful_request = Request.from_values(json=request_body, method='GET')
        self.assertTrue(strict_policy.check_request(successful_request)) 

        # Attach a different policy to the machine that should fail
        new_identity = {
            "type": "UserAssigned",
            "userAssignedIdentities": {
                "/subscriptions/{subscription-id}/resourceGroups/myResourceGroup/providers/Microsoft.ManagedIdentity/userAssignedIdentities/malicious": {}
            }
        }
        
        request_body["identity"] = new_identity
        failed_request = Request.from_values(json=request_body, method='GET')
        self.assertFalse(strict_policy.check_request(failed_request))