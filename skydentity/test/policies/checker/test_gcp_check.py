import json
import os
import unittest
from typing import Dict

from flask import Request

from skydentity.policies.checker.gcp_resource_policy import GCPPolicy
from skydentity.policies.managers.local_policy_manager import LocalPolicyManager


class GCPPolicyCheckSuite(unittest.TestCase):
    """
    Tests cases related to the GCP policies
    """

    def setUp(self):
        """
        Set up code run once before this test suite.
        """
        self._policy_dir = os.path.join(
            os.path.dirname(__file__),
            "..",  # For moving out of the current directory
            "resources",
            "policies",
            "gcp",
        )
        self._policy_manager = LocalPolicyManager(GCPPolicy)

    def get_request_body(self, request_name: str) -> Dict:
        """
        Reads the request body from a file, from resources/requests/gcp/{request_name}.json
        """
        request_path = os.path.join(
            os.path.dirname(__file__),
            "..",  # For moving out of the current directory
            "resources",
            "requests",
            "gcp",
            request_name + ".json",
        )
        with open(request_path, "r") as request_file:
            request_body = json.load(request_file)
        return request_body

    def get_policy(self, policy_path: str) -> GCPPolicy:
        """
        Reads the policy from a file, from policy_path
        """
        return self._policy_manager.get_policy(policy_path)

    def test_gcp_vm_loose_check(self):
        """
        Tests a loose GCP Policy, which allows all actions.
        """
        policy_path = os.path.join(self._policy_dir, "loose_vm.yaml")
        loose_policy = self.get_policy(policy_path)
        request_body = self.get_request_body("gcp_vm_creation")

        successful_request = Request.from_values(json=request_body, method="POST")
        self.assertTrue(loose_policy.check_request(successful_request))

        # Should also work for reads
        successful_request = Request.from_values(json=request_body, method="GET")
        self.assertTrue(loose_policy.check_request(successful_request))

        # Should fail to work for wrong regions
        request_body["machineType"] = "zones/asia-east1-b/machineTypes/n1-standard-1"
        failed_request = Request.from_values(json=request_body, method="POST")
        self.assertFalse(loose_policy.check_request(failed_request))

        # Should fail to work for wrong machine type
        # A2 yikes!
        request_body["machineType"] = "zones/us-west1-b/machineTypes/a2-standard-1"
        failed_request = Request.from_values(json=request_body, method="POST")
        self.assertFalse(loose_policy.check_request(failed_request))

    def test_gcp_vm_image_check(self):
        """
        Tests the checking of GCP VM images
        """
        policy_path = os.path.join(self._policy_dir, "loose_vm.yaml")
        loose_policy = self.get_policy(policy_path)
        request_body = self.get_request_body("gcp_vm_creation")

        request_body["disks"][0]["initializeParams"][
            "sourceImage"
        ] = "projects/debian-cloud/global/images/family/debian-9"
        failed_request = Request.from_values(json=request_body, method="POST")
        self.assertFalse(loose_policy.check_request(failed_request))

    def test_gcp_vm_strict_check(self):
        """
        Tests a stricter GCP Policy, which only allows reads.
        """
        policy_path = os.path.join(self._policy_dir, "strict_vm.yaml")
        strict_policy = self.get_policy(policy_path)
        request_body = self.get_request_body("gcp_vm_creation")

        successful_request = Request.from_values(json=request_body, method="GET")
        self.assertTrue(strict_policy.check_request(successful_request))

        # Should not work for creates
        failed_request = Request.from_values(json=request_body, method="POST")
        self.assertFalse(strict_policy.check_request(failed_request))

        # Should fail to work for wrong regions
        request_body["machineType"] = "zones/asia-east1-b/machineTypes/n1-standard-1"
        failed_request = Request.from_values(json=request_body, method="GET")
        self.assertFalse(strict_policy.check_request(failed_request))

    def test_gcp_attached_policy_strict_check(self):
        """
        Tests a stricter GCP Policy, which only allows reads, and we now enable attaching service accounts
        """
        policy_path = os.path.join(self._policy_dir, "strict_attach_policy.yaml")
        strict_policy = self.get_policy(policy_path)
        request_body = self.get_request_body("gcp_vm_creation_attached_policy")

        successful_request = Request.from_values(json=request_body, method="GET")
        self.assertTrue(strict_policy.check_request(successful_request))

        # Attach a different policy to the machine that should be successful
        request_body["serviceAccounts"][0][
            "email"
        ] = "service_account_2@project.iam.gserviceaccount.com"
        failed_request = Request.from_values(json=request_body, method="GET")
        self.assertTrue(strict_policy.check_request(failed_request))

        # Attach a different policy to the machine that should fail
        request_body["serviceAccounts"][0][
            "email"
        ] = "malicious_account@project.iam.gserviceaccount.com"
        failed_request = Request.from_values(json=request_body, method="GET")
        self.assertFalse(strict_policy.check_request(failed_request))

    ALLOWED_PROJECT = "custom-project"
    BLOCKED_PROJECT = "other-project"
    ALLOWED_REGION = "us-central1"
    BLOCKED_REGION = "us-east1"
    ALLOWED_ZONE = "us-central1-a"
    BLOCKED_ZONE = "us-east1-a"

    ALLOWED_NETWORK = "network-name"
    ALLOWED_OPERATION_ID = "operation-id-abc"

    def test_gcp_reads_project_check(self):
        """
        Tests the checking of GCP project reads.
        """
        policy_path = os.path.join(self._policy_dir, "reads.yaml")
        reads_policy = self.get_policy(policy_path)

        successful_request = Request.from_values(
            method="GET", path=f"/compute/v1/projects/{self.ALLOWED_PROJECT}"
        )
        self.assertTrue(reads_policy.check_request(successful_request))

        failed_request = Request.from_values(
            method="GET", path=f"/compute/v1/projects/{self.BLOCKED_PROJECT}"
        )
        self.assertFalse(reads_policy.check_request(failed_request))

        successful_request_with_extra = Request.from_values(
            method="GET",
            path=f"/compute/v1/projects/{self.ALLOWED_PROJECT}/other/path/to/endpoint",
        )
        self.assertTrue(reads_policy.check_request(successful_request_with_extra))

    def test_gcp_reads_region_check(self):
        """
        Tests the checking of GCP project regions.
        """
        policy_path = os.path.join(self._policy_dir, "reads.yaml")
        reads_policy = self.get_policy(policy_path)

        successful_request = Request.from_values(
            method="GET",
            path=f"/compute/v1/projects/{self.ALLOWED_PROJECT}/regions/{self.ALLOWED_REGION}",
        )
        self.assertTrue(reads_policy.check_request(successful_request))

        failed_request = Request.from_values(
            method="GET",
            path=f"/compute/v1/projects/{self.ALLOWED_PROJECT}/regions/{self.BLOCKED_REGION}",
        )
        self.assertFalse(reads_policy.check_request(failed_request))

        successful_request_with_extra = Request.from_values(
            method="GET",
            path=f"/compute/v1/projects/{self.ALLOWED_PROJECT}/regions/{self.ALLOWED_REGION}/other/path/to/endpoint",
        )
        self.assertTrue(reads_policy.check_request(successful_request_with_extra))

    def test_gcp_reads_zone_check(self):
        """
        Tests the checking of GCP project zones.
        """
        policy_path = os.path.join(self._policy_dir, "reads.yaml")
        reads_policy = self.get_policy(policy_path)

        successful_request = Request.from_values(
            method="GET",
            path=f"/compute/v1/projects/{self.ALLOWED_PROJECT}/zones/{self.ALLOWED_ZONE}",
        )
        self.assertTrue(reads_policy.check_request(successful_request))

        failed_request = Request.from_values(
            method="GET",
            path=f"/compute/v1/projects/{self.ALLOWED_PROJECT}/zones/{self.BLOCKED_ZONE}",
        )
        self.assertFalse(reads_policy.check_request(failed_request))

        successful_request_with_extra = Request.from_values(
            method="GET",
            path=f"/compute/v1/projects/{self.ALLOWED_PROJECT}/zones/{self.ALLOWED_ZONE}/other/path/to/endpoint",
        )
        self.assertTrue(reads_policy.check_request(successful_request_with_extra))

    def test_gcp_reads_reservations_check(self):
        """
        Tests the checking of GCP reservations requests.
        """
        policy_path = os.path.join(self._policy_dir, "reads.yaml")
        reads_policy = self.get_policy(policy_path)

        strict_policy_path = os.path.join(self._policy_dir, "reads_strict.yaml")
        strict_reads_policy = self.get_policy(strict_policy_path)

        successful_request = Request.from_values(
            method="GET",
            path=f"/compute/v1/projects/{self.ALLOWED_PROJECT}/aggregated/reservations",
        )
        self.assertTrue(reads_policy.check_request(successful_request))

        failed_request = Request.from_values(
            method="GET",
            path=f"/compute/v1/projects/{self.ALLOWED_PROJECT}/aggregated/reservations",
        )
        self.assertFalse(strict_reads_policy.check_request(failed_request))

    def test_gcp_reads_firewalls_check(self):
        """
        Tests the checking of GCP firewall requests.
        """
        policy_path = os.path.join(self._policy_dir, "reads.yaml")
        reads_policy = self.get_policy(policy_path)

        strict_policy_path = os.path.join(self._policy_dir, "reads_strict.yaml")
        strict_reads_policy = self.get_policy(strict_policy_path)

        # global firewalls

        successful_request = Request.from_values(
            method="GET",
            path=f"/compute/v1/projects/{self.ALLOWED_PROJECT}/global/firewalls",
        )
        self.assertTrue(reads_policy.check_request(successful_request))

        failed_request = Request.from_values(
            method="GET",
            path=f"/compute/v1/projects/{self.ALLOWED_PROJECT}/global/firewalls",
        )
        self.assertFalse(strict_reads_policy.check_request(failed_request))

        # effective firewalls

        successful_request = Request.from_values(
            method="GET",
            path=f"/compute/v1/projects/{self.ALLOWED_PROJECT}/global/networks/{self.ALLOWED_NETWORK}/getEffectiveFirewalls",
        )
        self.assertTrue(reads_policy.check_request(successful_request))

        failed_request = Request.from_values(
            method="GET",
            path=f"/compute/v1/projects/{self.ALLOWED_PROJECT}/global/networks/{self.ALLOWED_NETWORK}/getEffectiveFirewalls",
        )
        self.assertFalse(strict_reads_policy.check_request(failed_request))

    def test_gcp_reads_subnetworks_check(self):
        """
        Test checking of GCP subnetwork requests.
        """
        policy_path = os.path.join(self._policy_dir, "reads.yaml")
        reads_policy = self.get_policy(policy_path)

        strict_policy_path = os.path.join(self._policy_dir, "reads_strict.yaml")
        strict_reads_policy = self.get_policy(strict_policy_path)

        successful_request = Request.from_values(
            method="GET",
            path=f"/compute/v1/projects/{self.ALLOWED_PROJECT}/regions/{self.ALLOWED_REGION}/subnetworks",
        )
        self.assertTrue(reads_policy.check_request(successful_request))

        failed_request = Request.from_values(
            method="GET",
            path=f"/compute/v1/projects/{self.ALLOWED_PROJECT}/regions/{self.ALLOWED_REGION}/subnetworks",
        )
        self.assertFalse(strict_reads_policy.check_request(failed_request))

    def test_gcp_reads_operations_check(self):
        """
        Test checking of GCP operations requests.
        """
        policy_path = os.path.join(self._policy_dir, "reads.yaml")
        reads_policy = self.get_policy(policy_path)

        strict_policy_path = os.path.join(self._policy_dir, "reads_strict.yaml")
        strict_reads_policy = self.get_policy(strict_policy_path)

        # global operations

        successful_request = Request.from_values(
            method="GET",
            path=f"/compute/v1/projects/{self.ALLOWED_PROJECT}/global/operations/{self.ALLOWED_OPERATION_ID}",
        )
        self.assertTrue(reads_policy.check_request(successful_request))

        failed_request = Request.from_values(
            method="GET",
            path=f"/compute/v1/projects/{self.ALLOWED_PROJECT}/global/operations/{self.ALLOWED_OPERATION_ID}",
        )
        self.assertFalse(strict_reads_policy.check_request(failed_request))

        # zone-specific operations

        successful_request = Request.from_values(
            method="GET",
            path=f"/compute/v1/projects/{self.ALLOWED_PROJECT}/zones/{self.ALLOWED_ZONE}/operations/{self.ALLOWED_OPERATION_ID}",
        )
        self.assertTrue(reads_policy.check_request(successful_request))

        failed_request = Request.from_values(
            method="GET",
            path=f"/compute/v1/projects/{self.ALLOWED_PROJECT}/zones/{self.ALLOWED_ZONE}/operations/{self.ALLOWED_OPERATION_ID}",
        )
        self.assertFalse(strict_reads_policy.check_request(failed_request))
