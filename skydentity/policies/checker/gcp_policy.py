from typing import Dict, List
from flask import Request
import re

from skydentity.policies.checker.policy import (
    CloudPolicy, 
    ResourcePolicy, 
    VMPolicy, 
    PolicyContentException
)
from skydentity.policies.checker.policy_actions import PolicyAction

class GCPVMPolicy(VMPolicy):
    """
    Defines methods for GCP VM policies.
    """

    def __init__(self, policy: Dict):
        """
        :param policy: The dict of the policy to enforce.
        """
        self._policy = policy
        self._region_and_instance_type_regex = re.compile(r'zones/(?P<region>[a-z0-9-]+)/machineTypes/(?P<instance_type>[a-z0-9-]+)')
        self._image_regex = re.compile(r'.*/(?P<image>[a-z0-9-]+)$')
    
    def get_policy_standard_form(self) -> Dict:
        """
        Gets the policy in a standard form.
        :return: The policy in a standard form.
        """
        return self._policy
    
    def get_standard_request_form(self, request: Request) -> Dict:
        """
        Extracts the important values from the request to check in a standardized form.
        The standard form is:
        {
            "actions": <action>,
            "regions": <regions>,
            "instance_type": <instance_type>,
            "allowed_images": [list of allowed images],
        }
        """
        out_dict = {
            "actions": None,
            "regions": [],
            "instance_type": [],
            "allowed_images": []
        }
        if request.method == 'POST':
            out_dict["actions"] = PolicyAction.CREATE
        elif request.method == 'GET':
            out_dict["actions"] = PolicyAction.READ

        request_contents = request.get_json(cache=True)
        if "machineType" in request_contents:
            full_machine_type = request_contents["machineType"]

            # Extract the region from the machine type
            extracted_region_and_machine_type = self._region_and_instance_type_regex.match(full_machine_type)

            out_dict["instance_type"].append(extracted_region_and_machine_type.group("instance_type"))
            out_dict["regions"].append(extracted_region_and_machine_type.group("region"))

        # Now look up for the image
        if "disks" in request_contents:
            for disk in request_contents["disks"]:
                if "initializeParams" in disk:
                    if "sourceImage" in disk["initializeParams"]:
                        extracted_image = self._image_regex.match(disk["initializeParams"]["sourceImage"])
                        out_dict["allowed_images"].append(extracted_image.group("image"))

        return out_dict

    def to_dict(self) -> Dict:
        """
        Converts the policy to a dictionary so that it can be stored.
        :return: The dictionary representation of the policy.
        """
        out_dict = {
            "actions": self._policy["actions"].value,
            "cloud_provider": [
                GCPPolicy.GCP_CLOUD_NAME
            ],
            "regions": {
                "gcp": self._policy["regions"]
            },
            "instance_type": {
                "gcp": self._policy["instance_types"]
            },
            "allowed_images": {
                "gcp": self._policy["allowed_images"]
            }
        }
        return out_dict
    
    @staticmethod
    def from_dict(policy_dict_cloud_level: Dict):
        """
        Distills a general multi-cloud policy into a cloud specific policy.
        :param policy_dict_cloud_level: The dictionary representation of the policy in terms of all clouds.
        :throws: Error if the policy is not valid.
        :return: The policy representation of the dict.
        """
        cloud_specific_policy = {}
        cloud_specific_policy["can_cloud_run"] = GCPPolicy.GCP_CLOUD_NAME \
                            in policy_dict_cloud_level["cloud_provider"]
        if not cloud_specific_policy["can_cloud_run"]:
            raise PolicyContentException("Policy does not accept GCP")

        try:
            # TODO(kdharmarajan): Generalize this policy action
            action = PolicyAction[policy_dict_cloud_level["actions"][0]]
            cloud_specific_policy["actions"] = action
        except KeyError:
            raise PolicyContentException("Policy action is not valid")

        gcp_cloud_regions = []
        for region_group in policy_dict_cloud_level["regions"]:
            if GCPPolicy.GCP_CLOUD_NAME in region_group:
                gcp_cloud_regions = region_group[GCPPolicy.GCP_CLOUD_NAME]
                break

        # TODO(kdharmarajan): Check that the regions are valid later (not essential)
        cloud_specific_policy["regions"] = gcp_cloud_regions

        gcp_instance_types = []
        for instance_type_group in policy_dict_cloud_level["instance_type"]:
            if GCPPolicy.GCP_CLOUD_NAME in instance_type_group:
                gcp_instance_types = instance_type_group[GCPPolicy.GCP_CLOUD_NAME]
        cloud_specific_policy["instance_type"] = gcp_instance_types

        gcp_allowed_images = []
        for allowed_images_group in policy_dict_cloud_level["allowed_images"]:
            if GCPPolicy.GCP_CLOUD_NAME in allowed_images_group:
                gcp_allowed_images = allowed_images_group[GCPPolicy.GCP_CLOUD_NAME]

        cloud_specific_policy["allowed_images"] = gcp_allowed_images

        # TODO(kdharmarajan): Add allowed_setup script inclusion here
        return GCPVMPolicy(cloud_specific_policy)
    
class GCPAttachedPolicyPolicy(ResourcePolicy):
    """
    Defines methods for GCP Attached Policies (what GCP policies can be attached to a VM)
    """

    def __init__(self, policy: Dict):
        """
        :param policy: The dict of the policy to enforce.
        """
        self._policy = policy
    
    def check_request(self, request: Request) -> bool:
        """
        Enforces the policy on a request.
        :param request: The request to enforce the policy on.
        :return: True if the request is allowed, False otherwise.
        """
        # TODO(kdharmarajan): Implement this
        return True

    def to_dict(self) -> Dict:
        """
        Converts the policy to a dictionary so that it can be stored.
        :return: The dictionary representation of the policy.
        """
        raise NotImplementedError
    
    @staticmethod
    def from_dict(policy_dict_cloud_level: Dict) -> 'GCPAttachedPolicyPolicy':
        """
        Converts a dictionary to a policy.
        :param policy_dict: The dictionary representation of the policy.
        :return: The policy representation of the dict.
        """
        cloud_specific_policy = {}
        if "cloud_provider" in policy_dict_cloud_level:
            cloud_specific_policy['can_cloud_run'] = GCPPolicy.GCP_CLOUD_NAME \
                                in policy_dict_cloud_level["cloud_provider"]
        return GCPAttachedPolicyPolicy(cloud_specific_policy)

class GCPPolicy(CloudPolicy):
    """
    Defines methods for GCP policies.
    """

    GCP_CLOUD_NAME = "gcp"
    VM_REQUEST_KEYS = set([
        "networkInterfaces",
        "disks",
        "machineType"
    ])

    def __init__(self, vm_policy: GCPVMPolicy, attached_policy_policy: GCPAttachedPolicyPolicy):
        """
        :param vm_policy: The GCP VM Policy to enforce.
        :param attached_policy_policy: The Attached Policy Policy to enforce.
        """
        self._resource_policies = {
            "virtual_machine": vm_policy,
            "attached_policies": attached_policy_policy
        }

    def get_request_resource_types(self, request: Request) -> List[str]:
        """
        Gets the resource types that the request is trying to access / create / delete.
        :param request: The request to get the resource types from.
        :return: The resource types that the request is trying to access as a list of names.
        """
        resource_types = set([])
        for key in request.get_json(cache=True).keys():
            if key in GCPPolicy.VM_REQUEST_KEYS:
                resource_types.add("virtual_machine")
            # TODO(kdharmarajan): Add attached policy here
        return list(resource_types)
    
    def check_resource_type(self, resource_type: str, request: Request) -> bool:
        """
        Enforces the policy on a resource type.
        :param resource_type: The resource type to enforce the policy on.
        :param request: The request to enforce the policy on.
        :return: True if the request is allowed, False otherwise.
        """
        assert resource_type in self._resource_policies
        return self._resource_policies[resource_type].check_request(request)

    def to_dict(self) -> Dict:
        """
        Converts the policy to a dictionary so that it can be stored.
        :return: The dictionary representation of the policy.
        """
        out_dict = {}
        for resource_type, policy in self._resource_policies.items():
            out_dict[resource_type] = policy.to_dict()
        return out_dict

    @staticmethod
    def from_dict(policy_dict: Dict) -> 'GCPPolicy':
        """
        Converts a dictionary to a policy.
        :param policy_dict: The dictionary representation of the policy.
        :return: The policy representation of the dict.
        """
        vm_dict = {}
        if "virtual_machine" in policy_dict:
            vm_dict = policy_dict["virtual_machine"]
        vm_policy = GCPVMPolicy.from_dict(vm_dict)
        attached_policy_dict = {}
        if "attached_policies" in policy_dict:
            attached_policy_dict = policy_dict["attached_policies"]
        attached_policy_policy = GCPAttachedPolicyPolicy.from_dict(attached_policy_dict)
        return GCPPolicy(vm_policy, attached_policy_policy)