from typing import Dict, List
from flask import Request
import re
import sys

from skydentity.policies.checker.resource_policy import (
    CloudPolicy, 
    ResourcePolicy, 
    VMPolicy,
    UnrecognizedResourcePolicy,
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
                GCPPolicy.GCP_CLOUD_NAME: self._policy["regions"]
            },
            "instance_type": {
                GCPPolicy.GCP_CLOUD_NAME: self._policy["instance_type"]
            },
            "allowed_images": {
                GCPPolicy.GCP_CLOUD_NAME: self._policy["allowed_images"]
            }
        }
        return out_dict
    
    @staticmethod
    def from_dict(policy_dict_cloud_level: Dict, logger=None):
        """
        Distills a general multi-cloud policy into a cloud specific policy.
        :param policy_dict_cloud_level: The dictionary representation of the policy in terms of all clouds.
        :param logger: optional. google.cloud logger object 
        :throws: Error if the policy is not valid.
        :return: The policy representation of the dict.
        """
        if logger:
          logger.log_text(str(policy_dict_cloud_level), severity="WARNING")
        else:
          print(str(policy_dict_cloud_level))
        cloud_specific_policy = {}
        cloud_specific_policy["can_cloud_run"] = GCPPolicy.GCP_CLOUD_NAME \
                            in policy_dict_cloud_level["cloud_provider"]
        if not cloud_specific_policy["can_cloud_run"]:
            raise PolicyContentException("Policy does not accept GCP")

        try:
            # TODO(kdharmarajan): Generalize this policy actioni
            # TODO what happens if multiple actions are permitted?
            print(policy_dict_cloud_level["actions"])
            if isinstance(policy_dict_cloud_level["actions"], list):
              action = PolicyAction[policy_dict_cloud_level["actions"][0]]
            else:
              action = PolicyAction[policy_dict_cloud_level["actions"]]
            cloud_specific_policy["actions"] = action
        except KeyError:
            raise PolicyContentException("Policy action is not valid")

        gcp_cloud_regions = []
        for region_group in policy_dict_cloud_level["regions"]:
            print("REGION GROUP", region_group)
            if GCPPolicy.GCP_CLOUD_NAME in region_group:
                if isinstance(policy_dict_cloud_level["regions"], list):
                  gcp_cloud_regions = region_group[GCPPolicy.GCP_CLOUD_NAME] 
                else: 
                  gcp_cloud_regions = policy_dict_cloud_level["regions"][region_group] 
                break

        # TODO(kdharmarajan): Check that the regions are valid later (not essential)
        cloud_specific_policy["regions"] = gcp_cloud_regions

        gcp_instance_types = []
        for instance_type_group in policy_dict_cloud_level["instance_type"]:
            if GCPPolicy.GCP_CLOUD_NAME in instance_type_group:
                if isinstance(policy_dict_cloud_level["instance_type"], list):
                  gcp_instance_types = instance_type_group[GCPPolicy.GCP_CLOUD_NAME]
                else:
                  gcp_instance_types = policy_dict_cloud_level["instance_type"][GCPPolicy.GCP_CLOUD_NAME]
        cloud_specific_policy["instance_type"] = gcp_instance_types

        gcp_allowed_images = []
        for allowed_images_group in policy_dict_cloud_level["allowed_images"]:
            if GCPPolicy.GCP_CLOUD_NAME in allowed_images_group:
                if isinstance(policy_dict_cloud_level["allowed_images"], list):
                  gcp_allowed_images = allowed_images_group[GCPPolicy.GCP_CLOUD_NAME]
                else:
                  gcp_allowed_images = policy_dict_cloud_level["allowed_images"][GCPPolicy.GCP_CLOUD_NAME]

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
        print("check_request", flush=True)
        sys.stdout.flush()
        return True
#        request_contents = request.get_json(cache=True)
#        print(">>>request:", request_contents)
#        if "serviceAccounts" in request_contents:
#            for service_account in request_contents["serviceAccounts"]:
#                if service_account["email"] not in self._policy["authorization"]:
#                    return False
        # TODO(kdharmarajan): Add scope checks here 
#        return True

    def to_dict(self) -> Dict:
        """
        Converts the policy to a dictionary so that it can be stored.
        :return: The dictionary representation of the policy.
        """
        out_dict = {}
        if GCPPolicy.GCP_CLOUD_NAME in self._policy:
            out_dict[GCPPolicy.GCP_CLOUD_NAME] = self._policy[GCPPolicy.GCP_CLOUD_NAME]
        return out_dict

    @staticmethod
    def from_dict(policy_dict_cloud_level: Dict, logger=None) -> 'GCPAttachedPolicyPolicy':
        """
        Converts a dictionary to a policy.
        :param policy_dict: The dictionary representation of the policy.
        :param logger: optional. google.cloud logger object.
        :return: The policy representation of the dict.
        """
        if logger:
          logger.log_text("GCPAttachedPolicy", severity="WARNING")
        else:
          print("GCPAttachedPolicy")
        cloud_specific_policy = {}
        can_cloud_run = False
        print("Policy dict:", policy_dict_cloud_level)
        if isinstance(policy_dict_cloud_level, list):
          for cloud_auth in policy_dict_cloud_level:
              if GCPPolicy.GCP_CLOUD_NAME \
                              in cloud_auth:
                  can_cloud_run = True
                  service_accounts = cloud_auth[GCPPolicy.GCP_CLOUD_NAME]
                  cloud_specific_policy[GCPPolicy.GCP_CLOUD_NAME] = service_accounts
                  break
        else:
          for cloud_name in policy_dict_cloud_level:
              if not (cloud_name == GCPPolicy.GCP_CLOUD_NAME):
                  continue
              can_cloud_run = True
              service_accounts = policy_dict_cloud_level[cloud_name]
              cloud_specific_policy[GCPPolicy.GCP_CLOUD_NAME] = service_accounts
              break
        cloud_specific_policy['can_cloud_run'] = can_cloud_run
        print("Cloud-specific attached policy:", cloud_specific_policy)
        return GCPAttachedPolicyPolicy(cloud_specific_policy)
    
class GCPImageLookupPolicy(ResourcePolicy):
    """
    Defines methods for GCP Image Lookup policies.
    """

    PUBLIC_PROJECTS = set([
        "debian-cloud",
        "centos-cloud",
        "ubuntu-os-cloud",
        "windows-cloud",
        "cos-cloud",
        "rhel-cloud",
        "rhel-sap-cloud",
        "rocky-linux-cloud",
        "opensuse-cloud",
        "suse-sap-cloud",
        "suse-cloud",
        "windows-sql-cloud",
        "fedora-cloud",
        "fedora-coreos-cloud",
        "ubuntu-os-pro-cloud"])

    def __init__(self):
        """
        :param policy: The dict of the policy to enforce.
        """
        self._image_regex_extractor = re.compile(r'compute/v1/projects/(?P<project>)/global/images/family/(?P<family>)$')
    
    def check_request(self, request: Request) -> bool:
        """
        Enforces the policy on a request.
        :param request: The request to enforce the policy on.
        :return: True if the request is allowed, False otherwise.
        """
        if request.method == "GET":
            image_info = self._image_regex_extractor.match(request.path)
            if image_info:
                project = image_info.group("project")
                if project not in GCPImageLookupPolicy.PUBLIC_PROJECTS:
                    return False
        return True



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
    ATTACHED_POLICY_KEYS = set([
        "serviceAccounts"
    ])

    def __init__(self, vm_policy: GCPVMPolicy, attached_policy_policy: GCPAttachedPolicyPolicy):
        """
        :param vm_policy: The GCP VM Policy to enforce.
        :param attached_policy_policy: The Attached Policy Policy to enforce.
        """
        self._resource_policies = {
            "virtual_machine": vm_policy,
            "attached_policies": attached_policy_policy,
            "image_lookup": GCPImageLookupPolicy(),
            "unrecognized": UnrecognizedResourcePolicy()
        }
        print("GCPPolicy init:", self._resource_policies["attached_policies"]._policy)

    def get_request_resource_types(self, request: Request) -> List[str]:
        """
        Gets the resource types that the request is trying to access / create / delete.
        :param request: The request to get the resource types from.
        :return: The resource types that the request is trying to access as a list of names.
        """
        resource_types = set([])

        # Handle GET request
        if request.method == "GET":
            print("NOT JSON")
            if "images" in request.path:
                resource_types.add("image_lookup")
            else:
                resource_types.add("unrecognized")
            return list(resource_types)
        # Handle POST request
        for key in request.get_json(cache=True).keys():
            if key in GCPPolicy.VM_REQUEST_KEYS:
                resource_types.add("virtual_machine")
            elif key in GCPPolicy.ATTACHED_POLICY_KEYS:
                resource_types.add("attached_policies")
            else:
                resource_types.add("unrecognized")
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
            if resource_type == "unrecognized" or resource_type == "image_lookup":
                continue
            out_dict[resource_type] = policy.to_dict()
        return out_dict

    @staticmethod
    def from_dict(policy_dict: Dict, logger=None) -> 'GCPPolicy':
        """
        Converts a dictionary to a policy.
        :param policy_dict: The dictionary representation of the policy.
        :param logger: optional. google.cloud logger object.
        :return: The policy representation of the dict.
        """
        vm_dict = {}
        if "virtual_machine" in policy_dict:
            vm_dict = policy_dict["virtual_machine"]
        vm_policy = GCPVMPolicy.from_dict(vm_dict, logger)
        attached_policy_dict = {}
        if "attached_policies" in policy_dict:
            attached_policy_dict = policy_dict["attached_policies"]
        print("GCPPolicy attached policies dict:", attached_policy_dict)
        attached_policy_policy = GCPAttachedPolicyPolicy.from_dict(attached_policy_dict, logger)
        return GCPPolicy(vm_policy, attached_policy_policy)
