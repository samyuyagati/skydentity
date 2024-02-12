from typing import Dict, List
from flask import Request

from skydentity.policies.checker.resource_policy import (
    CloudPolicy, 
    ResourcePolicy, 
    VMPolicy, 
    PolicyContentException
)
from skydentity.policies.checker.policy_actions import PolicyAction

class AzureVMPolicy(VMPolicy):
    """
    Defines methods for Azure VM policies.
    """

    def __init__(self, policy: Dict):
        """
        :param policy: The dict of the policy to enforce.
        """
        self._policy = policy
    
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
        if request.method == 'POST' or request.method == 'PUT':
            out_dict["actions"] = PolicyAction.CREATE
        elif request.method == 'GET':
            out_dict["actions"] = PolicyAction.READ

        request_contents = request.get_json(cache=True)
        if "location" in request_contents:
            out_dict["regions"].append(request_contents["location"])

        if "properties" in request_contents:
            if "hardwareProfile" in request_contents["properties"]:
                out_dict["instance_type"].append(request_contents["properties"]["hardwareProfile"]["vmSize"])

        # Now get the image
        if "properties" in request_contents:
            if "storageProfile" in request_contents["properties"]:
                if "imageReference" in request_contents["properties"]["storageProfile"]:
                    image_reference = request_contents["properties"]["storageProfile"]["imageReference"]
                    if "offer" in image_reference and "sku" in image_reference:
                        image = f"{image_reference['offer']}:{image_reference['sku']}"
                        out_dict["allowed_images"].append(image)

        return out_dict

    def to_dict(self) -> Dict:
        """
        Converts the policy to a dictionary so that it can be stored.
        :return: The dictionary representation of the policy.
        """
        out_dict = {
            "actions": self._policy["actions"].value,
            "cloud_provider": [
                AzurePolicy.Azure_CLOUD_NAME
            ],
            "regions": {
                AzurePolicy.Azure_CLOUD_NAME: self._policy["regions"]
            },
            "instance_type": {
                AzurePolicy.Azure_CLOUD_NAME: self._policy["instance_type"]
            },
            "allowed_images": {
                AzurePolicy.Azure_CLOUD_NAME: self._policy["allowed_images"]
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
        cloud_specific_policy["can_cloud_run"] = AzurePolicy.Azure_CLOUD_NAME \
                            in policy_dict_cloud_level["cloud_provider"]
        if not cloud_specific_policy["can_cloud_run"]:
            raise PolicyContentException("Policy does not accept Azure")

        try:
            # TODO(kdharmarajan): Generalize this policy action
            action = PolicyAction[policy_dict_cloud_level["actions"][0]]
            cloud_specific_policy["actions"] = action
        except KeyError:
            raise PolicyContentException("Policy action is not valid")

        Azure_cloud_regions = []
        for region_group in policy_dict_cloud_level["regions"]:
            if AzurePolicy.Azure_CLOUD_NAME in region_group:
                Azure_cloud_regions = region_group[AzurePolicy.Azure_CLOUD_NAME]
                break

        # TODO(kdharmarajan): Check that the regions are valid later (not essential)
        cloud_specific_policy["regions"] = Azure_cloud_regions

        Azure_instance_types = []
        for instance_type_group in policy_dict_cloud_level["instance_type"]:
            if AzurePolicy.Azure_CLOUD_NAME in instance_type_group:
                Azure_instance_types = instance_type_group[AzurePolicy.Azure_CLOUD_NAME]
        cloud_specific_policy["instance_type"] = Azure_instance_types

        Azure_allowed_images = []
        for allowed_images_group in policy_dict_cloud_level["allowed_images"]:
            if AzurePolicy.Azure_CLOUD_NAME in allowed_images_group:
                Azure_allowed_images = allowed_images_group[AzurePolicy.Azure_CLOUD_NAME]

        cloud_specific_policy["allowed_images"] = Azure_allowed_images

        # TODO(kdharmarajan): Add allowed_setup script inclusion here
        return AzureVMPolicy(cloud_specific_policy)
    
class AzureAttachedPolicyPolicy(ResourcePolicy):
    """
    Defines methods for Azure Attached Policies (what Azure policies can be attached to a VM)
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
        request_contents = request.get_json(cache=True)

        if "identity" in request_contents:
            # Check that this is a user assigned identity
            # TODO(kdharmarajan): Do checking for system assigned identities later
            vm_identity = request_contents["identity"]
            if vm_identity["type"] != "UserAssigned":
                return False

            for assigned_user_identity in vm_identity["userAssignedIdentities"]:
                individual_identity_name = assigned_user_identity.split("/")[-1]

                if individual_identity_name not in self._policy["authorization"]:
                    return False

        # TODO(kdharmarajan): Add scope checks here 
        return True

    def to_dict(self) -> Dict:
        """
        Converts the policy to a dictionary so that it can be stored.
        :return: The dictionary representation of the policy.
        """
        out_dict = {}
        if "authorization" in self._policy:
            out_dict["authorization"] = self._policy["authorization"]
        return out_dict

    @staticmethod
    def from_dict(policy_dict_cloud_level: Dict) -> 'AzureAttachedPolicyPolicy':
        """
        Converts a dictionary to a policy.
        :param policy_dict: The dictionary representation of the policy.
        :return: The policy representation of the dict.
        """
        cloud_specific_policy = {}
        can_cloud_run = False
        for cloud_auth in policy_dict_cloud_level:
            if AzurePolicy.Azure_CLOUD_NAME \
                            in cloud_auth:
                can_cloud_run = True
                service_accounts = cloud_auth[AzurePolicy.Azure_CLOUD_NAME]["authorization"]
                cloud_specific_policy["authorization"] = service_accounts
                break
        cloud_specific_policy['can_cloud_run'] = can_cloud_run
        return AzureAttachedPolicyPolicy(cloud_specific_policy)

class AzurePolicy(CloudPolicy):
    """
    Defines methods for Azure policies.
    """

    Azure_CLOUD_NAME = "azure"
    VM_REQUEST_KEYS = set([
        # TODO(kdharmarajan): Possibly restrict which keys are allowed here
        "location"
    ])
    ATTACHED_POLICY_KEYS = set([
        "identity"
    ])

    def __init__(self, vm_policy: AzureVMPolicy, attached_policy_policy: AzureAttachedPolicyPolicy):
        """
        :param vm_policy: The Azure VM Policy to enforce.
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
            if key in AzurePolicy.VM_REQUEST_KEYS:
                resource_types.add("virtual_machine")
            if key in AzurePolicy.ATTACHED_POLICY_KEYS:
                resource_types.add("attached_policies")
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
    def from_dict(policy_dict: Dict) -> 'AzurePolicy':
        """
        Converts a dictionary to a policy.
        :param policy_dict: The dictionary representation of the policy.
        :return: The policy representation of the dict.
        """
        vm_dict = {}
        if "virtual_machine" in policy_dict:
            vm_dict = policy_dict["virtual_machine"]
        vm_policy = AzureVMPolicy.from_dict(vm_dict)
        attached_policy_dict = {}
        if "attached_policies" in policy_dict:
            attached_policy_dict = policy_dict["attached_policies"]
        attached_policy_policy = AzureAttachedPolicyPolicy.from_dict(attached_policy_dict)
        return AzurePolicy(vm_policy, attached_policy_policy)