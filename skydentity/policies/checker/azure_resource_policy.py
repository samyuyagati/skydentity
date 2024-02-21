from typing import Dict, List, Tuple, TypedDict, Union, Optional
from flask import Request
import sys

from skydentity.policies.checker.resource_policy import (
    CloudPolicy, 
    ResourcePolicy, 
    VMPolicy, 
    UnrecognizedResourcePolicy,
    PolicyContentException
)
from skydentity.policies.checker.policy_actions import PolicyAction
from skydentity.policies.managers.azure_authorization_policy_manager import AzureAuthorizationPolicyManager

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
            "actions": [self._policy["actions"].value],
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
            print("REGION GROUP", region_group)
            if AzurePolicy.Azure_CLOUD_NAME in region_group:
                if isinstance(policy_dict_cloud_level["regions"], list):
                  Azure_cloud_regions = region_group[AzurePolicy.Azure_CLOUD_NAME] 
                else: 
                  Azure_cloud_regions = policy_dict_cloud_level["regions"][region_group] 
                break

        # TODO(kdharmarajan): Check that the regions are valid later (not essential)
        cloud_specific_policy["regions"] = Azure_cloud_regions

        Azure_instance_types = []
        for instance_type_group in policy_dict_cloud_level["instance_type"]:
            if AzurePolicy.Azure_CLOUD_NAME in instance_type_group:
                if isinstance(policy_dict_cloud_level["instance_type"], list):
                  Azure_instance_types = instance_type_group[AzurePolicy.Azure_CLOUD_NAME]
                else:
                  Azure_instance_types = policy_dict_cloud_level["instance_type"][AzurePolicy.Azure_CLOUD_NAME]
        cloud_specific_policy["instance_type"] = Azure_instance_types

        Azure_allowed_images = []
        for allowed_images_group in policy_dict_cloud_level["allowed_images"]:
            if isinstance(policy_dict_cloud_level["allowed_images"], list):
                Azure_allowed_images = allowed_images_group[AzurePolicy.Azure_CLOUD_NAME]
            else:
                Azure_allowed_images = policy_dict_cloud_level["allowed_images"][AzurePolicy.Azure_CLOUD_NAME]

        cloud_specific_policy["allowed_images"] = Azure_allowed_images

        # TODO(kdharmarajan): Add allowed_setup script inclusion here
        return AzureVMPolicy(cloud_specific_policy)
    
class AzureAttachedAuthorizationPolicy(ResourcePolicy):
    """
    Defines methods for Azure Attached Policies (what Azure policies can be attached to a VM)
    """

    def __init__(self, policy: Dict):
        """
        :param policy: The dict of the policy to enforce.
        """
        self._policy = policy
    
    def check_request(self, request: Request, auth_policy_manager: AzureAuthorizationPolicyManager, logger=None) -> Tuple[Union[str, None], bool]:
        """
        Enforces the policy on a request.
        :param request: The request to enforce the policy on.
        :return: True if the request is allowed, False otherwise.
        """
        print("check_request", flush=True)
        sys.stdout.flush()
        
        request_contents = request.get_json(cache=True)
        print(">>>request:", request_contents)

        # Handle attached managed identity capability
        if "managedIdentities" not in request_contents:
            return (None, True)
        
        # Expect a single attached managed identity
        if len(request_contents["managedIdentities"]) != 1:
            if logger:
                logger.log_text("Only one managed identity may be attached", severity="WARNING")
            else:
                print("Only one managed identity may be attached")
            return (None, False)

        # Expect a capability of the form:
        #   { 'nonce': XX, 'header': XX, 'ciphertext': XX, 'tag': XX }
        managed_identity_capability = request_contents["managedIdentities"][0]
        print(">>>managed_identity_capability:", managed_identity_capability)
        if (managed_identity_capability["nonce"] is None or \
            managed_identity_capability["header"] is None or \
            managed_identity_capability["ciphertext"] is None or \
            managed_identity_capability["tag"] is None):
            if logger:
                logger.log_text("Invalid capability format", severity="WARNING")
            else:
                print("Invalid capability format")
            return (None, False)
        
        managed_identity_id, success = auth_policy_manager.check_capability(managed_identity_capability)
        if not success:
            print("Unsuccessful in checking capability")
            return (None, False)

        # Double-check that the managed identity is allowed (e.g., if policy changed since
        # the capability was issued)
        print(self._policy[AzurePolicy.Azure_CLOUD_NAME][0]["authorization"])
        if managed_identity_id not in self._policy[AzurePolicy.Azure_CLOUD_NAME][0]["authorization"]:
            print("managed identity id", managed_identity_id, "not in", self._policy[AzurePolicy.Azure_CLOUD_NAME])
            return (None, False)
        
        # If permitted, add the managed identity to the request
        return (managed_identity_id, True)

    def to_dict(self) -> Dict:
        """
        Converts the policy to a dictionary so that it can be stored.
        :return: The dictionary representation of the policy.
        """
        out_dict = {}
        if AzurePolicy.Azure_CLOUD_NAME in self._policy:
            out_dict[AzurePolicy.Azure_CLOUD_NAME] = self._policy[AzurePolicy.Azure_CLOUD_NAME]
        return out_dict

    @staticmethod
    def from_dict(policy_dict_cloud_level: Dict, logger=None) -> 'AzureAttachedAuthorizationPolicy':
        """
        Converts a dictionary to a policy.
        :param policy_dict: The dictionary representation of the policy.
        :param logger: optional. azure.cloud logger object.
        :return: The policy representation of the dict.
        """
        if logger:
            logger.log_text("AzureAttachedAuthorization", severity="WARNING")
        else:
            print("AzureAttachedAuthorization")
        cloud_specific_policy = {}
        can_cloud_run = False
        print("Policy dict:", policy_dict_cloud_level)
        if isinstance(policy_dict_cloud_level, list):
            for cloud_auth in policy_dict_cloud_level:
                if AzurePolicy.Azure_CLOUD_NAME \
                              in cloud_auth:
                    can_cloud_run = True
                    service_accounts = cloud_auth[AzurePolicy.Azure_CLOUD_NAME]
                    cloud_specific_policy[AzurePolicy.Azure_CLOUD_NAME] = service_accounts
                    break
        else:
            for cloud_name in policy_dict_cloud_level:
                if not (cloud_name == AzurePolicy.Azure_CLOUD_NAME):
                    continue
                can_cloud_run = True
                service_accounts = policy_dict_cloud_level[cloud_name]
                cloud_specific_policy[AzurePolicy.Azure_CLOUD_NAME] = service_accounts
                break
        cloud_specific_policy['can_cloud_run'] = can_cloud_run
        print("Cloud-specific attached authorization policy:", cloud_specific_policy)
        return AzureAttachedAuthorizationPolicy(cloud_specific_policy)

class AzurePolicy(CloudPolicy):
    """
    Defines methods for Azure policies.
    """

    Azure_CLOUD_NAME = "azure"
    VM_REQUEST_KEYS = set([
        # TODO(kdharmarajan): Possibly restrict which keys are allowed here
        "location",
        "properties"
    ])
    ATTACHED_AUTHORIZATION_KEYS = set([
        "managedIdentities"
    ])

    def __init__(self, vm_policy: AzureVMPolicy, attached_authorization_policy: AzureAttachedAuthorizationPolicy):
        """
        :param vm_policy: The Azure VM Policy to enforce.
        :param attached_authorization_policy: The Attached Policy Policy to enforce.
        """
        self._resource_policies = {
            "virtual_machine": vm_policy,
            "attached_authorizations": attached_authorization_policy,
            "unrecognized": UnrecognizedResourcePolicy()
        }
        self.valid_authorization: Union[str, None] = None
        print("AzureAuthorizationPolicy init:", self._resource_policies["attached_authorizations"]._policy)

    def get_request_resource_types(self, request: Request) -> List[str]:
        """
        Gets the resource types that the request is trying to access / create / delete.
        :param request: The request to get the resource types from.
        :return: The resource types that the request is trying to access as a list of names.
        """
        resource_types = set([])
        # TODO(kdharmarajan): Be on the lookout for certain GET requests that need to be allowed
        # TODO: Make sure we don't get to get_json for GET requests and instead use separate ReadPolicy
        # TODO(later): Refactoring the logic to reuse better
        if request.method == 'GET':
            return list(resource_types)
        for key in request.get_json(cache=True).keys():
            if key in AzurePolicy.VM_REQUEST_KEYS:
                resource_types.add(("virtual_machine",))
            elif key in AzurePolicy.ATTACHED_AUTHORIZATION_KEYS:
                resource_types.add(("attached_authorizations",))
        if len(resource_types) == 0:
            resource_types.add(("unrecognized",))
            print(">>>>> UNRECOGNIZED RESOURCE TYPE <<<<<")
        print("All resource types:", list(resource_types))
        return list(resource_types)
    
    def check_resource_type(self, resource_type: Tuple[str], request: Request) -> bool:
        """
        Enforces the policy on a resource type.
        :param resource_type: The resource type to enforce the policy on.
        :param request: The request to enforce the policy on.
        :return: True if the request is allowed, False otherwise.
        """
        resource_type_key, *resource_type_aux = resource_type
        assert resource_type_key in self._resource_policies
        if resource_type_key == "attached_authorizations":
            # Authorization policies
            result = self._resource_policies[resource_type_key].check_request(request, self._authorization_manager)
            self.valid_authorization = result[0]
            return result[1]
        return self._resource_policies[resource_type_key].check_request(request)

    def set_authorization_manager(self, manager: AzureAuthorizationPolicyManager):
        self._authorization_manager = manager

    def to_dict(self) -> Dict:
        """
        Converts the policy to a dictionary so that it can be stored.
        :return: The dictionary representation of the policy.
        """
        out_dict = {}
        for resource_type, policy in self._resource_policies.items():
            if resource_type == "unrecognized":
                continue
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
        if "attached_authorizations" in policy_dict:
            attached_policy_dict = policy_dict["attached_authorizations"]
        # TODO: Check for reading the attached authorization, also look for GCP code
        attached_authorization_policy = AzureAttachedAuthorizationPolicy.from_dict(attached_policy_dict)
        return AzurePolicy(vm_policy, attached_authorization_policy)