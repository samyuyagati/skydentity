from typing import Dict, List

from skydentity.policies.checker.policy import (
    CloudPolicy, 
    ResourcePolicy, 
    VMPolicy, 
    PolicyContentException,
    PolicyAction
)

class GCPVMPolicy(VMPolicy):
    """
    Defines methods for GCP VM policies.
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

    def to_dict(self) -> Dict:
        """
        Converts the policy to a dictionary so that it can be stored.
        :return: The dictionary representation of the policy.
        """
        out_dict = {
            "regions": {
                "gcp": self._policy["regions"]
            },
            "allowed_images": {
                "gcp": self._policy["allowed_images"]
            }
        }
    
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
            action = PolicyAction[policy_dict_cloud_level["action"]]
            cloud_specific_policy["action"] = action
        except KeyError:
            raise PolicyContentException("Policy action is not valid")

        gcp_cloud_regions = []
        if GCPPolicy.GCP_CLOUD_NAME in policy_dict_cloud_level["regions"]:
            gcp_cloud_regions = policy_dict_cloud_level["regions"][GCPPolicy.GCP_CLOUD_NAME]

        # TODO(kdharmarajan): Check that the regions are valid later (not essential)
        cloud_specific_policy["regions"] = gcp_cloud_regions

        gcp_allowed_images = []
        if GCPPolicy.GCP_CLOUD_NAME in policy_dict_cloud_level["allowed_images"]:
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
        pass
    
    def check_request(self, request) -> bool:
        """
        Enforces the policy on a request.
        :param request: The request to enforce the policy on.
        :return: True if the request is allowed, False otherwise.
        """
        raise NotImplementedError

    def to_dict(self) -> Dict:
        """
        Converts the policy to a dictionary so that it can be stored.
        :return: The dictionary representation of the policy.
        """
        raise NotImplementedError
    
    @staticmethod
    def from_dict(policy_dict_cloud_level: Dict):
        """
        Converts a dictionary to a policy.
        :param policy_dict: The dictionary representation of the policy.
        :return: The policy representation of the dict.
        """
        cloud_specific_policy = {}
        cloud_specific_policy['can_cloud_run'] = GCPPolicy.GCP_CLOUD_NAME \
                            in policy_dict_cloud_level["cloud_provider"]

class GCPPolicy(CloudPolicy):
    """
    Defines methods for GCP policies.
    """

    GCP_CLOUD_NAME = "gcp"

    def __init__(self, vm_policy: GCPVMPolicy, attached_policy_policy: GCPAttachedPolicyPolicy):
        """
        :param vm_policy: The GCP VM Policy to enforce.
        :param attached_policy_policy: The Attached Policy Policy to enforce.
        """
        self._resource_policies = {
            "virtual_machine": vm_policy,
            "attached_policies": attached_policy_policy
        }

    def get_request_resource_types(self, request) -> List[str]:
        """
        Gets the resource types that the request is trying to access / create / delete.
        :param request: The request to get the resource types from.
        :return: The resource types that the request is trying to access as a list of names.
        """
        raise NotImplementedError
    
    def check_resource_type(self, resource_type: str, request) -> bool:
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
        vm_policy = GCPVMPolicy.from_dict(policy_dict["virtual_machine"])
        attached_policy_policy = GCPAttachedPolicyPolicy.from_dict(policy_dict["attached_policies"])
        return GCPPolicy(vm_policy, attached_policy_policy)