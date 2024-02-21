from abc import ABC
from typing import Dict, List, Tuple
from flask import Request

class ResourcePolicy(ABC):
    """
    General resource policy for VMs, Attached Policies
    """

    def check_request(self, request: Request) -> bool:
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
    def from_dict(policy_dict: Dict):
        """
        Converts a dictionary to a policy.
        :param policy_dict: The dictionary representation of the policy.
        :return: The policy representation of the dict.
        """
        raise NotImplementedError

class VMPolicy(ResourcePolicy, ABC):
    """
    General resource policy for VMs
    """

    def check_request(self, request: Request) -> bool:
        """
        Enforces the policy on a request.
        :param request: The request to enforce the policy on.
        :return: True if the request is allowed, False otherwise.
        """
        standardized_request = self.get_standard_request_form(request)
        standardized_vm_policy = self.get_policy_standard_form()

        # First check the action
        if not standardized_request["actions"].is_allowed_be_performed(standardized_vm_policy["actions"]):
            print("Action not allowed")
            return False
        
        # Then check the regions
        for region in standardized_request["regions"]:
            if region not in standardized_vm_policy["regions"]:
                print("Region not allowed")
                return False

        # Then check the instance type
        for instance_type in standardized_request["instance_type"]:
            if instance_type not in standardized_vm_policy["instance_type"]:
                print("Instance type not allowed")
                return False

        # Then check the allowed images
        for image in standardized_request["allowed_images"]:
            if image not in standardized_vm_policy["allowed_images"]:
                print(f"Image {image} not allowed")
                return False
            
        # TODO(kdharmarajan): Add allowed_setup script inclusion here
        return True

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
        raise NotImplementedError
    
    def get_policy_standard_form(self) -> Dict:
        """
        Gets the policy in a standard form.
        :return: The policy in a standard form.
        """
        raise NotImplementedError

    def to_dict(self) -> Dict:
        """
        Converts the policy to a dictionary so that it can be stored.
        :return: The dictionary representation of the policy.
        """
        raise NotImplementedError
    
    @staticmethod
    def from_dict(policy_dict: Dict):
        """
        Converts a dictionary to a policy.
        :param policy_dict: The dictionary representation of the policy.
        :return: The policy representation of the dict.
        """
        raise NotImplementedError

class UnrecognizedResourcePolicy(ResourcePolicy):
    def check_request(self, request: Request) -> bool:
        """
        Enforces the policy on a request.

        If code is executed for an unrecognized resource, then it
        should always be denied.

        :param request: The request to enforce the policy on.
        :return: False.
        """
        print(f"Request is unrecognized: {request.url}")
        return False

    def to_dict(self) -> Dict:
        """
        Converts the policy to a dictionary so that it can be stored.
        :return: The dictionary representation of the policy.
        """
        raise NotImplementedError
    
    @staticmethod
    def from_dict(policy_dict: Dict):
        """
        Converts a dictionary to a policy.
        :param policy_dict: The dictionary representation of the policy.
        :return: The policy representation of the dict.
        """
        raise NotImplementedError

class CloudPolicy(ResourcePolicy, ABC):
    """
    A policy is a set of rules that tell what actions can be done on what resources.
    """

    def get_request_resource_types(self, request: Request) -> List[Tuple[str]]:
        """
        Gets the resource types that the request is trying to access / create / delete.
        :param request: The request to get the resource types from.
        :return: The resource types that the request is trying to access as a list of names.
        """
        raise NotImplementedError

    def check_request(self, request: Request) -> bool:
        """
        Enforces the policy on a request.
        :param request: The request to enforce the policy on.
        :return: True if the request is allowed, False otherwise.
        """
        request_resource_types = self.get_request_resource_types(request)
        for resource_type in request_resource_types:
            if not self.check_resource_type(resource_type, request):
                return False
        return True
    
    def check_resource_type(self, resource_type: Tuple[str], request: Request) -> (bool):
        """
        Enforces the policy on a resource type.
        :param resource_type: The resource type to enforce the policy on.
        :param request: The request to enforce the policy on.
        :return: True if the request is allowed, False otherwise.
        """
        raise NotImplementedError
    
class PolicyContentException(Exception):
    """
    Exception for when a policy is not valid (may not be formatted properly or contain correct information).
    """
    
    def __init__(self, message):
        """
        Initializes the exception.
        :param message: The message to display.
        """
        super().__init__(message)
        self.message = message
