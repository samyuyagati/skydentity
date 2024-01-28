import os
import yaml

from enum import Enum
from dataclasses import dataclass
from typing import Dict, List
from flask import Request

from skydentity.policies.checker.authorization_policy import AuthorizationPolicy
from skydentity.policies.iam.gcp_service_account_manager import GCPServiceAccountManager


@dataclass
class RestrictedRole:
    role: str
    scope: str
    object: str

class Action(Enum):
    CREATE = 1
    READ = 2
    DELETE = 3
    ALL = 4

class CloudProvider(Enum):
    gcp = 1

@dataclass
class Authorization:
    cloud_provider: str
    actions: List[Action]
    roles: List[RestrictedRole]

class GCPAuthorizationPolicy(AuthorizationPolicy):
    """
    Defines methods for checking authorization on GCP.
    """
    def __init__(self, policy_dict=None, policy_file=None):
        if policy_dict:
            self._policy = self.authorization_from_dict(policy_dict)
        elif policy_file:
            self._policy = self.authorization_from_yaml(policy_file)
        else:
            raise ValueError("Must provide either a policy dictionary or a policy file.")

    def authorization_from_dict(self, policy_dict: Dict) -> Authorization:
        """
        Parses a dictionary into an Authorization

        Assumes that the dictionary contains keys: cloud_provider, actions, roles.
        """
        try:
            cloud_provider = CloudProvider[policy_dict["cloud_provider"]]
        except KeyError:
            raise ValueError(f"Invalid action type {policy_dict['actions']}; action must be \
                                one of {[c.name for c in CloudProvider]}. Only one cloud provider \
                                may be specified per authorization policy.")

        try:
            actions = [Action[action_string] for action_string in policy_dict["actions"]]
        except KeyError:
            raise ValueError(f"Invalid action type in action list {policy_dict['actions']}; action must \
                                be one of {[a.name for a in Action]}")

        roles = []
        for restricted_role in policy_dict['roles']:
            roles.append(RestrictedRole(restricted_role['role'], restricted_role['scope'], 
                                        restricted_role['object']))
        
        return Authorization(cloud_provider, actions, roles)
    
    def authorization_from_yaml(self, file: str) -> Authorization:
        """
        Parses a YAML file into an Authorization
        """
        with open(file, 'r') as f:
            policy_dict = yaml.load(f, Loader=yaml.SafeLoader)['authorization']

            return self.authorization_from_dict(policy_dict)

    def check_request(self, request: Request, logger=None) -> bool:
        match request.method:
            case "GET":
                pass
            case "POST":
                pass
            case _:
                if logger:
                    logger.log_text(f"Request is unrecognized (gcp_authorization_policy.py): {request.url}", severity="WARNING")
                else:
                    print(f"Request is unrecognized (gcp_authorization_policy.py): {request.url}")
    
    def create_authorization(self, authorization: Authorization):
        pass

def main():
    print("HELLO")
    policy_file_name = '../config/auth_example.yaml'
    with open(os.path.join(os.getcwd(), policy_file_name), 'r') as f:
        policy_dict = yaml.load(f, Loader=yaml.SafeLoader)
#        print(policy_dict["cloud_provider"])
        print(policy_dict)

if __name__ == "__main__":
    main()