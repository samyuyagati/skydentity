import os
import yaml

from enum import Enum
from dataclasses import dataclass
from typing import Dict, List, Optional
from typing_extensions import Self
from flask import Request

from skydentity.policies.checker.authorization_policy import AuthorizationPolicy

@dataclass
class RestrictedRole:
    role: str
    scope: str
    object: str

    def is_member(self, roles) -> bool:
        """
        Checks if this restricted role is a member of the given list of restricted roles.
        @param roles: The list of RestrictedRole objects to check.
        """
        for restricted_role in roles:
            if (restricted_role.role == self.role and \
                    restricted_role.scope == self.scope and \
                    restricted_role.object == self.object):
                return True
        return False

class Action(Enum):
    CREATE = 1

class CloudProvider(Enum):
    GCP = 1

@dataclass
class Authorization:
    cloud_provider: str
    project: str
    actions: List[Action]
    roles: List[RestrictedRole]

class GCPAuthorizationPolicy(AuthorizationPolicy):
    """
    Defines methods for checking authorization on GCP.
    """
    def __init__(self, policy_dict=None, policy_file=None):
        if policy_dict:
            policy_dict = policy_dict['authorization']
            self._policy = self.authorization_from_dict(policy_dict)
        elif policy_file:
            self._policy = self.authorization_from_yaml(policy_file)
        else:
            raise ValueError("Must provide either a policy dictionary or a policy file.")

    def authorization_from_dict(self, policy_dict: Dict) -> Authorization:
        """
        Parses a dictionary into an Authorization

        Assumes that the dictionary contains keys: cloud_provider, project, actions, roles.
        """
        try:
            cloud_provider = CloudProvider[policy_dict["cloud_provider"][0]]
        except KeyError:
            raise ValueError(f"Invalid cloud provider {policy_dict['cloud_provider'][0]}; provider must be one of {[c.name for c in CloudProvider]}. Only one cloud provider may be specified per authorization policy.")

        try:
            actions = [Action[action_string] for action_string in policy_dict["actions"]]
        except KeyError:
            raise ValueError(f"Invalid action type in action list {policy_dict['actions']}; action must be one of {[a.name for a in Action]}")

        roles = []
        for r in policy_dict['roles']:
            restricted_role = RestrictedRole(
                [x['role'] for x in r['restricted_role'] if 'role' in x][0], 
                [x['scope'] for x in r['restricted_role'] if 'scope' in x][0], 
                None 
            )

            object_list = [x['object'] for x in r['restricted_role'] if 'object' in x]
            if len(object_list) > 0:
                restricted_role.object = object_list[0]
            roles.append(restricted_role)
        
        return Authorization(cloud_provider, policy_dict["project"][0], actions, roles)
    
    def authorization_from_yaml(self, file: str) -> Authorization:
        """
        Parses a YAML file into an Authorization
        """
        with open(file, 'r') as f:
            policy_dict = yaml.load(f, Loader=yaml.SafeLoader)['authorization']

            return self.authorization_from_dict(policy_dict)

    def check_request(self, request: Request, logger=None) -> (Self, bool):
        match request.method:
            # Disallow all reads; currently, this case should never trigger because there is no
            # handler for authorization GET requests.
            case "GET":
                return (None, False)

            case "POST":
                # Parse the request into an Authorization
                authorization_request = GCPAuthorizationPolicy(policy_dict=request.json)

                # Check the cloud provider matches (TODO: Should always be GCP in GCP auth policy)
                if authorization_request._policy.cloud_provider != self._policy.cloud_provider:
                    return (None, False)
                
                # Check that the project matches
                if authorization_request._policy.project != self._policy.project:
                    return (None, False)

                # Check that the actions are allowed
                for action in authorization_request._policy.actions:
                    if action not in self._policy.actions:
                        return (None, False)
                    
                # Check that the roles are allowed
                for restricted_role in authorization_request._policy.roles:
                    if not restricted_role.is_member(self._policy.roles):
                        return (None, False)
                
                # All checks passed
                return (authorization_request, True)

            case _:
                if logger:
                    logger.log_text(f"Request is unrecognized (gcp_authorization_policy.py): {request.url}", severity="WARNING")
                else:
                    print(f"Request is unrecognized (gcp_authorization_policy.py): {request.url}, {request.method}")
                return (None, False)

def main():
    print("HELLO")
    policy_file_name = '../config/auth_example.yaml'
    with open(os.path.join(os.getcwd(), policy_file_name), 'r') as f:
        policy_dict = yaml.load(f, Loader=yaml.SafeLoader)
#        print(policy_dict["cloud_provider"])
        print(policy_dict)

if __name__ == "__main__":
    main()