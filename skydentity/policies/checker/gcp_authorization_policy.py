import os
import yaml

from enum import Enum
from dataclasses import dataclass
from typing import Dict, List, Optional
from flask import Request

import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore
from skydentity.policies.checker.resource_policy import CloudPolicy

from skydentity.policies.managers.policy_manager import PolicyManager
from skydentity.policies.checker.authorization_policy import AuthorizationPolicy
from skydentity.policies.iam.gcp_service_account_manager import GCPServiceAccountManager

@dataclass
class RestrictedRole:
    role: str
    scope: str
    object: str

    def is_member(self, roles: List[RestrictedRole]) -> bool:
        for restricted_role in roles:
            if (restricted_role.role == self.role and \
                    restricted_role.scope == self.scope and \
                    restricted_role.object == self.object):
                return True
        return False

class Action(Enum):
    CREATE = 1

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
            roles.append(RestrictedRole(restricted_role['role'], 
                                        restricted_role['scope'], 
                                        restricted_role['object']))
        
        return Authorization(cloud_provider, actions, roles)
    
    def authorization_from_yaml(self, file: str) -> Authorization:
        """
        Parses a YAML file into an Authorization
        """
        with open(file, 'r') as f:
            policy_dict = yaml.load(f, Loader=yaml.SafeLoader)['authorization']

            return self.authorization_from_dict(policy_dict)

    def check_request(self, request: Request, logger=None) -> (GCPAuthorizationPolicy, bool):
        match request.method:
            # Disallow all reads; currently, this case should never trigger because there is no
            # handler for authorization GET requests.
            case "GET":
                return (None, False)

            case "POST":
                # Parse the request into an Authorization
                authorization_request = self.authorization_from_dict(request.json)

                # Check the cloud provider matches (TODO: Should always be GCP in GCP auth policy)
                if authorization_request.cloud_provider != self._policy.cloud_provider:
                    return (None, False)
                
                # Check that the project matches
                if authorization_request.project != self._policy.project:
                    return (None, False)

                # Check that the actions are allowed
                for action in authorization_request.actions:
                    if action not in self._policy.actions:
                        return (None, False)
                    
                # Check that the roles are allowed
                for restricted_role in authorization_request.roles:
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

    def create_service_account_with_roles(self):
        pass

class GCPAuthorizationPolicyManager(PolicyManager):
    def __init__(self, 
                 credentials_path: str,
                 firestore_policy_collection: str = 'authorization_policies'):
        """
        Initializes the GCP policy manager.
        :param credentials_path: The path to the credentials file.
        """
        self._cred = credentials.Certificate(credentials_path)
        self._app = firebase_admin.initialize_app(self._cred)
        self._db = firestore.client()
        self._firestore_policy_collection = firestore_policy_collection

    def get_policy_dict(self, public_key: str) -> CloudPolicy | None:
        """
        Gets a policy from the cloud vendor.
        :param public_key: The public key of the policy.
        :return: The policy.
        """
        return self._db \
            .collection(self._firestore_policy_collection) \
            .document(public_key) \
            .get() \
            .to_dict()


def main():
    print("HELLO")
    policy_file_name = '../config/auth_example.yaml'
    with open(os.path.join(os.getcwd(), policy_file_name), 'r') as f:
        policy_dict = yaml.load(f, Loader=yaml.SafeLoader)
#        print(policy_dict["cloud_provider"])
        print(policy_dict)

if __name__ == "__main__":
    main()