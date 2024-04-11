from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Tuple, Union

import yaml
from flask import Request

from skydentity.policies.checker.authorization_policy import AuthorizationPolicy


class StoragePolicyAction(Enum):
    """
    Actions specified in the storage policy.
    """

    # read-only
    READ = "READ"
    # write-only
    UPLOAD = "UPLOAD"
    # read-write
    OVERWRITE = "OVERWRITE"

    # none; deny
    NONE = "NONE"


class StorageRequestAction(Enum):
    """
    Actions requested by the server proxy.

    Gets translated into policy actions during request checking.
    """

    # read only
    READ = "READ"
    # overwrite, but fallback to upload if overwrite is not allowed
    OVERWRITE_FALLBACK_UPLOAD = "OVERWRITE_FALLBACK_UPLOAD"


class CloudProvider(Enum):
    azure = "azure"


@dataclass
class Authorization:
    """Parsed storage auth policy"""
    cloud_provider: CloudProvider
    storage_account: str
    actions: List[StoragePolicyAction]
    containers: List[str]


@dataclass
class AuthorizationRequest:
    """Parsed storage auth request"""

    cloud_provider: CloudProvider
    container: str
    # translated actions from storage request actions
    actions: List[StoragePolicyAction]


class AzureStoragePolicy(AuthorizationPolicy):
    def __init__(self, policy_dict=None, policy_file=None):
        if policy_dict:
            policy_dict = policy_dict["storage"]
            self._policy = self.authorization_from_dict(policy_dict)
        elif policy_file:
            self._policy = self.authorization_from_yaml(policy_file)
        else:
            raise ValueError(
                "Must provide either a policy dictionary or a policy file."
            )

    def authorization_from_dict(self, policy_dict: dict) -> Authorization:
        """
        Parses a dictionary into an Authorization.

        The dictionary should contain keys:
        - cloud_provider
        - storage_account
        - actions
        - containerss
        """

        try:
            cloud_provider = CloudProvider[policy_dict["cloud_provider"][0]]
        except KeyError:
            raise ValueError(
                f"Invalid cloud provider {policy_dict['cloud_provider'][0]}; provider must be one of {[c.name for c in CloudProvider]}. Only one cloud provider may be specified per authorization policy."
            )

        try:
            actions = [
                StoragePolicyAction[action_string]
                for action_string in policy_dict["actions"]
            ]
        except KeyError:
            raise ValueError(
                f"Invalid action type in action list {policy_dict['actions']}; action must be one of {[a.name for a in StoragePolicyAction]}"
            )

        containers = policy_dict["containers"]

        return Authorization(
            cloud_provider=cloud_provider,
            storage_account=policy_dict["storage_account"][0],
            actions=actions,
            containers=containers,
        )

    def authorization_from_yaml(self, file: str) -> Authorization:
        """
        Parses a YAML file into an Authorization.
        """
        with open(file, "r") as f:
            policy_dict = yaml.load(f, Loader=yaml.SafeLoader)["storage_policy"]

            return self.authorization_from_dict(policy_dict)

    def authorization_request_from_dict(self, policy_dict: dict) -> AuthorizationRequest:
        """
        Parses a dictionary into an AuthorizationRequest.

        `policy_dict` should be the raw POST request body for a storage auth request.

        When parsing the request actions, checks the current policy dict to do any translations.
        In particular:
        - if OVERWRITE_FALLBACK_UPLOAD:
            - if policy allows overwrite, translate to OVERWRITE
            - if policy allows only upload, translate to UPLOAD
            - otherwise, translate to NONE
        """

        # request data should have a container name, storage_account name, actions
        try:
            cloud_provider = CloudProvider[policy_dict["cloud_provider"]]
        except KeyError:
            cloud_provider = None
        container = policy_dict["container"]
        request_actions = policy_dict["actions"]

        combined_actions = set()
        for request_action in request_actions:
            try:
                request_action_enum = StorageRequestAction[request_action]
            except KeyError:
                # unrecognized request action
                print(f"Unrecognized requested action: {request_action}")
                combined_actions.add(StoragePolicyAction.NONE)
                continue

            if request_action_enum == StorageRequestAction.READ:
                if StoragePolicyAction.READ not in self._policy.actions:
                    print("[request check failed] action")
                    combined_actions.add(StoragePolicyAction.NONE)
                else:
                    combined_actions.add(StoragePolicyAction.READ)
            elif (
                request_action_enum
                == StorageRequestAction.OVERWRITE_FALLBACK_UPLOAD
            ):
                if StoragePolicyAction.OVERWRITE in self._policy.actions:
                    combined_actions.add(StoragePolicyAction.OVERWRITE)
                elif StoragePolicyAction.UPLOAD in self._policy.actions:
                    combined_actions.add(StoragePolicyAction.UPLOAD)
                else:
                    # neither upload or overwrite allowed
                    combined_actions.add(StoragePolicyAction.NONE)
            else:
                # unhandled request action
                print(f"[request check failed] unknown action, {request_action}")

        if StoragePolicyAction.NONE in combined_actions:
            # if any failures occurred, replace all actions with only NONE
            combined_actions = [StoragePolicyAction.NONE]
        else:
            combined_actions = list(combined_actions)

        auth_request = AuthorizationRequest(
            cloud_provider=cloud_provider,
            container=container,
            actions=combined_actions,
        )

        return auth_request

    def check_request(
        self, request: Request, logger=None
    ) -> Tuple[Optional[AuthorizationRequest], bool]:
        if request.method == "GET":
            # Disallow all reads; currently, this case should never trigger because there is no
            # handler for authorization GET requests.
            return (None, False)
        elif request.method == "POST":
            # handle the request
            request_data = request.get_json(cache=True)

            auth_request = self.authorization_request_from_dict(request_data)

            # check requested cloud provider
            if auth_request.cloud_provider != self._policy.cloud_provider:
                print(f"[request check failed] cloud provider; expected {self._policy.cloud_provider}, got {auth_request.cloud_provider}")
                return (None, False)

            # check requested container
            if auth_request.container not in self._policy.containers:
                print(f"[request check failed] container; expected {self._policy.containers}, got {auth_request.container}")
                return (None, False)

            # check requested actions
            if StoragePolicyAction.NONE in auth_request.actions:
                print(f"[request check failed] action; expected subset of {self._policy.actions}, got {auth_request.actions}")
                return (None, False)
            else:
                for requested_action in auth_request.actions:
                    if requested_action not in self._policy.actions:
                        print(f"[request check failed] action; expected subset of {self._policy.actions}, got {auth_request.actions}")
                        return (None, False)

            # passed all checks
            return (auth_request, True)
        else:
            if logger:
                logger.log_text(
                    f"Request is unrecognized (azure_storage_policy.py): {request.url}",
                    severity="WARNING",
                )
            else:
                print(
                    f"Request is unrecognized (azure_storage_policy.py): {request.url}, {request.method}"
                )
            return (None, False)