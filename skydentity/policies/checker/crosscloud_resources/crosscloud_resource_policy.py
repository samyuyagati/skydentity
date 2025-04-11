from collections.abc import Sequence
from dataclasses import dataclass
from typing import Optional

import yaml
from flask import Request

from skydentity.policies.checker.crosscloud_resources.clouds.azure import (
    AzurePermission,
    AzureRoleChecker,
)
from skydentity.policies.checker.crosscloud_resources.clouds.base import (
    CrossCloudPolicyPermission,
    CrossCloudRoleChecker,
)
from skydentity.policies.checker.crosscloud_resources.clouds.gcp import (
    GCPPermission,
    GCPRoleChecker,
)


@dataclass
class CrossCloudAuthorization:
    """
    Parsed authorization policy for cross-cloud resource access.
    """

    role: str

    @dataclass
    class CloudSpecificAuthorization:
        """
        Cloud-specific authorization, containing a list of permissions.

        Permissions have cloud-specific formats,
        as subclasses of `CrossCloudPolicyPermission.BasePermission`.
        """

        cloud: str
        permissions: Sequence["CrossCloudPolicyPermission.BasePermission"]

        # identity to access
        access_identity: Optional[str] = None

        def to_dict(self):
            """Convert this object into a Python dictionary."""
            return {
                "cloud": self.cloud,
                "permissions": [
                    permission.to_dict() for permission in self.permissions
                ],
                "access_identity": self.access_identity,
            }

    clouds: Sequence[CloudSpecificAuthorization]

    def to_dict(self):
        """Convert this object into a Python dictionary."""
        return {"role": self.role, "clouds": [auth.to_dict() for auth in self.clouds]}


class CrossCloudPolicy:
    """
    Policy for cross-cloud resource access.

    This policy is not cloud-specific, and has a generic implementation
    that calls cloud-specific parsers for permissions.

    Policy must be of the form
    ```yaml
    policy:
      - role: <role name>
        clouds:
          - cloud: <cloud name>
            permissions:
              - permission: <permission name>
                <key>: <value>  # other keys needed to specify a permission in the given cloud
              - ... <other permissions>
          - ... <other clouds>
      - ... <other roles>
    ```
    """

    CLOUD_SPECIFIC_PERMISSIONS: dict[str, type[CrossCloudPolicyPermission]] = {
        GCPPermission.cloud: GCPPermission,
        AzurePermission.cloud: AzurePermission,
    }

    CLOUD_SPECIFIC_REQUEST_CHECKS: dict[str, type[CrossCloudRoleChecker]] = {
        GCPRoleChecker.cloud: GCPRoleChecker,
        AzureRoleChecker.cloud: AzureRoleChecker,
    }

    def __init__(self, policy_dict=None, policy_file=None):
        if policy_dict:
            self.policy = self.from_dict(policy_dict)
        elif policy_file:
            self.policy = self.from_yaml(policy_file)

    @staticmethod
    def from_dict(policy: dict) -> list[CrossCloudAuthorization]:
        """Parse policy from a dict."""
        assert isinstance(policy, dict), "The policy should be a dictionary."
        assert (
            "policy" in policy
        ), "The policy dictionary should contain a single key called 'policy'"

        roles = policy["policy"]
        assert isinstance(roles, list), "The policy should consist of a list of roles."

        parsed_policy = []
        for role_dict in roles:
            assert isinstance(
                role_dict, dict
            ), "Each element of the policy should be a dictionary"

            assert "role" in role_dict, "Role name must be specified"
            assert "clouds" in role_dict, "Clouds dictionary must be specified"

            role = role_dict["role"]
            clouds = role_dict["clouds"]

            assert isinstance(clouds, list), "Clouds must be specified as a list"

            cloud_authorizations = []
            for cloud_dict in role_dict["clouds"]:
                assert isinstance(
                    cloud_dict, dict
                ), "Each element of the clouds list should be a dictionary"

                assert (
                    "cloud" in cloud_dict
                ), "The cloud dictionary must specify a cloud name."
                assert (
                    "permissions" in cloud_dict
                ), "The cloud dictionary must specify a list of permissions."
                cloud = cloud_dict["cloud"]
                permissions = cloud_dict["permissions"]

                # if access identity is not provided, default ot None
                access_identity = cloud_dict.get("access_identity", None)

                parsed_permissions: Sequence[
                    CrossCloudPolicyPermission.BasePermission
                ] = []

                # get the appropriate permission class
                cloud_permission_class = CrossCloudPolicy.CLOUD_SPECIFIC_PERMISSIONS[
                    cloud
                ]
                parsed_permissions = cloud_permission_class.from_dict(permissions)

                cloud_authorizations.append(
                    CrossCloudAuthorization.CloudSpecificAuthorization(
                        cloud=cloud,
                        permissions=parsed_permissions,
                        access_identity=access_identity,
                    )
                )

            parsed_policy.append(
                CrossCloudAuthorization(role=role, clouds=cloud_authorizations)
            )

        return parsed_policy

    @staticmethod
    def from_yaml(file: str) -> list[CrossCloudAuthorization]:
        """Parse policy from a yaml file."""
        with open(file, "r", encoding="utf-8") as f:
            policy = yaml.load(f, Loader=yaml.SafeLoader)
            return CrossCloudPolicy.from_dict(policy)

    def to_dict(self):
        """
        Convert policy to a Python dictionary.
        """
        return {"policy": [role_dict.to_dict() for role_dict in self.policy]}

    def get_vm_role_from_request(self, cloud: str, request: Request) -> Optional[str]:
        """
        Check a VM creation request to determine whether it attaches a role to the VM,
        from one of the roles in the policy.
        If it does, return the role. Otherwise, returns None.
        """
        # extract set of roles
        roles: set[str] = set(role_obj.role for role_obj in self.policy)

        role_checker = self.CLOUD_SPECIFIC_REQUEST_CHECKS[cloud]
        vm_role = role_checker.get_role_from_request(request, roles)

        return vm_role

    def find_authorization(self, role: str) -> Optional[CrossCloudAuthorization]:
        """
        Find the authorization corresponding to the given role.
        Returns None if not found.
        """
        for authorization in self.policy:
            if authorization.role == role:
                return authorization

        return None

    def get_access_identity(self, role: str, cloud: str) -> Optional[str]:
        """
        Retrieve the access identity for the given role in a particular cloud.

        Returns None if either the role or the cloud is not found.
        """
        authorization = self.find_authorization(role)
        if authorization is None:
            # role not found
            return None

        for cloud_authorization in authorization.clouds:
            if cloud_authorization.cloud == cloud:
                return cloud_authorization.access_identity

        # cloud not found
        return None


def _test_parse():
    """Test parsing"""
    from pprint import pprint

    policy_dict = {
        "policy": [
            {
                "role": "bucket-reader",
                "clouds": [
                    {
                        "cloud": "gcp",
                        "permissions": [
                            {
                                # role in GCP
                                "permission": "roles/storage.objectViewer",
                                # resource that the role applies to
                                "resource": {
                                    # type from https://cloud.google.com/iam/docs/conditions-resource-attributes#resource-type
                                    "type": "storage.googleapis.com/Bucket",
                                    # name format from https://cloud.google.com/iam/docs/conditions-resource-attributes#resource-name
                                    "name": "projects/_/buckets/storage-bucket-name",
                                },
                            }
                        ],
                        "access_identity": "test@test",
                    },
                    {
                        "cloud": "azure",
                        "permissions": [
                            {
                                # role in Azure
                                "permission": "Storage Blob Data Reader",
                                # a resource is defined only by a scope ID in Azure
                                "resource": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/Example-Storage-rg/providers/Microsoft.Storage/storageAccounts/storage12345/blobServices/default/containers/blob-container-01",
                            }
                        ],
                    },
                ],
            }
        ]
    }

    print("ORIGINAL:")
    pprint(policy_dict)

    parsed_policy = CrossCloudPolicy(policy_dict=policy_dict)
    print("PARSED:")
    pprint(parsed_policy.policy)

    print("SERIALIZED:")
    serialized_policy = parsed_policy.to_dict()
    pprint(serialized_policy)


if __name__ == "__main__":
    _test_parse()
