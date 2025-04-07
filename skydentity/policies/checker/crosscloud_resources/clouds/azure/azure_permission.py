from collections.abc import Sequence
from dataclasses import dataclass
from typing import ClassVar

from skydentity.policies.checker.crosscloud_resources.clouds.base import (
    CrossCloudPolicyPermission,
)


class AzurePermission(CrossCloudPolicyPermission):
    """
    Cross-cloud policy permission specification for Azure.
    """

    cloud: ClassVar[str] = "azure"

    @dataclass
    class Permission(CrossCloudPolicyPermission.BasePermission):
        """A single permission in GCP"""

        resource: str

        def to_dict(self):
            """Convert this object into a Python dictionary."""
            return {
                "permission": self.permission,
                "resource": self.resource,
            }

    @staticmethod
    def from_dict(permissions_list: list[dict]) -> Sequence[Permission]:
        assert isinstance(permissions_list, list), "Permissions must be a list."

        parsed_permissions: list[AzurePermission.Permission] = []

        for permission_dict in permissions_list:
            assert isinstance(
                permission_dict, dict
            ), "Each permission must be a dictionary."

            assert (
                "permission" in permission_dict
            ), "Permission name (Azure role) must be specified."
            assert (
                "resource" in permission_dict
            ), "Resource (Azure scope) must be specified."

            permission_name = permission_dict["permission"]
            resource = permission_dict["resource"]

            parsed_permissions.append(
                AzurePermission.Permission(
                    permission=permission_name, resource=resource
                )
            )

        return parsed_permissions
