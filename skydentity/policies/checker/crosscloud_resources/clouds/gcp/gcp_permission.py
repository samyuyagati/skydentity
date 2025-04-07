from collections.abc import Sequence
from dataclasses import dataclass
from typing import ClassVar, cast

from skydentity.policies.checker.crosscloud_resources.clouds.base import (
    CrossCloudPolicyPermission,
)


class GCPPermission(CrossCloudPolicyPermission):
    """
    Cross-cloud policy permission specification for GCP.
    """

    cloud: ClassVar[str] = "gcp"

    @dataclass
    class Resource:
        """Specification for a resource in GCP."""

        # `resource.type` in IAM conditions:
        # https://cloud.google.com/iam/docs/conditions-resource-attributes#resource-type
        type: str

        # `resource.name` in IAM conditions:
        # https://cloud.google.com/iam/docs/conditions-resource-attributes#resource-name
        name: str

        def to_dict(self):
            """Convert this object into a Python dictionary"""
            return {
                "type": self.type,
                "name": self.name,
            }

    @dataclass
    class Permission(CrossCloudPolicyPermission.BasePermission):
        """A single permission in GCP"""

        resource: "GCPPermission.Resource"

        def to_dict(self):
            """Convert this object into a Python dictionary"""
            return {
                "permission": self.permission,
                "resource": self.resource.to_dict(),
            }

    @staticmethod
    def from_dict(permissions_list: list[dict]) -> Sequence[Permission]:
        assert isinstance(permissions_list, list), "Permissions must be a list."

        parsed_permissions: list[GCPPermission.Permission] = []
        for permission_dict in permissions_list:
            assert isinstance(
                permission_dict, dict
            ), "Each permission must be a dictionary."

            assert (
                "permission" in permission_dict
            ), "Permission name (GCP role) must be specified."
            assert "resource" in permission_dict, "Resource must be specified."

            permission_name = permission_dict["permission"]
            resource_dict = permission_dict["resource"]

            assert isinstance(
                resource_dict, dict
            ), "Resource must be specified as a dict"
            assert "type" in resource_dict, "Resource type must be specified"
            assert "name" in resource_dict, "Resource name must be specified"

            resource_type: str = resource_dict["type"]
            resource_name: str = resource_dict["name"]

            parsed_permissions.append(
                GCPPermission.Permission(
                    permission=permission_name,
                    resource=GCPPermission.Resource(
                        type=resource_type, name=resource_name
                    ),
                )
            )

        return parsed_permissions
