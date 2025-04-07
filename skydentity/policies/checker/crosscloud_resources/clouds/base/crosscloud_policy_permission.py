from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass
from typing import ClassVar


class CrossCloudPolicyPermission(ABC):
    """
    Abstract class for storing policy permissions for a specific cloud.
    """

    # key in the policy for this permission list
    cloud: ClassVar[str] = NotImplemented

    @dataclass
    class BasePermission(ABC):
        """
        Base class for a single permission in this cloud.

        All cloud-specific permission objects should inherit from this base class,
        for typing and inheritance.
        """

        # there should always be some form of permission given using the cloud IAM;
        # GCP has roles, AWS has policies, Azure has policies.
        permission: str

        # some clouds (ex. AWS) have policies that already have actions and resources baked in,
        # so we should allow for this customization as well
        # (in that case, there is no need to specify the resource).

        @abstractmethod
        def to_dict(self) -> dict:
            """Convert this object into a Python dictionary."""
            return NotImplemented

    @staticmethod
    @abstractmethod
    def from_dict(
        permissions_list: list[dict],
    ) -> Sequence[
        BasePermission
    ]:  # Sequence (read-only list) is necessary for subclassing
        """Parse policy from a dict."""
        return NotImplemented

    @staticmethod
    @abstractmethod
    def to_dict(permissions: Sequence[BasePermission]) -> Sequence[dict]:
        """Convert a sequence of permissions into a list of dicts."""
        return NotImplemented
