from abc import ABC, abstractmethod
from typing import ClassVar, Optional

from flask import Request


class CrossCloudRoleChecker(ABC):
    cloud: ClassVar[str]
    """Name of the current cloud"""

    crosscloud_role_key: ClassVar[str] = "skydentity-crosscloud-role"
    """Key to use when retrieving the crosscloud role from the VM tags"""

    @staticmethod
    @abstractmethod
    def get_role_from_request(request: Request, valid_roles: set[str]) -> Optional[str]:
        """
        Check a VM creation request to determine whether it attaches a role to the VM,
        from one of the roles given as input.
        If it does, return the role. Otherwise, returns None.
        """
        return NotImplemented
