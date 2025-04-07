import logging
from typing import ClassVar, Optional

from flask import Request

from skydentity.policies.checker.crosscloud_resources.clouds.base import (
    CrossCloudRoleChecker,
)

LOGGER = logging.getLogger(__name__)


class AzureRoleChecker(CrossCloudRoleChecker):
    cloud: ClassVar[str] = "azure"

    # TODO: this class is probably going to be expanded in the future for other kinds of checks

    @staticmethod
    def get_role_from_request(request: Request, valid_roles: set[str]) -> Optional[str]:
        request_body = request.get_json()
        request_tags = request_body.get("tags", {})
        LOGGER.debug("received tags: %s", request_tags)
        LOGGER.debug("checking against roles %s", valid_roles)

        # fetch role from the request
        role = request_tags.get(AzureRoleChecker.crosscloud_role_key, None)

        # check if it is one of the valid roles
        if role is not None and role in valid_roles:
            return role

        # no valid tags found
        return None
