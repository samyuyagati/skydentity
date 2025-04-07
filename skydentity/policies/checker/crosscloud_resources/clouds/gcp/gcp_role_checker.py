from typing import ClassVar, Optional

from flask import Request

from skydentity.policies.checker.crosscloud_resources.clouds.base import (
    CrossCloudRoleChecker,
)


class GCPRoleChecker(CrossCloudRoleChecker):
    cloud: ClassVar[str] = "gcp"
    # TODO: this class is probably going to be expanded in the future for other kinds of checks

    @staticmethod
    def get_role_from_request(request: Request, valid_roles: set[str]) -> Optional[str]:
        request_body = request.get_json()
        request_labels = request_body["labels"]
        print(request_labels)

        # TODO: check tags;
        #  search for "skydentity-crosscloud-role" key?
        #  check if value is part of the roles in the policy
        # TODO: we'll prob be using azure VM accessing GCP resources, so this function may not be needed for a long while
