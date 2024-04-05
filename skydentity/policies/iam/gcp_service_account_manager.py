import argparse
#import logging as py_logging
import os

import googleapiclient.discovery
from google.oauth2 import service_account

from skydentity.policies.checker.gcp_authorization_policy import (
    Authorization,
    GCPAuthorizationPolicy,
    RestrictedRole,
)
from skydentity.utils.log_util import build_file_handler

# import httplib2
# httplib2.debuglevel = 4

LOGGER = py_logging.getLogger("policies.iam.GCPServiceAccountManager")
LOGGER.addHandler(build_file_handler(filename="gcp_service_account_manager.log"))


class GCPServiceAccountManager:

    def __init__(self, credentials_path: str) -> None:
        """
        :param credentials_path: path to service account json
        """
        py_logging.basicConfig(
            filename="gcp_service_account_manager.log", level=py_logging.INFO
        )
        LOGGER.debug(f"Credentials path: {credentials_path}")
        self._service_accounts = {}
        self._credentials = service_account.Credentials.from_service_account_file(
            filename=credentials_path,
            scopes=["https://www.googleapis.com/auth/cloud-platform"],
        )
        self._iam_service = googleapiclient.discovery.build(
            "iam", "v1", credentials=self._credentials, cache_discovery=False
        )
        self._cloudresourcemanager_service = googleapiclient.discovery.build(
            "cloudresourcemanager",
            "v3",
            credentials=self._credentials,
            cache_discovery=False,
        )

    def create_service_account(
        self, authorization: GCPAuthorizationPolicy, service_account_name
    ):

        auth: Authorization = authorization._policy

        # Create service account if it doesn't exist
        if service_account_name not in self._service_accounts:

            # Check if service account exists
            try:
                self._iam_service.projects().serviceAccounts().get(
                    name=f"projects/{auth.project}/serviceAccounts/{service_account_name}@{auth.project}.iam.gserviceaccount.com"
                ).execute()
                return
            except:
                self._service_accounts[service_account_name] = (
                    self._iam_service.projects()
                    .serviceAccounts()
                    .create(
                        name=f"projects/{auth.project}",
                        body={
                            "accountId": service_account_name,
                            "serviceAccount": {"displayName": service_account_name},
                        },
                    )
                    .execute()
                )

    def add_roles_to_service_account(
        self, authorization: GCPAuthorizationPolicy, service_account_name
    ):

        auth: Authorization = authorization._policy

        service_account = None
        if service_account_name in self._service_accounts:
            service_account = self._service_accounts[service_account_name]
        else:
            try:
                service_account = (
                    self._iam_service.projects()
                    .serviceAccounts()
                    .get(
                        name=f"projects/{auth.project}/serviceAccounts/{service_account_name}@{auth.project}.iam.gserviceaccount.com"
                    )
                    .execute()
                )
                self._service_accounts[service_account_name] = service_account
            except:
                raise ValueError(
                    f"Service account {service_account_name} does not exist in project {auth.project}"
                )
        service_email = service_account["email"]

        # Get current policy to modify and add roles
        LOGGER.debug(f"Project: {auth.project}")
        iam_policy = (
            self._cloudresourcemanager_service.projects()
            .getIamPolicy(
                resource="projects/" + auth.project,
                body={"options": {"requestedPolicyVersion": 3}},
            )
            .execute()
        )

        def get_object_condition(auth: Authorization, binding: RestrictedRole):
            if binding.scope == "project":
                return None
            elif binding.scope == "bucket":
                return f'resource.name == "projects/_/buckets/{binding.object}/"'
            else:
                raise ValueError(f"Unsupported object {binding.object}")

        for new_binding in auth.roles:
            iam_policy["bindings"].append(
                {
                    "role": new_binding.role,
                    "members": [f"serviceAccount:{service_email}"],
                    "condition": {
                        "title": "skydentity",
                        "description": "skydentity-generated IAM condition",
                        "expression": get_object_condition(auth, new_binding),
                    },
                }
            )

        iam_policy["version"] = 3
        self._cloudresourcemanager_service.projects().setIamPolicy(
            resource="projects/" + auth.project, body={"policy": iam_policy}
        ).execute()
