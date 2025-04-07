import secrets
import string

import google.oauth2.service_account
from google.api_core import exceptions
from google.api_core.retry import Retry
from google.cloud.iam_admin import (
    CreateServiceAccountRequest,
    GetServiceAccountRequest,
    IAMClient,
    ServiceAccount,
)
from googleapiclient import discovery

from skydentity.policies.checker.crosscloud_resources.clouds.gcp.gcp_permission import (
    GCPPermission,
)


class GCPCrossCloudServiceAccountManager:
    def __init__(self, credentials_path: str):
        self._credentials = (
            google.oauth2.service_account.Credentials.from_service_account_file(
                filename=credentials_path,
                scopes=["https://www.googleapis.com/auth/cloud-platform"],
            )
        )
        # get project id from credentials
        self.project = self._credentials.project_id

        self._iam_client = IAMClient(credentials=self._credentials)

        # python api client for resourcemanager is horrible, so we fall back to the discovery api
        self._resourcemanager_service = discovery.build(
            "cloudresourcemanager",
            "v3",
            cache_discovery=False,
            credentials=self._credentials,
        )

    def create_account_with_permissions(
        self, permissions: list[GCPPermission.Permission]
    ) -> str:
        service_account = self.create_service_account()
        service_account_email = service_account.email

        bindings = []

        for permission_obj in permissions:
            role_name = permission_obj.permission
            resource_spec = permission_obj.resource

            resource_type = resource_spec.type
            resource_name = resource_spec.name

            # TODO: more sophisticated input sanitization may be needed;
            # for now, we can be very strict and only allow alphanumeric, along with -./_
            allowed_characters = set(string.ascii_letters + string.digits + "-./_")
            if (set(resource_type) - set(allowed_characters)) or (
                set(resource_name) - set(allowed_characters)
            ):
                raise ValueError("Invalid characters in resource specification")

            condition = f"resource.type == '{resource_spec.type}' && resource.name == '{resource_spec.name}'"

            bindings.append(
                {
                    "role": role_name,
                    "members": [f"serviceAccount:{service_account_email}"],
                    "condition": {"title": "Resource scope", "expression": condition},
                }
            )

        # get old policy
        project_policy = (
            self._resourcemanager_service.projects()
            .getIamPolicy(
                resource=f"projects/{self.project}",
                body={"options": {"requestedPolicyVersion": 3}},
            )
            .execute()
        )

        # add new bindings
        project_policy["bindings"].extend(bindings)

        # set new policy
        self._resourcemanager_service.projects().setIamPolicy(
            resource=f"projects/{self.project}", body={"policy": project_policy}
        ).execute()

        return service_account_email

    def create_service_account(self) -> ServiceAccount:
        """Create a new service account."""
        service_account_name = secrets.choice(string.ascii_letters) + secrets.token_hex(
            8
        )

        create_service_account_request = CreateServiceAccountRequest()
        create_service_account_request.name = f"projects/{self.project}"
        create_service_account_request.account_id = service_account_name
        create_service_account_request.service_account = ServiceAccount()
        create_service_account_request.service_account.display_name = (
            service_account_name
        )
        create_service_account_request.service_account.description = "[skydentity] Automatically generated service account for cross-cloud resource access"

        created_service_account = self._iam_client.create_service_account(
            create_service_account_request
        )

        # request the service account to ensure that it exists
        get_service_account_request = GetServiceAccountRequest()
        get_service_account_request.name = created_service_account.name
        service_account_check = self._iam_client.get_service_account(
            get_service_account_request,
            # retry if the service account is not found
            retry=Retry(lambda e: isinstance(e, exceptions.NotFound)),
        )
        assert service_account_check.name == created_service_account.name

        return created_service_account
