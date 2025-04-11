import logging
import secrets
import string

import google.auth.transport.requests
import google.oauth2.service_account
from google.api_core import exceptions
from google.api_core.retry import Retry
from google.auth import impersonated_credentials
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

LOGGER = logging.getLogger(__name__)


class GCPCrossCloudServiceAccountManager:
    _EXPIRATION_MINUTES = 60
    """
    Expiration time of short-lived credentials for service accounts;
    GCP limits this to a maximum of 1 hour by default, and can be extended to 12 hours.

    (Expirations of more than 1 hour require the organization-level policy constraint
        `constraints/iam.allowServiceAccountCredentialLifetimeExtension`
    to be set.)
    """

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

            # TODO: more sophisticated input sanitization may be needed;
            # for now, we can be very strict and only allow alphanumeric, along with -./_
            allowed_characters = set(string.ascii_letters + string.digits + "-./_")
            if (
                (set(resource_spec.type) - set(allowed_characters))
                or (
                    resource_spec.name is not None
                    and set(resource_spec.name) - set(allowed_characters)
                )
                or (
                    resource_spec.name_prefix is not None
                    and set(resource_spec.name_prefix) - set(allowed_characters)
                )
            ):
                raise ValueError("Invalid characters in resource specification")

            if resource_spec.name is not None:
                # name takes precedence over prefix
                condition = f"resource.type == '{resource_spec.type}' && resource.name == '{resource_spec.name}'"
            elif resource_spec.name_prefix is not None:
                condition = f"resource.type == '{resource_spec.type}' && resource.name.startsWith('{resource_spec.name_prefix}')"
            else:
                raise ValueError(
                    "At least one of name and name_prefix must be specified."
                )

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

    def generate_credentials(self, service_account_email: str) -> str:
        """
        Generate credentials for a requested service account.

        TODO: can maybe replace this with service account keys for longer access lifetimes (i.e. >12hrs)
        """

        service_account_credentials = impersonated_credentials.Credentials(
            source_credentials=self._credentials,
            target_principal=service_account_email,
            # scope to all services
            target_scopes=["https://www.googleapis.com/auth/cloud-platform"],
            lifetime=self._EXPIRATION_MINUTES * 60,
        )

        LOGGER.debug("Fetching access token for %s", service_account_email)
        request = google.auth.transport.requests.Request()
        service_account_credentials.refresh(request)
        access_token = service_account_credentials.token

        LOGGER.debug("New access token for %s: %s", service_account_email, access_token)

        return access_token
