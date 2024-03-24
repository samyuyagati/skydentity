import subprocess
from datetime import datetime, timedelta, timezone, tzinfo
from typing import List

from google.oauth2 import service_account
from googleapiclient import discovery

from skydentity.policies.checker.gcp_storage_policy import StoragePolicyAction


class GCPStorageServiceAccountManager:
    def __init__(self, credentials_path: str) -> None:
        """
        :param credentials_path: path to service account json
        """
        self._service_accounts = {}
        self._credentials_path = credentials_path
        self._credentials = service_account.Credentials.from_service_account_file(
            filename=credentials_path,
            scopes=["https://www.googleapis.com/auth/cloud-platform"],
        )
        self._iam_service = discovery.build("iam", "v1", credentials=self._credentials)
        self._cloudresourcemanager_service = discovery.build(
            "cloudresourcemanager", "v3", credentials=self._credentials
        )

        self._roles = {
            StoragePolicyAction.READ: "roles/storage.objectViewer",
            StoragePolicyAction.UPLOAD: "roles/storage.objectCreator",
            StoragePolicyAction.OVERWRITE: "roles/storage.objectUser",
        }

    def create_service_account(self, project_id: str, service_account_name: str):
        """
        Create service account with the requested actions.
        """

        # TODO: create duplicate accounts and cache them

        # Create service account if it doesn't exist
        if service_account_name not in self._service_accounts:

            # Check if service account exists
            try:
                self._iam_service.projects().serviceAccounts().get(
                    name=f"projects/{project_id}/serviceAccounts/{service_account_name}@{project_id}.iam.gserviceaccount.com"
                ).execute()
                return
            except:
                self._service_accounts[service_account_name] = (
                    self._iam_service.projects()
                    .serviceAccounts()
                    .create(
                        name=f"projects/{project_id}",
                        body={
                            "accountId": service_account_name,
                            "serviceAccount": {
                                "displayName": service_account_name,
                                "description": "[skydentity] Automatically created timed service account",
                            },
                        },
                    )
                    .execute()
                )

    def _get_service_account(self, project_id: str, service_account_name: str):
        service_account = None
        if service_account_name in self._service_accounts:
            service_account = self._service_accounts[service_account_name]
        else:
            # fetch service account
            try:
                service_account = (
                    self._iam_service.projects()
                    .serviceAccounts()
                    .get(
                        name=f"projects/{project_id}/serviceAccounts/{service_account_name}@{project_id}.iam.gserviceaccount.com"
                    )
                    .execute()
                )
                self._service_accounts[service_account_name] = service_account
            except Exception as e:
                raise ValueError(
                    f"Service account {service_account_name} does not exist in project {project_id}"
                ) from e

        return service_account

    def add_roles_to_service_account(
        self,
        project_id: str,
        bucket: str,
        request_actions: List[StoragePolicyAction],
        service_account_name: str,
    ):
        """
        Add associated roles to the given service account.
        """

        service_account = self._get_service_account(project_id, service_account_name)
        service_email = service_account["email"]

        # get the current policy
        iam_policy = (
            self._cloudresourcemanager_service.projects()
            .getIamPolicy(
                resource=f"projects/{project_id}",
                body={"options": {"requestedPolicyVersion": 3}},
            )
            .execute()
        )

        roles = []
        if StoragePolicyAction.OVERWRITE in request_actions:
            # read and write roles
            roles = [self._roles[StoragePolicyAction.OVERWRITE]]
        elif StoragePolicyAction.UPLOAD in request_actions:
            # write-only role
            roles = [self._roles[StoragePolicyAction.UPLOAD]]
        elif StoragePolicyAction.READ in request_actions:
            # read-only role
            roles = [self._roles[StoragePolicyAction.READ]]

        expiration_datetime = datetime.now(timezone.utc)
        # add 15 minutes, remove microseconds
        expiration_datetime += timedelta(
            minutes=15, microseconds=-expiration_datetime.microsecond
        )
        # with microseconds=0, the fractional part is omitted in ISO format
        expiration_timestamp = expiration_datetime.isoformat()

        for role in roles:
            iam_policy["bindings"].append(
                {
                    "role": role,
                    "members": [f"serviceAccount:{service_email}"],
                    "condition": {
                        "title": "skydentity-timed",
                        "description": "skydentity-generated IAM condition with expiration",
                        "expression": f'resource.name == "projects/_/buckets/{bucket}" && request.time < timestamp("{expiration_timestamp}")',
                    },
                }
            )

        iam_policy["version"] = 3
        print("storage account policy:", iam_policy)
        self._cloudresourcemanager_service.projects().setIamPolicy(
            resource=f"projects/{project_id}",
            body={"policy": iam_policy},
        ).execute()

    def get_access_token(self, project_id: str, service_account_name: str):
        """
        Generate a short-lived access token for the given service account.
        """
        service_account = self._get_service_account(project_id, service_account_name)

        # activate the service account with the given credentials
        auth_process = subprocess.Popen(
            [
                "gcloud",
                "auth",
                "activate-service-account",
                f"--key-file={self._credentials_path}",
            ]
        )
        auth_process.wait()

        # get an auth token for the service account
        auth_token_process = subprocess.Popen(
            [
                "gcloud",
                "auth",
                "print-access-token",
                "--impersonate-service-account",
                service_account["email"],
            ],
            stdout=subprocess.PIPE,
        )
        auth_token_process_out_bytes, _ = auth_token_process.communicate()
        auth_token = auth_token_process_out_bytes.strip().decode("utf-8")
        return auth_token
