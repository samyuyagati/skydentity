import re
import secrets
import string
import subprocess
from datetime import datetime, timedelta, timezone, tzinfo
from functools import cached_property
from typing import TYPE_CHECKING, Callable, List, Optional, Tuple, cast

from Crypto.Hash import HMAC
from google.oauth2 import service_account
from googleapiclient import discovery
from googleapiclient.errors import HttpError

from skydentity.policies.checker.gcp_storage_policy import StoragePolicyAction


class GCPStorageServiceAccountManager:
    """
    Service account manager for GCP storage integration.

    Each instance is associated with a single project id.
    """

    # roles for each policy action type
    _ACTION_ROLES = {
        StoragePolicyAction.READ: "roles/storage.objectViewer",
        StoragePolicyAction.UPLOAD: "roles/storage.objectCreator",
        StoragePolicyAction.OVERWRITE: "roles/storage.objectUser",
    }

    _SERVICE_USAGE_CONSUMER_ROLE = "roles/serviceusage.serviceUsageConsumer"

    # role titles; used for matching
    _ROLE_TITLES = {
        "timed": "skydentity-storage-timed",
        "untimed": "skydentity-storage-untimed",
    }
    _ROLE_DESCRIPTIONS = {
        "timed": "skydentity-generated IAM condition with expiration",
        "untimed": "skydentity-generated IAM condition with no expiration (backup use only)",
    }

    # service account permission expiration time in minutes
    _EXPIRATION_MINUTES = 15

    def __init__(
        self,
        credentials_path: str,
        project_id: str,
        log_func: Optional[Callable] = None,
    ) -> None:
        """
        :param credentials_path: path to service account json
        """
        self.project_id = project_id
        self._log_func = log_func

        self._credentials_path = credentials_path
        self._credentials = service_account.Credentials.from_service_account_file(
            filename=credentials_path,
            scopes=["https://www.googleapis.com/auth/cloud-platform"],
        )

        self._iam_service = discovery.build("iam", "v1", credentials=self._credentials)
        self._cloudresourcemanager_service = discovery.build(
            "cloudresourcemanager", "v3", credentials=self._credentials
        )
        self._storage_service = discovery.build(
            "storage", "v1", credentials=self._credentials
        )

    def log(self, *args, **kwargs):
        """
        Wrapper for the log function; if it exists, logs using the log function, otherwise just prints.
        """
        if self._log_func is not None:
            self._log_func(*args, **kwargs)
        else:
            print(*args)

    def generate_service_account_name(self):
        """
        Generate a random secure service account name.
        """
        return secrets.choice(string.ascii_letters) + secrets.token_hex(8)

    def _service_account_description(
        self, bucket: str, action: StoragePolicyAction, backup: bool = False
    ) -> str:
        """
        Generate a service account description from a given bucket and action.

        The descriptions are used to filter service accounts to match with buckets/actions.

        Care must be taken to ensure that the description is at most 256 characters:
        - Bucket names are restricted to <= 63 characters
        - Action values are always <= 10 characters
        As such, other text needs to be restricted to <= 83 characters.
        """

        if backup:
            return f"[skydentity/backup/{bucket}/{action.value}] Automatically generated backup service account"
        else:
            return f"[skydentity/{bucket}/{action.value}] Automatically generated timed service account"

    def _match_service_account_description(
        self,
        description: str,
        bucket: str,
        action: StoragePolicyAction,
        backup: bool = False,
    ) -> Optional[re.Match]:
        """
        Match a given service account description with a bucket and action;
        returns the match if theere is one, or None otherwise.
        """

        if backup:
            pattern = re.compile(
                re.escape(f"[skydentity/backup/{bucket}/{action.value}]")
            )
        else:
            pattern = re.compile(re.escape(f"[skydentity/{bucket}/{action.value}]"))

        match = re.search(pattern, description)
        return match

    def init_service_accounts(
        self, buckets: List[str], actions: List[StoragePolicyAction]
    ):
        """
        Initializes backup service accounts.
        """
        # make a service account for each bucket and action pair
        for bucket in buckets:
            for action in actions:
                # no need for the current; just ensure that we have backups ready
                _, backup = self.get_service_accounts_for_resource(bucket, action)

                # only create if it doesn't exist already
                if len(backup) == 0:
                    self.create_service_account(bucket, action, backup=True)

    def create_service_account(
        self, bucket: str, action: StoragePolicyAction, backup: bool = False
    ) -> Tuple[dict, Optional[str]]:
        """
        Create service account, and the correct permissions for the requested action and bucket
        are attached to the account.

        If backup is False (default), then an additional timed condition is added to the role.
        Otherwise, no timing conditions are added.

        Does NOT check whether there already exists any other service accounts for the given
        bucket and action; this must be done prior to calling this method,
        otherwise duplicate accounts may be created.

        Returns a tuple (service_account_dict, expiration):
        - `service_account_dict` is the full service account information from the response
        - `expiration` is the ISO timestamp of when the service account permissions expire;
            if no expiration time is included, then this is None
        """

        service_account_name = self.generate_service_account_name()

        self.log(
            f"[{bucket}/{action.value}/{'backup' if backup else 'timed'}]"
            f" Creating service account {service_account_name}..."
        )

        # Check if service account exists (generally shouldn't happen)
        try:
            self._iam_service.projects().serviceAccounts().get(
                name=f"projects/{self.project_id}/serviceAccounts/{service_account_name}@{self.project_id}.iam.gserviceaccount.com"
            ).execute()
            raise RuntimeError(
                f"Randomly generated service account name already exists! ({service_account_name})"
            )
        except HttpError:
            # create service account
            service_account: dict = (
                self._iam_service.projects()
                .serviceAccounts()
                .create(
                    name=f"projects/{self.project_id}",
                    body={
                        "accountId": service_account_name,
                        "serviceAccount": {
                            "displayName": service_account_name,
                            "description": self._service_account_description(
                                bucket, action, backup
                            ),
                        },
                    },
                )
                .execute()
            )

        # add roles to the service account
        add_timed = not backup
        expiration_timestamp = self.add_roles_to_service_account(
            service_account["email"], bucket, action, timed=add_timed
        )

        self.log(
            f"[{bucket}/{action.value}/{'backup' if backup else 'timed'}]"
            f" Created service account {service_account['email']};"
            f" expires {expiration_timestamp}",
        )
        return service_account, expiration_timestamp

    @cached_property
    def all_service_accounts(self) -> List[dict]:
        """
        Retrieves all service accounts for a project.

        Cached property; only computed once for the life of the instance.
        """
        self.log("Listing all service accounts")
        all_service_accounts = []

        list_request = (
            self._iam_service.projects()
            .serviceAccounts()
            .list(name=f"projects/{self.project_id}")
        )

        while list_request:
            list_response = list_request.execute()

            all_service_accounts.extend(list_response.get("accounts", []))

            list_request = (
                self._iam_service.projects()
                .serviceAccounts()
                .list_next(
                    previous_request=list_request, previous_response=list_response
                )
            )
        self.log(
            f"Done listing all service accounts; {len(all_service_accounts)} total"
        )

        return all_service_accounts

    def get_service_accounts_for_resource(
        self, bucket: str, action: StoragePolicyAction
    ) -> Tuple[List[dict], List[dict]]:
        """
        Check stored service accounts to match the bucket and action.

        Returns a tuple (current_list, backup_list) of service accounts;
        the corresponding lists will be empty if no service accounts match.
        """

        current_accounts = []
        backup_accounts = []

        # filter all service accounts for matching bucket/action
        for service_account in self.all_service_accounts:
            description = service_account.get("description", None)
            if description is None:
                continue

            # match description
            current_match = self._match_service_account_description(
                description, bucket, action, backup=False
            )
            backup_match = self._match_service_account_description(
                description, bucket, action, backup=True
            )

            if current_match is not None:
                current_accounts.append(service_account)
            if backup_match is not None:
                backup_accounts.append(service_account)

        # return accounts
        return current_accounts, backup_accounts

    def add_roles_to_service_account(
        self,
        service_account_email: str,
        bucket: str,
        action: StoragePolicyAction,
        timed: bool = True,
    ) -> Optional[str]:
        """
        Add associated roles to the given service account.
        If timed is True, also sets a 15 minute expiration time on all roles, returning the expiration timestamp.
        If timed is False, does not set any expiration and returns None.

        Assumes that the service account has no prior roles (related to skydentity).

        Adds a bucket-level access permission, as well as a project-level usage consumer permission.
        """

        # get the current bucket policy
        iam_policy = (
            self._storage_service.buckets()
            .getIamPolicy(
                bucket=bucket,
                optionsRequestedPolicyVersion=3,
                userProject=self.project_id,
            )
            .execute()
        )
        # get the current project policy
        project_iam_policy = (
            self._cloudresourcemanager_service.projects()
            .getIamPolicy(
                resource=f"projects/{self.project_id}",
                body={"options": {"requestedPolicyVersion": 3}},
            )
            .execute()
        )

        if action == StoragePolicyAction.OVERWRITE:
            # read and write roles
            role = self._ACTION_ROLES[StoragePolicyAction.OVERWRITE]
        elif action == StoragePolicyAction.UPLOAD:
            # write-only role
            role = self._ACTION_ROLES[StoragePolicyAction.UPLOAD]
        elif action == StoragePolicyAction.READ:
            # read-only role
            role = self._ACTION_ROLES[StoragePolicyAction.READ]
        else:
            raise ValueError(f"Invalid action: {action}")

        expiration_datetime = datetime.now(timezone.utc)
        # add 15 minutes, remove microseconds
        expiration_datetime += timedelta(
            minutes=self._EXPIRATION_MINUTES,
            microseconds=-expiration_datetime.microsecond,
        )
        # with microseconds=0, the fractional part is omitted in ISO format
        expiration_timestamp = expiration_datetime.isoformat()

        # update bucket policy
        if timed:
            iam_policy["bindings"].append(
                {
                    "role": role,
                    "members": [f"serviceAccount:{service_account_email}"],
                    "condition": {
                        "title": self._ROLE_TITLES["timed"],
                        "description": self._ROLE_DESCRIPTIONS["timed"],
                        "expression": f'request.time < timestamp("{expiration_timestamp}")',
                    },
                }
            )
        else:
            iam_policy["bindings"].append(
                {
                    "role": role,
                    "members": [f"serviceAccount:{service_account_email}"],
                    "condition": {
                        "title": self._ROLE_TITLES["untimed"],
                        "description": self._ROLE_DESCRIPTIONS["untimed"],
                        # no condition
                        "expression": "true",
                    },
                }
            )

        # update project policy
        # add service usage consumer role; always needed to access resources
        if timed:
            project_iam_policy["bindings"].append(
                {
                    "role": self._SERVICE_USAGE_CONSUMER_ROLE,
                    "members": [f"serviceAccount:{service_account_email}"],
                    "condition": {
                        "title": self._ROLE_TITLES["timed"],
                        "description": self._ROLE_DESCRIPTIONS["timed"],
                        "expression": f'request.time < timestamp("{expiration_timestamp}")',
                    },
                }
            )
        else:
            project_iam_policy["bindings"].append(
                {
                    "role": self._SERVICE_USAGE_CONSUMER_ROLE,
                    "members": [f"serviceAccount:{service_account_email}"],
                    "condition": {
                        "title": self._ROLE_TITLES["untimed"],
                        "description": self._ROLE_DESCRIPTIONS["untimed"],
                        "expression": "true",
                    },
                }
            )

        iam_policy["version"] = 3
        project_iam_policy["version"] = 3

        # save storage policy
        self._storage_service.buckets().setIamPolicy(
            bucket=bucket,
            body=iam_policy,
            userProject=self.project_id,
        ).execute()
        # save project policy
        self._cloudresourcemanager_service.projects().setIamPolicy(
            resource=f"projects/{self.project_id}", body={"policy": project_iam_policy}
        ).execute()

        if timed:
            return expiration_timestamp
        else:
            return None

    def add_expiration_to_service_account(
        self, service_account_email: str, bucket: str, action: StoragePolicyAction
    ):
        """
        Update the given service account to add an expiration time to relevant permissions.

        Modifies the bucket-level access permission, as well as the project-level usage consumer permission.
        """
        # get the current bucket policy
        iam_policy = (
            self._storage_service.buckets()
            .getIamPolicy(
                bucket=bucket,
                optionsRequestedPolicyVersion=3,
                userProject=self.project_id,
            )
            .execute()
        )
        # get the current project policy
        project_iam_policy = (
            self._cloudresourcemanager_service.projects()
            .getIamPolicy(
                resource=f"projects/{self.project_id}",
                body={"options": {"requestedPolicyVersion": 3}},
            )
            .execute()
        )

        expiration_datetime = datetime.now(timezone.utc)
        # add 15 minutes, remove microseconds
        expiration_datetime += timedelta(
            minutes=self._EXPIRATION_MINUTES,
            microseconds=-expiration_datetime.microsecond,
        )
        # with microseconds=0, the fractional part is omitted in ISO format
        expiration_timestamp = expiration_datetime.isoformat()

        # update policies for the bucket
        for binding in iam_policy["bindings"]:
            if (
                # filter for desired service account
                f"serviceAccount:{service_account_email}" in binding["members"]
                # filter for untimed role
                and binding["condition"]["title"] == self._ROLE_TITLES["untimed"]
            ):
                # add expiration to the role
                binding["condition"][
                    "expression"
                ] = f'request.time < timestamp("{expiration_timestamp}")'
                # update title
                binding["condition"]["title"] = self._ROLE_TITLES["timed"]

        # update policies for the project
        for binding in project_iam_policy["bindings"]:
            if (
                # filter for desired service account
                f"serviceAccount:{service_account_email}" in binding["members"]
                # filter for untimed role
                and binding["condition"]["title"] == self._ROLE_TITLES["untimed"]
            ):
                # add expiration to the role
                binding["condition"][
                    "expression"
                ] = f'request.time < timestamp("{expiration_timestamp}")'
                # update title
                binding["condition"]["title"] = self._ROLE_TITLES["timed"]

        # save policy
        self._storage_service.buckets().setIamPolicy(
            bucket=bucket,
            body=iam_policy,
            userProject=self.project_id,
        ).execute()
        # save project policy
        self._cloudresourcemanager_service.projects().setIamPolicy(
            resource=f"projects/{self.project_id}", body={"policy": project_iam_policy}
        ).execute()

        # update the service account description; should no longer be labeled as backup
        self._iam_service.projects().serviceAccounts().patch(
            name=f"projects/{self.project_id}/serviceAccounts/{service_account_email}",
            body={
                "serviceAccount": {
                    "description": self._service_account_description(
                        bucket, action, backup=False
                    ),
                },
                "updateMask": "description",
            },
        ).execute()

        return expiration_timestamp

    def rotate_service_account(
        self, bucket: str, action: StoragePolicyAction
    ) -> Tuple[str, str]:
        """
        Rotate the service account associated with the given bucket/action.

        This deletes any currently timed service account, adds an expiration time
        to the backup account (converting it into the currently active account),
        and creates a new backup service account.

        Returns the new service account email along with the expiration timestamp.
        """
        current_list, backup_list = self.get_service_accounts_for_resource(
            bucket, action
        )

        if len(current_list) > 0:
            # delete the current service accounts
            for current in current_list:
                current_email = current["email"]
                self.log(f"[{bucket}/{action.value}] Deleting {current_email}")
                self._iam_service.projects().serviceAccounts().delete(
                    name=f"projects/{self.project_id}/serviceAccounts/{current_email}"
                ).execute()

        if len(backup_list) > 0:
            # if more than one exists, arbitrarliy choose the first
            backup = backup_list[0]
            # update the backup account to add an expiration
            backup_email = backup["email"]
            self.log(f"[{bucket}/{action.value}] Adding expiration to {backup_email}")
            expiration_timestamp = self.add_expiration_to_service_account(
                backup_email, bucket, action
            )
            new_email = backup_email
        else:
            # no backup exists; directly create an account with an expiration time
            new_service_account, expiration_timestamp = self.create_service_account(
                bucket, action, backup=False
            )
            new_email = new_service_account["email"]

            # cast for typing; we know the expiration timestamp will be given, since backup=False
            if TYPE_CHECKING:
                expiration_timestamp = cast(str, expiration_timestamp)

        # re-create the backup account
        self.create_service_account(bucket, action, backup=True)

        return new_email, expiration_timestamp

    def get_access_token(self, service_account_email: str) -> str:
        """
        Generate a short-lived access token for the given service account.
        """
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
                f"--lifetime={self._EXPIRATION_MINUTES * 60}",
                "--impersonate-service-account",
                # lifetime of access token in seconds
                service_account_email,
            ],
            stdout=subprocess.PIPE,
        )
        auth_token_process_out_bytes, _ = auth_token_process.communicate()
        auth_token = auth_token_process_out_bytes.strip().decode("utf-8")
        return auth_token
