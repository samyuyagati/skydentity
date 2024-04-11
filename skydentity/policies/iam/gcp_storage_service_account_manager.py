import logging as py_logging
import re
import secrets
import string
import subprocess
from datetime import datetime, timedelta, timezone
from functools import cached_property
from typing import TYPE_CHECKING, List, Optional, Tuple, cast

import backoff
from google.oauth2 import service_account
from googleapiclient import discovery
from googleapiclient.errors import HttpError
from googleapiclient.http import ssl

from skydentity.policies.checker.gcp_storage_policy import StoragePolicyAction
from skydentity.utils.log_util import build_file_handler
from skydentity.utils.request_util import (
    DEFAULT_BACKOFF_STRATEGY,
    DEFAULT_MAX_BACKOFF_TRIES,
    request_builder_factory,
)

LOGGER = py_logging.getLogger("policies.iam.GCPStorageServiceAccountManager")
LOGGER.addHandler(build_file_handler("gcp_storage_service_account_manager.log"))


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
    ) -> None:
        """
        :param credentials_path: path to service account json
        """
        self.project_id = project_id

        self._credentials_path = credentials_path
        self._credentials = service_account.Credentials.from_service_account_file(
            filename=credentials_path,
            scopes=["https://www.googleapis.com/auth/cloud-platform"],
        )

        # Create a new Http object for every request
        build_request, authorized_http = request_builder_factory(self._credentials)

        self._iam_service = discovery.build(
            "iam",
            "v1",
            cache_discovery=False,
            requestBuilder=build_request,
            http=authorized_http,
        )
        self._cloudresourcemanager_service = discovery.build(
            "cloudresourcemanager",
            "v3",
            cache_discovery=False,
            requestBuilder=build_request,
            http=authorized_http,
        )
        self._storage_service = discovery.build(
            "storage",
            "v1",
            cache_discovery=False,
            requestBuilder=build_request,
            http=authorized_http,
        )

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

    @cached_property
    def all_service_accounts(self) -> List[dict]:
        """
        Retrieves all service accounts for a project.

        Cached property; only computed once for the life of the instance.
        """
        LOGGER.debug("Listing all service accounts")
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
        LOGGER.debug(
            f"Done listing all service accounts; {len(all_service_accounts)} total"
        )

        return all_service_accounts

    def invalidate_cached_service_accounts(self):
        """
        Invalidate the current instance's cache of service accounts.
        """
        if "all_service_accounts" in self.__dict__:
            del self.all_service_accounts

    def init_service_accounts(
        self, buckets: List[str], actions: List[StoragePolicyAction]
    ):
        """
        Initializes backup service accounts.
        """
        # make a service account for each bucket and action pair
        for bucket in buckets:
            for action in actions:
                current, backup = self.get_service_accounts_for_resource(bucket, action)

                # only create backups if it doesn't exist already
                if len(backup) == 0:
                    self.create_service_account(bucket, action, backup=True)

                # delete all timed accounts
                if len(current) > 0:
                    for account in current:
                        self.delete_service_account(account["email"], bucket, action)

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

        LOGGER.debug(
            f"[{bucket}/{action.value}/{'backup' if backup else 'timed'}]"
            f" Creating service account {service_account_name}...",
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

        # add roles to the service account, retrying with exponential backoff
        add_timed = not backup
        expiration_timestamp = self.add_roles_to_service_account(
            service_account["email"], bucket, action, timed=add_timed
        )

        LOGGER.info(
            f"[{bucket}/{action.value}/{'backup' if backup else 'timed'}]"
            f" Created service account {service_account['email']};"
            f" expires {expiration_timestamp}",
        )

        # invalidate cache of service accounts, since we've added a new one
        self.invalidate_cached_service_accounts()

        return service_account, expiration_timestamp

    def delete_service_account(
        self, service_account_email: str, bucket: str, action: StoragePolicyAction
    ):
        """
        Delete a service account.
        """
        LOGGER.debug(f"[{bucket}/{action.value}] Deleting {service_account_email}")
        self._iam_service.projects().serviceAccounts().delete(
            name=f"projects/{self.project_id}/serviceAccounts/{service_account_email}"
        ).execute()
        LOGGER.info(f"[{bucket}/{action.value}] Deleted {service_account_email}")

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

        @backoff.on_exception(
            DEFAULT_BACKOFF_STRATEGY,
            (HttpError, ssl.SSLError),
            max_tries=DEFAULT_MAX_BACKOFF_TRIES,
        )
        def update_bucket_policy():
            """
            Update the IAM policy for the given bucket.

            Retries with backoff in case of failure (usually due to concurrency).
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

            # update bucket policy
            if timed:
                LOGGER.debug(f"[{bucket}/{action}] Adding timed policy to bucket")
                iam_policy["bindings"].append(
                    {
                        "role": role,
                        "members": [f"serviceAccount:{service_account_email}"],
                        "condition": {
                            "title": self._ROLE_TITLES["timed"],
                            "description": f"[{service_account_email}] {self._ROLE_DESCRIPTIONS['timed']}",
                            "expression": f'request.time < timestamp("{expiration_timestamp}")',
                        },
                    }
                )
            else:
                LOGGER.debug(f"[{bucket}/{action}] Adding untimed policy to bucket")
                iam_policy["bindings"].append(
                    {
                        "role": role,
                        "members": [f"serviceAccount:{service_account_email}"],
                        "condition": {
                            "title": self._ROLE_TITLES["untimed"],
                            "description": f"[{service_account_email}] {self._ROLE_DESCRIPTIONS['untimed']}",
                            # no condition
                            "expression": "true",
                        },
                    }
                )
            iam_policy["version"] = 3
            # save storage policy
            self._storage_service.buckets().setIamPolicy(
                bucket=bucket,
                body=iam_policy,
                userProject=self.project_id,
            ).execute()

        @backoff.on_exception(
            DEFAULT_BACKOFF_STRATEGY,
            (HttpError, ssl.SSLError),
            max_tries=DEFAULT_MAX_BACKOFF_TRIES,
        )
        def update_project_policy():
            """
            Update the IAM policy for the given project.

            Retries with backoff in case of failure (usually due to concurrency).
            """
            # get the current project policy
            project_iam_policy = (
                self._cloudresourcemanager_service.projects()
                .getIamPolicy(
                    resource=f"projects/{self.project_id}",
                    body={"options": {"requestedPolicyVersion": 3}},
                )
                .execute()
            )
            # update project policy
            # add service usage consumer role; always needed to access resources
            if timed:
                LOGGER.debug(f"[{bucket}/{action}] Adding timed policy to project")
                project_iam_policy["bindings"].append(
                    {
                        "role": self._SERVICE_USAGE_CONSUMER_ROLE,
                        "members": [f"serviceAccount:{service_account_email}"],
                        "condition": {
                            "title": self._ROLE_TITLES["timed"],
                            "description": f"[{service_account_email}] {self._ROLE_DESCRIPTIONS['timed']}",
                            "expression": f'request.time < timestamp("{expiration_timestamp}")',
                        },
                    }
                )
            else:
                LOGGER.debug(f"[{bucket}/{action}] Adding untimed policy to project")
                project_iam_policy["bindings"].append(
                    {
                        "role": self._SERVICE_USAGE_CONSUMER_ROLE,
                        "members": [f"serviceAccount:{service_account_email}"],
                        "condition": {
                            "title": self._ROLE_TITLES["untimed"],
                            "description": f"[{service_account_email}] {self._ROLE_DESCRIPTIONS['untimed']}",
                            "expression": "true",
                        },
                    }
                )
            project_iam_policy["version"] = 3
            # save project policy
            self._cloudresourcemanager_service.projects().setIamPolicy(
                resource=f"projects/{self.project_id}",
                body={"policy": project_iam_policy},
            ).execute()

        # update each policy with exponential backoff
        update_bucket_policy()
        update_project_policy()

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

        expiration_datetime = datetime.now(timezone.utc)
        # add 15 minutes, remove microseconds
        expiration_datetime += timedelta(
            minutes=self._EXPIRATION_MINUTES,
            microseconds=-expiration_datetime.microsecond,
        )
        # with microseconds=0, the fractional part is omitted in ISO format
        expiration_timestamp = expiration_datetime.isoformat()

        @backoff.on_exception(
            DEFAULT_BACKOFF_STRATEGY,
            (HttpError, ssl.SSLError),
            max_tries=DEFAULT_MAX_BACKOFF_TRIES,
        )
        def update_bucket_policy():
            """
            Update the IAM policy for the given bucket.

            Retries with backoff in case of failure (usually due to concurrency).
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

            # update policies for the bucket
            changed = False
            for binding in iam_policy["bindings"]:
                if (
                    # filter for desired service account
                    f"serviceAccount:{service_account_email}" in binding["members"]
                    # filter for untimed role
                    and binding["condition"]["title"] == self._ROLE_TITLES["untimed"]
                ):
                    if len(binding["members"]) > 1:
                        LOGGER.warning(
                            f"Multiple members in binding: {binding['members']}"
                        )
                        continue

                    changed = True
                    # add expiration to the role
                    binding["condition"][
                        "expression"
                    ] = f'request.time < timestamp("{expiration_timestamp}")'
                    # update title
                    binding["condition"]["title"] = self._ROLE_TITLES["timed"]
                    binding["condition"][
                        "description"
                    ] = f"[{service_account_email}] {self._ROLE_DESCRIPTIONS['timed']}"

            if changed:
                # save policy
                self._storage_service.buckets().setIamPolicy(
                    bucket=bucket,
                    body=iam_policy,
                    userProject=self.project_id,
                ).execute()

            return changed

        @backoff.on_exception(
            DEFAULT_BACKOFF_STRATEGY,
            (HttpError, ssl.SSLError),
            max_tries=DEFAULT_MAX_BACKOFF_TRIES,
        )
        def update_project_policy():
            """
            Update the IAM policy for the given project.

            Retries with backoff in case of failure (usually due to concurrency).
            """
            # get the current project policy
            project_iam_policy = (
                self._cloudresourcemanager_service.projects()
                .getIamPolicy(
                    resource=f"projects/{self.project_id}",
                    body={"options": {"requestedPolicyVersion": 3}},
                )
                .execute()
            )

            # update policies for the project
            changed = False
            for binding in project_iam_policy["bindings"]:
                if (
                    # filter for desired service account
                    f"serviceAccount:{service_account_email}" in binding["members"]
                    # filter for untimed role
                    and binding["condition"]["title"] == self._ROLE_TITLES["untimed"]
                ):
                    if len(binding["members"]) > 1:
                        LOGGER.warning(
                            f"Multiple members in binding: {binding['members']}"
                        )
                        continue

                    changed = True
                    # add expiration to the role
                    binding["condition"][
                        "expression"
                    ] = f'request.time < timestamp("{expiration_timestamp}")'
                    # update title
                    binding["condition"]["title"] = self._ROLE_TITLES["timed"]
                    binding["condition"][
                        "description"
                    ] = f"[{service_account_email}] {self._ROLE_DESCRIPTIONS['timed']}"

            if changed:
                # save project policy
                self._cloudresourcemanager_service.projects().setIamPolicy(
                    resource=f"projects/{self.project_id}",
                    body={"policy": project_iam_policy},
                ).execute()

            return changed

        # update each policy with exponential backoff
        bucket_iam_changed = update_bucket_policy()
        project_iam_changed = update_project_policy()

        # only update the service account if anything was changed
        if bucket_iam_changed or project_iam_changed:
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
            # invalidate cache of service accounts, since it's been modified
            self.invalidate_cached_service_accounts()

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

        if len(backup_list) > 0:
            # if more than one exists, arbitrarliy choose the first
            backup = backup_list[0]
            # update the backup account to add an expiration
            backup_email = backup["email"]
            LOGGER.debug(
                f"[{bucket}/{action.value}] Adding expiration to {backup_email}"
            )
            expiration_timestamp = self.add_expiration_to_service_account(
                backup_email, bucket, action
            )
            LOGGER.info(
                f"[{bucket}/{action.value}] Expiration for {backup_email} set to {expiration_timestamp}"
            )
            new_email = backup_email
        else:
            LOGGER.debug(
                f"[{bucket}/{action.value}] Directly creating service account with expiration"
            )
            # no backup exists; directly create an account with an expiration time
            new_service_account, expiration_timestamp = self.create_service_account(
                bucket, action, backup=False
            )
            new_email = new_service_account["email"]

            # cast for typing; we know the expiration timestamp will be given, since backup=False
            if TYPE_CHECKING:
                expiration_timestamp = cast(str, expiration_timestamp)

        # preparation for next calls
        # delete the current service accounts
        # if len(current_list) > 0:
        #     LOGGER.debug(
        #         f"Service accounts to delete: {[acc['email'] for acc in current_list]}"
        #     )
        #     for current in current_list:
        #         current_email = current["email"]
        #         self.delete_service_account(
        #             service_account_email=current_email, bucket=bucket, action=action
        #         )

        # re-create the backup account
        # self.create_service_account(bucket, action, backup=True)

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
