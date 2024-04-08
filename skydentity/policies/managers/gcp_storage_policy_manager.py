import logging as py_logging
from typing import List, Tuple

import backoff
import firebase_admin
from firebase_admin import credentials, firestore
from google.oauth2 import service_account
from googleapiclient import discovery

from skydentity.policies.checker.gcp_storage_policy import (
    Authorization,
    GCPStoragePolicy,
    StoragePolicyAction,
)
from skydentity.policies.iam.gcp_storage_service_account_manager import (
    GCPStorageServiceAccountManager,
)
from skydentity.policies.managers.policy_manager import PolicyManager
from skydentity.utils.log_util import build_file_handler
from skydentity.utils.request_util import (
    DEFAULT_BACKOFF_STRATEGY,
    DEFAULT_MAX_BACKOFF_TRIES,
    request_builder_factory,
)

LOGGER = py_logging.getLogger("policies.managers.GCPStoragePolicyManager")
LOGGER.addHandler(build_file_handler("gcp_storage_policy_manager.log"))


class GCPStoragePolicyManager(PolicyManager):
    def __init__(
        self,
        credentials_path: str,
        firestore_policy_collection: str = "storage_policies",
    ):
        """
        Initializes the GCP policy manager for storage policies.

        :param credentials_path: The path to the credentials file.
        :param firestore_policy_collection: Name of the GCP storage collection for policies.
        """
        self._credentials_path = credentials_path
        self._credentials = service_account.Credentials.from_service_account_file(
            filename=credentials_path,
            scopes=["https://www.googleapis.com/auth/cloud-platform"],
        )

        # firestore
        try:
            self._app = firebase_admin.initialize_app(
                credentials.Certificate(credentials_path),
                name="storage_policy_manager",
            )
        except ValueError:
            self._app = firebase_admin.get_app(name="storage_policy_manager")

        self._db = firestore.client(self._app)
        self._firestore_policy_collection = firestore_policy_collection

        # Create a new Http object for every request
        build_request, authorized_http = request_builder_factory(self._credentials)

        # apis
        self._storage_service = discovery.build(
            "storage",
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

    def get_policy_dict(self, public_key_hash) -> dict:
        """
        Gets a policy from the cloud vendor.
        :param public_key_hash: The hash of the public key tied to the policy.
        :return: The policy.
        """
        LOGGER.debug(f"public key hash {public_key_hash}")
        return (
            self._db.collection(self._firestore_policy_collection)
            .document(public_key_hash)
            .get()
            .to_dict()
        )

    def upload_policy(self, hashed_public_key: str, policy: Authorization):
        """
        Uploads a policy to the cloud vendor.
        :param public_key: The public key of the policy.
        :param policy: The policy to upload.
        """
        policy_dict = GCPStoragePolicy.authorization_to_dict(policy)
        self._db.collection("storage_policies").document(hashed_public_key).set(
            policy_dict
        )

    @backoff.on_exception(
        DEFAULT_BACKOFF_STRATEGY, (TimeoutError), max_tries=DEFAULT_MAX_BACKOFF_TRIES
    )
    def get_project_info_from_bucket_name(self, bucket: str) -> str:
        """
        Retrieve the project ID from the given bucket name.

        :param bucket: bucket name
        """

        bucket_metadata = self._storage_service.buckets().get(bucket=bucket).execute()
        project_number = bucket_metadata["projectNumber"]
        project_metadata = (
            self._cloudresourcemanager_service.projects()
            .get(name=f"projects/{project_number}")
            .execute()
        )

        return project_metadata["projectId"]

    def create_timed_service_account(
        self,
        bucket: str,
        request_action: StoragePolicyAction,
    ) -> Tuple[str, str]:
        """
        Creates a service account with write access to the specified bucket.

        :param access: requested Action for the given service account.

        Returns the credentials for the service account.
        """

        project_id = self.get_project_info_from_bucket_name(bucket)
        LOGGER.debug(f"project id {project_id}")

        gcp_storage_account_manager = GCPStorageServiceAccountManager(
            credentials_path=self._credentials_path,
            project_id=project_id,
        )

        service_account_email, expiration_timestamp = (
            gcp_storage_account_manager.rotate_service_account(bucket, request_action)
        )

        access_token = gcp_storage_account_manager.get_access_token(
            service_account_email=service_account_email,
        )

        return access_token, expiration_timestamp

    def init_service_accounts(
        self, buckets: List[str], actions: List[StoragePolicyAction]
    ):
        if len(buckets) == 0 or len(actions) == 0:
            # no service accounts to initialize; no buckets allowed
            return

        project_id = self.get_project_info_from_bucket_name(buckets[0])

        gcp_storage_account_manager = GCPStorageServiceAccountManager(
            credentials_path=self._credentials_path,
            project_id=project_id,
        )
        gcp_storage_account_manager.init_service_accounts(buckets, actions)
