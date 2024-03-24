import secrets
import string
from typing import List, Tuple

import firebase_admin
from firebase_admin import credentials, firestore
from google.oauth2 import service_account
from googleapiclient import discovery

from skydentity.policies.checker.gcp_storage_policy import StoragePolicyAction
from skydentity.policies.iam.gcp_storage_service_account_manager import (
    GCPStorageServiceAccountManager,
)
from skydentity.policies.managers.policy_manager import PolicyManager


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
        self._app = firebase_admin.initialize_app(
            credentials.Certificate(credentials_path),
            name="storage_policy_manager",
        )
        self._db = firestore.client(self._app)
        self._firestore_policy_collection = firestore_policy_collection

        # apis
        self._storage_service = discovery.build(
            "storage", "v1", credentials=self._credentials
        )
        self._cloudresourcemanager_service = discovery.build(
            "cloudresourcemanager", "v3", credentials=self._credentials
        )

    def get_policy_dict(self, public_key_hash) -> dict:
        """
        Gets a policy from the cloud vendor.
        :param public_key_hash: The hash of the public key tied to the policy.
        :return: The policy.
        """
        print(self._firestore_policy_collection)
        print(public_key_hash)
        return (
            self._db.collection(self._firestore_policy_collection)
            .document(public_key_hash)
            .get()
            .to_dict()
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
        request_actions: List[StoragePolicyAction],
    ) -> dict:
        """
        Creates a service account with write access to the specified bucket.

        :param access: requested Action for the given service account.

        Returns the credentials for the service account.
        """

        project_id = self.get_project_info_from_bucket_name(bucket)
        print("project id", project_id)

        gcp_storage_account_manager = GCPStorageServiceAccountManager(
            credentials_path=self._credentials_path
        )

        # Create random service account name from a random 64 bit value
        account_name = secrets.choice(string.ascii_letters) + secrets.token_hex(8)
        print("account name", account_name)

        # Create service account
        gcp_storage_account_manager.create_service_account(
            project_id=project_id,
            service_account_name=account_name,
        )
        print("created service account")

        # Add roles to service account
        gcp_storage_account_manager.add_roles_to_service_account(
            project_id=project_id,
            bucket=bucket,
            request_actions=request_actions,
            service_account_name=account_name,
        )
        print("added roles to service account")

        access_token = gcp_storage_account_manager.get_access_token(
            project_id=project_id,
            service_account_name=account_name,
        )

        return access_token
