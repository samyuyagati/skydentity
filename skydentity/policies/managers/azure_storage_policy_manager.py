import json
from typing import List, Tuple
from datetime import datetime, timedelta, timezone

from azure.cosmos import CosmosClient
from azure.cosmos.partition_key import PartitionKey

from skydentity.policies.checker.azure_storage_policy import StoragePolicyAction
from skydentity.policies.managers.policy_manager import PolicyManager
from azure.storage.blob import BlobServiceClient, generate_container_sas, ContainerSasPermissions

class AzureStoragePolicyManager(PolicyManager):
    def __init__(
        self,
        db_endpoint: str = None,
        db_key: str = None,
        db_info_file: str = None,
        storage_account_connection_string: str = None,
        db_name = 'skydentity',
        db_container_name = 'storage_policies'
        ):
        """
        Initializes the azure policy manager for storage policies.

        :param db_endpoint: The endpoint of the Azure database.
        :param db_key: The key of the Azure database.
        :param db_info_file: The path to the database info file.
        :param db_name: The name of the database.
        :param db_container_name: The name of the container.
        """
        if db_info_file is None and db_endpoint is None and db_key is None:
            raise Exception("Must provide either db_info_file or db_endpoint and db_key")

        if storage_account_connection_string is None:
            raise Exception("Must provide storage_account_connection_string")

        if db_info_file is not None:
            db_info = self.get_db_info_from_file(db_info_file)
            db_endpoint = db_info['db_endpoint']
            db_key = db_info['db_key']

        self._client = CosmosClient(db_endpoint, db_key)
        self._db = self._client.create_database_if_not_exists(db_name)
        partition_key = PartitionKey(path = '/id')
        self._container = self._db.create_container_if_not_exists(db_container_name, partition_key = partition_key)

        self._storage_client = BlobServiceClient.from_connection_string(storage_account_connection_string)

    def get_db_info_from_file(self, db_info_file: str):
        """
        Gets the database info from a file, which is expected to eb in JSON format.
        :param db_info_file: The file containing the database info.
        """
        with open(db_info_file, 'r') as f:
            db_info = json.load(f)
            return {
                'db_endpoint': db_info['AZURE_DB_ENDPOINT'],
                'db_key': db_info['AZURE_DB_KEY']
            }

    def upload_policy_dict(self, public_key_hash: str, policy: dict):
        """
        Uploads a policy to Azure.
        :param public_key_hash: The public key of the policy.
        :param policy: The policy to upload.
        """
        self._container.upsert_item(
            body = {
                'id': public_key_hash,
                'policy': policy
            },
        )

    def get_policy_dict(self, public_key_hash) -> dict:
        """
        Gets a policy from the cloud vendor.
        :param public_key_hash: The hash of the public key tied to the policy.
        :return: The policy.
        """
        print(public_key_hash)
        return self._container.read_item(
                    item = public_key_hash,
                    partition_key = public_key_hash,
                )['policy']

    def generate_sas_token(self, container: str, actions: List[StoragePolicyAction]) -> Tuple[str, str]:
        """
        Generates a SAS token for the given container and actions.
        :return: The SAS token and the expiration time.
        """
        # Define the access policy expiration time (15 minutes from now)
        # Start a little before due to potential clock sync issues
        start_time = datetime.now(timezone.utc) - timedelta(minutes=0.5)
        expiration_time = datetime.now(timezone.utc) + timedelta(minutes=15)

        # Define the permissions for the SAS token
        permissions = ""
        
        if StoragePolicyAction.READ in actions:
            permissions = "r"
        if StoragePolicyAction.UPLOAD in actions:
            permissions += "c"
        if StoragePolicyAction.OVERWRITE in actions:
            if "c" not in permissions:
                permissions += "c"
            permissions += "w"

        # Generate the SAS token for the container
        sas_token = generate_container_sas(
            self._storage_client.account_name,
            container,
            account_key=self._storage_client.credential.account_key,
            permission=permissions,
            expiry=expiration_time,
            start=start_time
        )
        return sas_token, expiration_time.isoformat()