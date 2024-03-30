import json
from typing import Union, Dict

from azure.cosmos import CosmosClient
from azure.cosmos.partition_key import PartitionKey

from skydentity.policies.managers.policy_manager import PolicyManager
from skydentity.policies.checker.azure_resource_policy import AzurePolicy
from skydentity.policies.checker.azure_authorization_policy import AzureAuthorizationPolicy

class AzurePolicyManager(PolicyManager):
    """
    A policy manager for Azure.
    """

    def __init__(self,
                 db_endpoint: str = None,
                 db_key: str = None,
                 db_info_file: str = None,
                 policy_type = AzurePolicy,
                 db_name = 'skydentity',
                 db_container_name = 'policies'):
        """
        Initializes the Azure policy manager.
        :param db_endpoint: The endpoint of the Azure database.
        :param db_key: The key of the Azure database.
        :param db_name: The name of the database.
        :param db_container_name: The name of the container.
        """
        self._policy_type = policy_type
        if db_info_file is None and db_endpoint is None and db_key is None:
            raise Exception("Must provide either db_info_file or db_endpoint and db_key")

        if db_info_file is not None:
            db_info = self.get_db_info_from_file(db_info_file)
            db_endpoint = db_info['db_endpoint']
            db_key = db_info['db_key']

        self._client = CosmosClient(db_endpoint, db_key)
        self._db = self._client.create_database_if_not_exists(db_name)
        partition_key = PartitionKey(path = '/id')
        self._container = self._db.create_container_if_not_exists(db_container_name, partition_key = partition_key)

    def upload_policy(self, public_key_hash: str, policy: Union[AzurePolicy, AzureAuthorizationPolicy]):
        """
        Uploads a policy to Azure.
        :param public_key_hash: The public key of the policy.
        :param policy: The policy to upload.
        """
        self.upload_policy_dict(public_key_hash, policy.to_dict())

    def upload_policy_dict(self, public_key_hash: str, policy_dict: Dict):
        """
        Uploads a policy to Azure.
        :param public_key_hash: The public key of the policy.
        :param policy: The policy to upload.
        """
        self._container.upsert_item(
            body = {
                'id': public_key_hash,
                'policy': policy_dict
            },
        )

    def get_policy(self, public_key_hash: str) -> Union[AzurePolicy, AzureAuthorizationPolicy]:
        """
        Gets a policy from the cloud vendor.
        :param public_key_hash: The public key of the policy.
        :return: The policy.
        """
        try:
            policy = self._policy_type.from_dict(
                self._container.read_item(
                    item = public_key_hash,
                    partition_key = public_key_hash,
                )['policy']
            )
            return policy
        except Exception as e:
            print("Failed to get policy from Azure, possibly due to invalid public key:", e)
            return None
        
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