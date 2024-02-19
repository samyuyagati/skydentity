from azure.cosmos import CosmosClient
from azure.cosmos.partition_key import PartitionKey
from azure.identity import DefaultAzureCredential

from skydentity.policies.managers.policy_manager import PolicyManager
from skydentity.policies.checker.azure_resource_policy import AzurePolicy
from skydentity.policies.checker.azure_authorization_policy import AzureAuthorizationPolicy

class AzurePolicyManager(PolicyManager):
    """
    A policy manager for Azure.
    """

    def __init__(self,
                 db_endpoint: str,
                 db_key: str,
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
        self._client = CosmosClient(db_endpoint, db_key)
        self._db = self._client.create_database_if_not_exists(db_name)
        partition_key = PartitionKey(path = '/id')
        self._container = self._db.create_container_if_not_exists(db_container_name, partition_key = partition_key)

    def upload_policy(self, public_key: str, policy: AzurePolicy | AzureAuthorizationPolicy):
        """
        Uploads a policy to Azure.
        :param public_key: The public key of the policy.
        :param policy: The policy to upload.
        """
        self._container.upsert_item(
            body = {
                'id': public_key,
                'policy': policy.to_dict()
            },
        )

    def get_policy(self, public_key: str) -> AzurePolicy | AzureAuthorizationPolicy:
        """
        Gets a policy from the cloud vendor.
        :param public_key: The public key of the policy.
        :return: The policy.
        """
        return self._policy_type.from_dict(
            self._container.read_item(
                item = public_key,
                partition_key = public_key
            )['policy']
        )