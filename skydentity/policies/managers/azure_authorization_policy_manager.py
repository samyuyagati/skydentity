from base64 import b64encode, b64decode
from Crypto.Cipher import AES
import secrets
import string
from typing import Dict
from functools import cache

from skydentity.policies.managers.policy_manager import PolicyManager
from skydentity.policies.checker.azure_authorization_policy import AzureAuthorizationPolicy
from skydentity.policies.iam.azure_managed_identity_manager import AzureManagedIdentityManager

from azure.identity import DefaultAzureCredential
from azure.mgmt.subscription import SubscriptionClient

class AzureAuthorizationPolicyManager(PolicyManager):
    """
    A policy manager for Azure.
    """

    def __init__(self,
                 capability_enc_path: str,
                 db_endpoint: str = None,
                 db_key: str = None,
                 db_info_file: str = None,
                 ):
        """
        Initializes the Azure policy manager.
        :param db_endpoint: The endpoint of the Azure database.
        :param db_key: The key of the Azure database.
        :param capability_enc_path: The path to the capability encryption key.
        """
        from skydentity.policies.managers.azure_policy_manager import AzurePolicyManager
        self._internal_policy_manager = AzurePolicyManager(db_endpoint, db_key, db_info_file, policy_type=AzureAuthorizationPolicy, db_container_name='authorization_policies')
        with open(capability_enc_path, 'rb') as f:
            self._capability_enc = f.read()

    def get_policy_dict(self, public_key_hash: str) -> Dict:
        return self._internal_policy_manager.get_policy(public_key_hash).to_dict()
    
    def generate_capability(self, managed_identity_id: str) -> dict:
        """
        Encrypts the managed identity identifier with AES-GCM and returns it as a capability.
        """
        cipher = AES.new(self._capability_enc, AES.MODE_GCM)
        header = b"" # No public information required; could later make this the public key of the broker if desired
        cipher.update(header)
        capability, tag = cipher.encrypt_and_digest(managed_identity_id.encode('utf-8'))
        dict_keys = ['nonce', 'header', 'ciphertext', 'tag']
        dict_values = [b64encode(x).decode('utf-8') for x in (cipher.nonce, header, capability, tag)]
        return dict(zip(dict_keys, dict_values))
    
    def check_capability(self, capability: dict) -> (str, bool):
        """
        Decrypts the capability and returns True, along with the managed identity id, if it is valid.
        """
        nonce = b64decode(capability['nonce'])
        header = b64decode(capability['header']) # If checking broker public key, check that the header matches the public key attached to the request
        ciphertext = b64decode(capability['ciphertext'])
        tag = b64decode(capability['tag'])
        cipher = AES.new(self._capability_enc, AES.MODE_GCM, nonce=nonce)
        cipher.update(header)
        try:
            candidate_managed_identity_id = cipher.decrypt_and_verify(ciphertext, tag)
            return (candidate_managed_identity_id.decode('utf-8'), True)
        except ValueError:
            print("Invalid capability: could not decrypt or verify")
            return (None, False)

    @cache  
    def get_subscription_id(self) -> str:
        """
        Gets the subscription id from the Azure database.
        :return: The subscription id.
        """
        credential = DefaultAzureCredential()
        subscription_client = SubscriptionClient(credential)
        subscription = next(subscription_client.subscriptions.list())
        return subscription.subscription_id
        
    def create_managed_identity_with_roles(self, authorization: AzureAuthorizationPolicy) -> str:
        """
        Creates a managed identity with the roles specified in the policy.
        :param authorization: The AuthorizationPolicy specifying the roles for the managed identity.
        :return The created managed identity name.
        """
        azure_managed_identity_manager = AzureManagedIdentityManager(self.get_subscription_id())

        # Create random managed identity name from a random 64 bit value
        account_name = secrets.choice(string.ascii_letters) + secrets.token_hex(8)

        # Create managed identity
        full_id = azure_managed_identity_manager.create_managed_identity(
            authorization=authorization,
            managed_identity_name=account_name
        )

        # Add roles to managed identity
        azure_managed_identity_manager.add_roles_to_managed_identity(
            authorization=authorization,
            managed_identity_name=account_name
        )

        return full_id