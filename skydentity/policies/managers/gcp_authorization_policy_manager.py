import firebase_admin

from firebase_admin import credentials
from firebase_admin import firestore

from skydentity.policies.checker.resource_policy import CloudPolicy
from skydentity.policies.iam.gcp_service_account_manager import GCPServiceAccountManager
from skydentity.policies.managers.policy_manager import PolicyManager

class GCPAuthorizationPolicyManager(PolicyManager):
    def __init__(self, 
                 credentials_path: str,
                 capability_enc_path: str,
                 firestore_policy_collection: str = 'authorization_policies'):
        """
        Initializes the GCP policy manager.
        :param credentials_path: The path to the credentials file.
        """
        self._cred = credentials.Certificate(credentials_path)
        self._app = firebase_admin.initialize_app(self._cred)
        self._db = firestore.client()
        self._firestore_policy_collection = firestore_policy_collection
        with open(capability_enc_path, 'r') as f:
            self._capability_enc = f.read()

    def get_policy_dict(self, public_key: str) -> CloudPolicy | None:
        """
        Gets a policy from the cloud vendor.
        :param public_key: The public key of the policy.
        :return: The policy.
        """
        return self._db \
            .collection(self._firestore_policy_collection) \
            .document(public_key) \
            .get() \
            .to_dict()

    def generate_capability(self, service_account_id: str) -> dict:
        """
        Encrypts the service account identifier with AES-GCM and returns it as a capability.
        """
        cipher = AES.new(self._capability_enc, AES.MODE_GCM)
        capability, tag = cipher.encrypt_and_digest(service_account_id.encode('utf-8'))
        dict_keys = ['nonce', 'header', 'ciphertext', 'tag']
        dict_values = [b64encode(x).decode('utf-8') for x in (cipher.nonce, cipher.header, capability, tag)]
        return dict(zip(dict_keys, dict_values))