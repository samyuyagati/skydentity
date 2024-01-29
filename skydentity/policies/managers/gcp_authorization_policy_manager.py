import firebase_admin

from base64 import b64encode, b64decode
from Crypto.Cipher import AES
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
        self._app = firebase_admin.initialize_app(self._cred, name='authorization_policy_manager')
        self._db = firestore.client()
        self._firestore_policy_collection = firestore_policy_collection
        with open(capability_enc_path, 'rb') as f:
            self._capability_enc = f.read()

    def get_policy_dict(self, public_key: str) -> CloudPolicy | None:
        """
        Gets a policy from the cloud vendor.
        :param public_key: The public key of the policy.
        :return: The policy.
        """
        print(self._firestore_policy_collection)
        print(public_key)
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
        header = b"" # No public information required; could later make this the public key of the broker if desired
        cipher.update(header)
        capability, tag = cipher.encrypt_and_digest(service_account_id.encode('utf-8'))
        dict_keys = ['nonce', 'header', 'ciphertext', 'tag']
        dict_values = [b64encode(x).decode('utf-8') for x in (cipher.nonce, header, capability, tag)]
        return dict(zip(dict_keys, dict_values))
    
    def check_capability(self, capability: dict) -> (str, bool):
        """
        Decrypts the capability and returns True, along with the service account id, if it is valid.
        """
        nonce = b64decode(capability['nonce'])
        header = b64decode(capability['header']) # If checking broker public key, check that the header matches the public key attached to the request
        ciphertext = b64decode(capability['ciphertext'])
        tag = b64decode(capability['tag'])
        cipher = AES.new(self._capability_enc, AES.MODE_GCM, nonce=nonce)
        cipher.update(header)
        try:
            candidate_service_account_id = cipher.decrypt_and_verify(ciphertext, tag)
            return (candidate_service_account_id.decode('utf-8'), True)
        except ValueError:
            print("Invalid capability: could not decrypt or verify")
            return (None, False)
        
    def create_service_account_with_roles(self, authorization_request) -> str:
        # TODO put actual service account creation here
        return "terraform@sky-identity.iam.gserviceaccount.com"