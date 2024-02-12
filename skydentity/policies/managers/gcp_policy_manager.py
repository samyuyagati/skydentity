import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore

from skydentity.policies.managers.policy_manager import PolicyManager
from skydentity.policies.checker.gcp_resource_policy import GCPPolicy

class GCPPolicyManager(PolicyManager):
    """
    A policy manager for GCP.
    """

    def __init__(self, 
                 credentials_path: str,
                 firestore_policy_collection: str = 'policies'):
        """
        Initializes the GCP policy manager.
        :param credentials_path: The path to the credentials file.
        """
        self._cred = credentials.Certificate(credentials_path)
        self._app = firebase_admin.initialize_app(self._cred)
        self._db = firestore.client()
        self._firestore_policy_collection = firestore_policy_collection

    def upload_policy(self, public_key: str, policy: GCPPolicy):
        """
        Uploads a policy to GCP.
        :param public_key: The public key of the policy.
        :param policy: The policy to upload.
        """
        print("Uploading policy:\n", policy.to_dict())
        self._db \
            .collection(self._firestore_policy_collection) \
            .document(public_key) \
            .set(policy.to_dict())

    def get_policy(self, public_key: str, logger=None) -> GCPPolicy:
        """
        Gets a policy from the cloud vendor.
        :param public_key: The public key of the policy.
        :param logger: optional. google.cloud logger
        :return: The policy.
        """
        return GCPPolicy.from_dict(
            self._db \
                .collection(self._firestore_policy_collection) \
                .document(public_key) \
                .get() \
                .to_dict(),
            logger
        )
