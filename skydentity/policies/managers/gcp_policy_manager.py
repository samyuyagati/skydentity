import firebase_admin
import logging as py_logging
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
        py_logging.basicConfig(filename='gcp_policy_manager.log', level=py_logging.INFO)
        self._pylogger = py_logging.getLogger("GCPPolicyManager")
        self._cred = credentials.Certificate(credentials_path)
        try:
            self._app = firebase_admin.initialize_app(self._cred, name='policy_manager')
        except ValueError:
            self._app = firebase_admin.get_app('policy_manager')
        self._db = firestore.client(self._app)
        self._firestore_policy_collection = firestore_policy_collection

    def upload_policy(self, public_key: str, policy: GCPPolicy):
        """
        Uploads a policy to GCP.
        :param public_key: The public key of the policy.
        :param policy: The policy to upload.
        """
        self._pylogger.debug(f"Uploading policy:\n {policy.to_dict()}")
        self._db \
            .collection(self._firestore_policy_collection) \
            .document(public_key) \
            .set(policy.to_dict())

    def get_policy(self, public_key_hash: str, logger=None) -> GCPPolicy:
        """
        Gets a policy from the cloud vendor.
        :param public_key: The public key of the policy.
        :param logger: optional. google.cloud logger
        :return: The policy.
        """
        try:
            policy = GCPPolicy.from_dict(
                self._db \
                    .collection(self._firestore_policy_collection) \
                    .document(public_key_hash) \
                    .get() \
                    .to_dict(),
                logger
            )
            return policy
        except Exception as e:
            self._pylogger.debug(f"Failed to get policy from GCP, possibly due to invalid public key: {e}")
            return None
