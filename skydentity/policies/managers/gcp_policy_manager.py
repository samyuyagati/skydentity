import logging as py_logging

from datetime import datetime
import firebase_admin
from firebase_admin import credentials, firestore

from skydentity.policies.checker.gcp_resource_policy import GCPPolicy
from skydentity.policies.managers.policy_manager import PolicyManager
from skydentity.utils.log_util import build_file_handler

LOGGER = py_logging.getLogger("policies.managers.gcp_policy_manager")
LOGGER.addHandler(build_file_handler("gcp_policy_manager.log"))


class GCPPolicyManager(PolicyManager):
    """
    A policy manager for GCP.
    """

    def __init__(
        self, credentials_path: str, firestore_policy_collection: str = "policies"
    ):
        """
        Initializes the GCP policy manager.
        :param credentials_path: The path to the credentials file.
        """
        self._cred = credentials.Certificate(credentials_path)
        try:
            self._app = firebase_admin.initialize_app(self._cred, name="policy_manager")
        except ValueError:
            self._app = firebase_admin.get_app("policy_manager")
        self._db = firestore.client(self._app)
        self._firestore_policy_collection = firestore_policy_collection
        self._policies = {}
        self._policies_last_read = None

    def upload_policy(self, public_key_hash: str, policy: GCPPolicy):
        """
        Uploads a policy to GCP.
        :param public_key_hash: The public key of the policy.
        :param policy: The policy to upload.
        """
        LOGGER.debug(f"Uploading policy:\n {policy.to_dict()}")
        self._db.collection(self._firestore_policy_collection).document(
            public_key_hash
        ).set(policy.to_dict())

    def get_policy(self, public_key_hash: str) -> GCPPolicy:
        """
        Gets a policy from the cloud vendor.
        :param public_key: The public key of the policy.
        :return: The policy.
        """
        # Cache already-read policies for 30 seconds
        if public_key_hash in self._policies and (datetime.now() - self._policies_last_read).total_seconds() < 30.0:
            return self._policies[public_key_hash]
        try:
            policy = GCPPolicy.from_dict(
                self._db.collection(self._firestore_policy_collection)
                .document(public_key_hash)
                .get()
                .to_dict()
            )
            self._policies[public_key_hash] = policy
            self._policies_last_read = datetime.now()
            return policy
        except Exception as e:
            LOGGER.warning(
                f"Failed to get policy from GCP, possibly due to invalid public key: {e}"
            )
            return None
