import firebase_admin
from firebase_admin import credentials, firestore

from skydentity.policies.checker.crosscloud_resources.crosscloud_resource_policy import (
    CrossCloudPolicy,
)


class CrossCloudPolicyManager:
    def __init__(
        self,
        creds: str | dict,
        firestore_policy_collection: str = "crosscloud_resource_policies",
    ):
        """
        Initializes the cross-cloud policy manager.

        Requires either a path to the credentials file, or the contents of the credentials file.
        """
        self._credentials = credentials.Certificate(creds)

        try:
            self._app = firebase_admin.initialize_app(
                self._credentials, name="crosscloud_policy_manager"
            )
        except ValueError:
            self._app = firebase_admin.get_app(name="crosscloud_policy_manager")

        self._db = firestore.client(self._app)
        self._firestore_policy_collection = firestore_policy_collection

    def get_policy_dict(self, public_key_hash: str) -> dict:
        """
        Retrieves the crosscloud policy associated with the given public key hash (of the orchestrator).
        """

        policy = (
            self._db.collection(self._firestore_policy_collection)
            .document(public_key_hash)
            .get(timeout=10)
            .to_dict()
        )
        assert policy is not None, "Failed to fetch cross-cloud policy"

        return policy

    def upload_policy(self, public_key_hash: str, policy: CrossCloudPolicy):
        """
        Uploads a crosscloud policy associated with the given public key hash (of the orchestrator).
        """

        policy_dict = policy.to_dict()
        self._db.collection(self._firestore_policy_collection).document(
            public_key_hash
        ).set(policy_dict)
