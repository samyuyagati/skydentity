"""
Manager for cross-cloud resources global state, stored in GCP.
"""

from dataclasses import dataclass

import firebase_admin
from firebase_admin import credentials, firestore
from google.oauth2 import service_account


@dataclass
class CrossCloudGlobalState:
    # source cloud (which the VM resides in)
    cloud: str

    # unique VM ID (within the cloud)
    vm_id: str

    # public key associated with the VM
    vm_public_key: str

    # role of the VM
    vm_role: str

    # hash of the public key of orchestrator, used to identify the cross-cloud policy
    orchestrator_key_hash: str

    @staticmethod
    def from_dict(
        cloud: str, vm_id: str, state: dict[str, str]
    ) -> "CrossCloudGlobalState":
        assert (
            "vm_public_key" in state
        ), f"Invalid state for ({cloud}, {vm_id}); 'public_key' not found"
        assert (
            "vm_role" in state
        ), f"Invalid state for ({cloud}, {vm_id}); 'vm_role' not found"
        assert (
            "orchestrator_key_hash" in state
        ), f"Invalid state for ({cloud}, {vm_id}); 'orchestrator_key_hash' not found"

        return CrossCloudGlobalState(
            cloud=cloud,
            vm_id=vm_id,
            vm_public_key=state["vm_public_key"],
            vm_role=state["vm_role"],
            orchestrator_key_hash=state["orchestrator_key_hash"],
        )

    @dataclass
    class _CrossCloudGlobalStateExport:
        key: str
        value_dict: dict[str, str]

    @staticmethod
    def serialize_key(cloud: str, vm_id: str):
        return f"{cloud}; {vm_id}"

    def to_dict(self) -> "_CrossCloudGlobalStateExport":
        exported_key = self.serialize_key(self.cloud, self.vm_id)
        exported_value = {
            "vm_public_key": self.vm_public_key,
            "vm_role": self.vm_role,
            "orchestrator_key_hash": self.orchestrator_key_hash,
        }

        return CrossCloudGlobalState._CrossCloudGlobalStateExport(
            key=exported_key, value_dict=exported_value
        )


class GCPGlobalStateManager:
    def __init__(
        self,
        credentials_info: dict[str, str],
        firestore_policy_collection="crosscloud_global_state",
    ):
        """
        Initializes the GCP global state manager for cross-cloud policies.

        Credentials must be read and parsed for initialization.
        (This allows for the possibility of storing the credentials in memory, rather than in a file.)
        """
        self._credentials_info = credentials_info
        self._credentials = service_account.Credentials.from_service_account_info(
            credentials_info
        )

        # firestore
        try:
            self._app = firebase_admin.initialize_app(
                credentials.Certificate(credentials_info), name="global_state_manager"
            )
        except ValueError:
            self._app = firebase_admin.get_app(name="global_state_manager")

        self._db = firestore.client(self._app)
        self._firestore_policy_collection = firestore_policy_collection

    def fetch_state(self, cloud: str, vm_id: str) -> CrossCloudGlobalState:
        """
        Retrieves the global state for a particular VM, identified by (cloud, vm_id).
        """
        state_dict = (
            self._db.collection(self._firestore_policy_collection)
            .document(CrossCloudGlobalState.serialize_key(cloud, vm_id))
            .get(timeout=10)
            .to_dict()
        )

        return CrossCloudGlobalState.from_dict(cloud, vm_id, state_dict)

    def update_state(self, state: CrossCloudGlobalState):
        """
        Updates the global state for a particular VM, identified by (cloud, vm_id),
        retrieved from the state dataclass.
        """
        export_obj = state.to_dict()

        self._db.collection(self._firestore_policy_collection).document(
            export_obj.key
        ).set(export_obj.value_dict)
