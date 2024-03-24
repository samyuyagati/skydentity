import argparse

import firebase_admin
import yaml
from firebase_admin import credentials, firestore

from skydentity.policies.checker.azure_authorization_policy import (
    AzureAuthorizationPolicy,
)
from skydentity.policies.checker.azure_resource_policy import AzurePolicy
from skydentity.policies.checker.gcp_authorization_policy import GCPAuthorizationPolicy
from skydentity.policies.checker.gcp_resource_policy import GCPPolicy
from skydentity.policies.checker.gcp_storage_policy import GCPStoragePolicy
from skydentity.policies.managers.azure_policy_manager import AzurePolicyManager
from skydentity.policies.managers.gcp_policy_manager import GCPPolicyManager
from skydentity.policies.managers.gcp_storage_policy_manager import (
    GCPStoragePolicyManager,
)
from skydentity.policies.managers.local_policy_manager import LocalPolicyManager
from skydentity.utils.hash_util import hash_public_key_from_file


def main():
    parser = argparse.ArgumentParser(description="Upload a policy to the cloud storage")
    parser.add_argument("--policy", type=str, help="Path to the policy file to upload")
    parser.add_argument("--cloud", type=str, help="Name of the cloud to upload to")
    parser.add_argument(
        "--public-key-path",
        type=str,
        help="Path to public key pem file corresponding to the broker",
    )
    parser.add_argument(
        "--credentials", type=str, help="Credentials of the cloud to upload to"
    )

    # group to specify policy type; mutually exclusive
    policy_type_group = parser.add_mutually_exclusive_group()
    policy_type_group.add_argument(
        "--authorization", action="store_true", help="Upload an authorization policy"
    )
    policy_type_group.add_argument(
        "--storage", action="store_true", help="Upload a storage policy"
    )

    args = parser.parse_args()

    formatted_cloud = args.cloud.lower().strip()

    cloud_policy_manager = None
    policy_type = None

    if formatted_cloud not in ("gcp", "azure"):
        raise Exception("Cloud not supported.")

    with open(args.public_key_path, "r") as f:
        print("Public key:", f.read())

    hashed_public_key = hash_public_key_from_file(args.public_key_path)
    print("Hashed public key: ", hashed_public_key)

    if formatted_cloud == "gcp":
        cloud_policy_manager: GCPPolicyManager
        if args.authorization:
            cloud_policy_manager = GCPPolicyManager(
                credentials_path=args.credentials,
                firestore_policy_collection="authorization_policies",
            )
            policy_type = GCPAuthorizationPolicy
        elif args.storage:
            # TODO: replace with abstracted classes
            creds = credentials.Certificate(args.credentials)
            app = firebase_admin.initialize_app(creds)
            db = firestore.client()
            with open(args.policy, "r") as f:
                policy_dict = yaml.load(f, Loader=yaml.SafeLoader)
                print(policy_dict)
                db.collection("storage_policies").document(hashed_public_key).set(
                    policy_dict
                )
                cloud_policy_manager = GCPStoragePolicyManager(
                    credentials_path=args.credentials
                )
            print("Policy has been uploaded!")
            return
        else:
            cloud_policy_manager = GCPPolicyManager(credentials_path=args.credentials)
            policy_type = GCPPolicy
    elif formatted_cloud == "azure":
        policy_container_name = (
            "policies" if not args.authorization else "authorization_policies"
        )
        policy_type = (
            AzurePolicy if not args.authorization else AzureAuthorizationPolicy
        )
        cloud_policy_manager = AzurePolicyManager(
            db_info_file=args.credentials,
            policy_type=policy_type,
            db_container_name=policy_container_name,
        )
    else:
        raise Exception("Cloud not supported. Supported types are gcp and azure")

    local_policy_manager = LocalPolicyManager(policy_type)
    read_from_local_policy = local_policy_manager.get_policy(args.policy)
    cloud_policy_manager.upload_policy(hashed_public_key, read_from_local_policy)
    print("Policy has been uploaded!")


if __name__ == "__main__":
    main()
