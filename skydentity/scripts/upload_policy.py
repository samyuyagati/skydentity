import argparse
from typing import Type, Union

import firebase_admin
import requests
import yaml
from firebase_admin import credentials, firestore

from skydentity.policies.checker.authorization_policy import AuthorizationPolicy
from skydentity.policies.checker.azure_authorization_policy import (
    AzureAuthorizationPolicy,
)
from skydentity.policies.checker.azure_resource_policy import AzurePolicy
from skydentity.policies.checker.gcp_authorization_policy import GCPAuthorizationPolicy
from skydentity.policies.checker.gcp_resource_policy import GCPPolicy
from skydentity.policies.checker.gcp_storage_policy import GCPStoragePolicy
from skydentity.policies.checker.resource_policy import CloudPolicy
from skydentity.policies.managers.azure_policy_manager import AzurePolicyManager
from skydentity.policies.managers.gcp_policy_manager import GCPPolicyManager
from skydentity.policies.managers.gcp_storage_policy_manager import (
    GCPStoragePolicyManager,
)
from skydentity.policies.managers.local_policy_manager import LocalPolicyManager
from skydentity.policies.managers.policy_manager import PolicyManager
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

    cloud_policy_manager: PolicyManager
    policy_type: Union[Type[CloudPolicy], Type[AuthorizationPolicy]]

    if formatted_cloud not in ("gcp", "azure"):
        raise Exception("Cloud not supported.")

    with open(args.public_key_path, "r") as f:
        print("Public key:", f.read())

    hashed_public_key = hash_public_key_from_file(args.public_key_path)
    print("Hashed public key: ", hashed_public_key)

    if formatted_cloud == "gcp":
        if args.authorization:
            cloud_policy_manager = GCPPolicyManager(
                credentials_path=args.credentials,
                firestore_policy_collection="authorization_policies",
            )
            policy_type = GCPAuthorizationPolicy
        elif args.storage:
            cloud_policy_manager = GCPStoragePolicyManager(
                credentials_path=args.credentials
            )
            policy_type = GCPStoragePolicy
        else:
            cloud_policy_manager = GCPPolicyManager(credentials_path=args.credentials)
            policy_type = GCPPolicy
    elif formatted_cloud == "azure":
        if args.storage:
            cloud_policy_manager = AzurePolicyManager(
                db_info_file = args.credentials,
                db_container_name = 'storage_policies'
            )
            print("Uploading storage policy for Azure")
            with open(args.policy, "r") as f:
                policy_dict = yaml.load(f, Loader=yaml.SafeLoader)
                print(policy_dict)
                cloud_policy_manager.upload_policy_dict(hashed_public_key, policy_dict)
        else:
            policy_type = AzurePolicy if not args.authorization else AzureAuthorizationPolicy
            policy_container_name = "authorization_policies" if args.authorization else "policies"
            cloud_policy_manager = AzurePolicyManager(
                db_info_file = args.credentials,
                policy_type = policy_type,
                db_container_name = policy_container_name
            )
    else:
        raise Exception("Cloud not supported. Supported types are gcp and azure")

    if not args.storage:
        local_policy_manager = LocalPolicyManager(policy_type)
        read_from_local_policy = local_policy_manager.get_policy(args.policy)
        cloud_policy_manager.upload_policy(hashed_public_key, read_from_local_policy)


    if formatted_cloud == "gcp" and args.storage:
        # send request to initialize storage service accounts
        print("Initializing storage service accounts...")
        response = requests.post(
            "http://127.0.0.1:5000/skydentity/cloud/gcp/init-storage-authorization"
        )
        if not response.ok:
            print(response.status_code, "Error initializing storage authorization:", response.content)

    print("Policy has been uploaded!")


if __name__ == "__main__":
    main()
