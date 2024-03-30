import argparse
import yaml

from skydentity.policies.managers.local_policy_manager import LocalPolicyManager
from skydentity.policies.checker.gcp_resource_policy import GCPPolicy
from skydentity.policies.checker.gcp_authorization_policy import GCPAuthorizationPolicy
from skydentity.policies.managers.gcp_policy_manager import GCPPolicyManager

from skydentity.policies.checker.azure_resource_policy import AzurePolicy
from skydentity.policies.checker.azure_authorization_policy import AzureAuthorizationPolicy
from skydentity.policies.managers.azure_policy_manager import AzurePolicyManager 

from skydentity.utils.hash_util import hash_public_key_from_file

def main():
    parser = argparse.ArgumentParser(description='Upload a policy to the cloud storage')
    parser.add_argument('--policy', type=str, help='Path to the policy file to upload')
    parser.add_argument('--cloud', type=str, help='Name of the cloud to upload to')
    parser.add_argument('--public-key-path', type=str, help='Path to public key pem file corresponding to the broker')
    parser.add_argument('--credentials', type=str, help='Credentials of the cloud to upload to')
    
    policy_type_group = parser.add_mutually_exclusive_group()
    policy_type_group.add_argument(
        '--authorization', action="store_true", help="Upload an authorization policy"
    )
    policy_type_group.add_argument(
        "--storage", action="store_true", help="Upload a storage policy"
    )

    args = parser.parse_args()

    formatted_cloud = args.cloud.lower().strip()

    cloud_policy_manager = None
    policy_type = None

    policy_container_name = 'policies'
    if args.authorization:
        policy_container_name = 'authorization_policies'
    elif args.storage:
        policy_container_name = 'storage_policies'
 
    hashed_public_key = hash_public_key_from_file(args.public_key_path)
    print("Hashed public key: ", hashed_public_key)

    if formatted_cloud == 'gcp':
        cloud_policy_manager = GCPPolicyManager(credentials_path=args.credentials, 
                                                firestore_policy_collection=policy_container_name)
        policy_type = GCPPolicy if not args.authorization else GCPAuthorizationPolicy
    elif formatted_cloud == 'azure':
        if args.storage:
            cloud_policy_manager = AzurePolicyManager(
                db_info_file = args.credentials,
                db_container_name = policy_container_name
            )
            print("Uploading storage policy for Azure")
            with open(args.policy, "r") as f:
                policy_dict = yaml.load(f, Loader=yaml.SafeLoader)
                print(policy_dict)
                cloud_policy_manager.upload_policy_dict(hashed_public_key, policy_dict)
        else:
            policy_type = AzurePolicy if not args.authorization else AzureAuthorizationPolicy
            cloud_policy_manager = AzurePolicyManager(
                db_info_file = args.credentials,
                policy_type = policy_type,
                db_container_name = policy_container_name
            )
    else:
        raise Exception('Cloud not supported. Supported types are gcp and azure')

    if not args.storage:
        local_policy_manager = LocalPolicyManager(policy_type)
        read_from_local_policy = local_policy_manager.get_policy(args.policy)
        cloud_policy_manager.upload_policy(hashed_public_key, read_from_local_policy)
        print('Policy has been uploaded!')

if __name__ == "__main__":
    main()