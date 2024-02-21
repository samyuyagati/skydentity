import argparse
import os

from skydentity.policies.managers.local_policy_manager import LocalPolicyManager
from skydentity.policies.checker.gcp_resource_policy import GCPPolicy
from skydentity.policies.checker.gcp_authorization_policy import GCPAuthorizationPolicy
from skydentity.policies.managers.gcp_policy_manager import GCPPolicyManager

from skydentity.policies.checker.azure_resource_policy import AzurePolicy
from skydentity.policies.checker.azure_authorization_policy import AzureAuthorizationPolicy
from skydentity.policies.managers.azure_policy_manager import AzurePolicyManager 

def main():
    parser = argparse.ArgumentParser(description='Upload a policy to the cloud storage')
    parser.add_argument('--policy', type=str, help='Path to the policy file to upload')
    parser.add_argument('--authorization', action="store_true", help="Upload an authorization policy")
    parser.add_argument('--cloud', type=str, help='Name of the cloud to upload to')
    parser.add_argument('--public-key', type=str, help='Public key corresponding to the broker')
    parser.add_argument('--credentials', type=str, default=None, help='Credentials of the cloud to upload to')
    parser.add_argument('--db-endpoint', type=str, help='Endpoint of the Azure database (Required for azure)')
    args = parser.parse_args()

    formatted_cloud = args.cloud.lower().strip()

    cloud_policy_manager = None
    policy_type = None

    policy_container_name = 'policies' if not args.authorization else 'authorization_policies'
 
    if formatted_cloud == 'gcp':
        cloud_policy_manager = GCPPolicyManager(credentials_path=args.credentials, 
                                                firestore_policy_collection=policy_container_name)
        policy_type = GCPPolicy if not args.authorization else GCPAuthorizationPolicy
    elif formatted_cloud == 'azure':
        policy_type = AzurePolicy if not args.authorization else AzureAuthorizationPolicy
        cloud_policy_manager = AzurePolicyManager(
            db_endpoint = args.db_endpoint,
            db_key = args.credentials,
            policy_type = policy_type,
            db_container_name = policy_container_name
        )
    else:
        raise Exception('Cloud not supported. Supported types are gcp and azure')

    local_policy_manager = LocalPolicyManager(policy_type)
    read_from_local_policy = local_policy_manager.get_policy(args.policy)
    cloud_policy_manager.upload_policy(args.public_key, read_from_local_policy)
    print('Policy has been uploaded!')

if __name__ == "__main__":
    main()