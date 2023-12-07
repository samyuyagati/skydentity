from skydentity.policies.managers.gcp_policy_manager import GCPPolicyManager
from skydentity.policies.managers.local_policy_manager import LocalPolicyManager
from skydentity.policies.checker.gcp_policy import GCPPolicy

import argparse
import os

def main():
    parser = argparse.ArgumentParser(description='Upload a policy to the cloud storage')
    parser.add_argument('--policy', type=str, help='Path to the policy file to upload')
    parser.add_argument('--cloud', type=str, help='Name of the cloud to upload to')
    parser.add_argument('--public-key', type=str, help='Public key corresponding to the broker')
    parser.add_argument('--credentials', type=str, help='Credentials of the cloud to upload to')
    args = parser.parse_args()

    formatted_cloud = args.cloud.lower().strip()

    cloud_policy_manager = None
    policy_type = None
    if formatted_cloud == 'gcp':
        cloud_policy_manager = GCPPolicyManager(credentials_path=args.credentials)
        policy_type = GCPPolicy
    else:
        raise Exception('Cloud not supported.')
    
    policy_dir = os.path.dirname(args.policy)
    local_policy_manager = LocalPolicyManager(policy_dir, policy_type)

    policy_name = os.path.basename(args.policy)
    read_from_local_policy = local_policy_manager.get_policy(policy_name)

    cloud_policy_manager.upload_policy(args.public_key, read_from_local_policy)
    print('Policy has been uploaded!')

if __name__ == "__main__":
    main()