import argparse
import os
import yaml

import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore

from skydentity.policies.managers.gcp_policy_manager import GCPPolicyManager
from skydentity.policies.managers.local_policy_manager import LocalPolicyManager
from skydentity.policies.checker.gcp_resource_policy import GCPPolicy

def main():
    parser = argparse.ArgumentParser(description='Upload a policy to the cloud storage')
    parser.add_argument('--policy', type=str, help='Path to the policy file to upload')
    parser.add_argument('--authorization', action="store_true", help="Upload an authorization policy")
    parser.add_argument('--cloud', type=str, help='Name of the cloud to upload to')
    parser.add_argument('--public-key', type=str, help='Public key corresponding to the broker')
    parser.add_argument('--credentials', type=str, help='Credentials of the cloud to upload to')
    args = parser.parse_args()

    formatted_cloud = args.cloud.lower().strip()

    cloud_policy_manager = None
    policy_type = None

    if formatted_cloud != 'gcp':
        raise Exception('Cloud not supported.')

    # Resource policy
    if not args.authorization:
        cloud_policy_manager = GCPPolicyManager(credentials_path=args.credentials)
        policy_type = GCPPolicy   
 
        policy_dir = os.path.dirname(args.policy)
        local_policy_manager = LocalPolicyManager(policy_dir, policy_type)

        policy_name = os.path.basename(args.policy)
        read_from_local_policy = local_policy_manager.get_policy(policy_name)
        cloud_policy_manager.upload_policy(args.public_key, read_from_local_policy)
        print ("Policy has been uploaded!")
        return
    
    # Authorization policy
    creds = credentials.Certificate(args.credentials)
    app = firebase_admin.initialize_app(creds)
    db = firestore.client()
    with open(args.policy, 'r') as f:
        policy_dict = yaml.load(f, Loader=yaml.SafeLoader)
        print(policy_dict)
        db \
            .collection("authorization_policies") \
            .document(args.public_key) \
            .set(policy_dict)

    print('Policy has been uploaded!')

if __name__ == "__main__":
    main()