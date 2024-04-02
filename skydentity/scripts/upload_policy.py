import argparse
import os
import yaml

import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore

from skydentity.policies.managers.gcp_policy_manager import GCPPolicyManager
from skydentity.policies.managers.local_policy_manager import LocalPolicyManager
from skydentity.policies.checker.gcp_resource_policy import GCPPolicy
from skydentity.utils.hash_util import hash_public_key_from_file

def main():
    parser = argparse.ArgumentParser(description='Upload a policy to the cloud storage')
    parser.add_argument('--policy', type=str, help='Path to the policy file to upload')
    parser.add_argument('--authorization', action="store_true", help="Upload an authorization policy")
    parser.add_argument('--cloud', type=str, help='Name of the cloud to upload to')
    parser.add_argument('--public-key-path', type=str, help='Path to public key pem file corresponding to the broker')
    parser.add_argument('--credentials', type=str, help='Credentials of the cloud to upload to')
    args = parser.parse_args()

    formatted_cloud = args.cloud.lower().strip()

    cloud_policy_manager = None
    policy_type = None

    if formatted_cloud != 'gcp':
        raise Exception('Cloud not supported.')

    with open(args.public_key_path, 'r') as f:
        print("Public key:", f.read()) 
    hashed_public_key = hash_public_key_from_file(args.public_key_path)
    print("Hashed public key: ", hashed_public_key)

    # Resource policy
    if not args.authorization:
        cloud_policy_manager = GCPPolicyManager(credentials_path=args.credentials)
        policy_type = GCPPolicy   
 
        policy_dir = os.path.dirname(args.policy)
        local_policy_manager = LocalPolicyManager(policy_dir, policy_type)

        policy_name = os.path.basename(args.policy)
        read_from_local_policy = local_policy_manager.get_policy(policy_name)
        cloud_policy_manager.upload_policy(hashed_public_key, read_from_local_policy)
        print ("Policy has been uploaded!")
        return
    
    # Authorization policy
    creds = credentials.Certificate(args.credentials)
    try:
        app = firebase_admin.initialize_app(creds)
    except ValueError:
        app = firebase_admin.get_app('[DEFAULT]')
    db = firestore.client()
    with open(args.policy, 'r') as f:
        policy_dict = yaml.load(f, Loader=yaml.SafeLoader)
        print(policy_dict)
        db \
            .collection("authorization_policies") \
            .document(hashed_public_key) \
            .set(policy_dict)

    print('Policy has been uploaded!')

if __name__ == "__main__":
    main()