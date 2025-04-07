import argparse
import json
import os

from google.oauth2 import service_account  
from google.cloud import storage
import googleapiclient.discovery


parser = argparse.ArgumentParser()
parser.add_argument('-p', '--project-id', type=str, 
                    help='your GCP project ID string')
parser.add_argument('-n', '--service-acct-name', type=str, 
                    help='desired service account name (recommended: set to broker service name)')
parser.add_argument('-b', '--bucket-name', type=str,
                    help='name of GCP cloud storage bucket to give service account access to')
parser.add_argument('-c', '--credentials', type=str,
                    help='path to service account json')
parser.add_argument('--service-acct-credentials', type=str,
                    help='path to store new service account credentials')
 
''' Adapted from GCP docs '''

def get_service_account_credentials(path: str) -> service_account.Credentials:
    return service_account.Credentials.from_service_account_file(
        path)

''' Required application default credentials to be set up (user has to authenticate with gcloud auth) '''
def create_service_account(project_id: str, name: str, display_name: str, credentials) -> dict:
    """Creates a service account."""

#    credentials = service_account.Credentials.from_service_account_file(
#        filename=os.environ["GOOGLE_APPLICATION_CREDENTIALS"],
#        scopes=["https://www.googleapis.com/auth/cloud-platform"],
#    )

    service = googleapiclient.discovery.build("iam", "v1", credentials=credentials)

    my_service_account = (
        service.projects()
        .serviceAccounts()
        .create(
            name="projects/" + project_id,
            body={"accountId": name, "serviceAccount": {"displayName": display_name, "description": "[skydentity] Automatically generated service account"}},
        )
        .execute()
    )

    print("Created service account: " + my_service_account["email"])
    return my_service_account

def create_key(service_account_email: str, credentials, key_path: str) -> None:
    """Creates a key for a service account; auth using ADC."""

#    credentials = service_account.Credentials.from_service_account_file(
#        filename=os.environ["GOOGLE_APPLICATION_CREDENTIALS"],
#        scopes=["https://www.googleapis.com/auth/cloud-platform"],
#    )

    service = googleapiclient.discovery.build("iam", "v1", credentials=credentials)

    key = (
        service.projects()
        .serviceAccounts()
        .keys()
        .create(name="projects/-/serviceAccounts/" + service_account_email, body={})
        .execute()
    )

    # The privateKeyData field contains the base64-encoded service account key
    # in JSON format.
    # TODO(Developer): Save the below key {json_key_file} to a secure location.
    #  You cannot download it again later.
    import base64
    json_key_file = base64.b64decode(key['privateKeyData']).decode('utf-8')
    json_object = json.dumps(json_key_file, indent=4)
    with open("key_path", "w") as outfile:
        outfile.write(json_object)

    if not key["disabled"]:
        print("Created json key")

def get_policy(project_id: str, version: int = 1) -> dict:
    """Gets IAM policy for a project."""

#    credentials = service_account.Credentials.from_service_account_file(
#        filename=os.environ["GOOGLE_APPLICATION_CREDENTIALS"],
#        scopes=["https://www.googleapis.com/auth/cloud-platform"],
#    )
    service = googleapiclient.discovery.build(
        "cloudresourcemanager", "v1" #, credentials=credentials
    )
    policy = (
        service.projects()
        .getIamPolicy(
            resource=project_id,
            body={"options": {"requestedPolicyVersion": version}},
        )
        .execute()
    )
    print(policy)
    return policy

''' Use to grant a role that is not yet included in the allow policy, add a new role binding '''
def modify_policy_add_role(policy: dict, role: str, member: str) -> dict:
    """Adds a new role binding to a policy."""

    binding = {"role": role, "members": [member]}
    policy["bindings"].append(binding)
    print(policy)
    return policy

''' Should be used only after calling get policy and modifying that result '''
def set_policy(project_id: str, policy: dict) -> dict:
    """Sets IAM policy for a project."""

    credentials = service_account.Credentials.from_service_account_file(
        filename=os.environ["GOOGLE_APPLICATION_CREDENTIALS"],
        scopes=["https://www.googleapis.com/auth/cloud-platform"],
    )
    service = googleapiclient.discovery.build(
        "cloudresourcemanager", "v1", credentials=credentials
    )

    policy = (
        service.projects()
        .setIamPolicy(resource=project_id, body={"policy": policy})
        .execute()
    )
    print(policy)
    return policy

def list_service_accounts(project_id: str) -> dict:
    """Lists all service accounts for the current project."""

    credentials = service_account.Credentials.from_service_account_file(
        filename=os.environ["GOOGLE_APPLICATION_CREDENTIALS"],
        scopes=["https://www.googleapis.com/auth/cloud-platform"],
    )

    service = googleapiclient.discovery.build("iam", "v1", credentials=credentials)

    service_accounts = (
        service.projects()
        .serviceAccounts()
        .list(name="projects/" + project_id)
        .execute()
    )

    for account in service_accounts["accounts"]:
        print("Name: " + account["name"])
        print("Email: " + account["email"])
        print(" ")
    return service_accounts

def allow_bucket_read(project_id: str, bucket_name: str, service_acct_email: str, credential_path):
    credentials = get_service_account_credentials(credential_path)

    permissions = {"object": ["storage.objects.get", "storage.objects.list"]}

    # Add the service account to the bucket's ACL 
    client = storage.Client(project=project_id, credentials=credentials)
    bucket = client.get_bucket(bucket_name)
    bucket.acl.user(service_acct_email).grant_permissions(permissions)

''' For testing: create a bucket '''
def create_bucket_class_location(project_id: str, bucket_name: str):
    """
    Create a new bucket in the US region with the coldline storage
    class
    """
    storage_client = storage.Client(project=project_id)

    bucket = storage_client.bucket(bucket_name)
    bucket.storage_class = "COLDLINE"
    new_bucket = storage_client.create_bucket(bucket, location="us")

    print(
        "Created bucket {} in {} with storage class {}".format(
            new_bucket.name, new_bucket.location, new_bucket.storage_class
        )
    )
    return new_bucket


def main():
    args = parser.parse_args()
#    print("Creating bucket", args.bucket_name)
#    create_bucket_class_location(args.project_id, args.bucket_name)

    # Get user service account creds
    user_credentials = get_service_account_credentials(args.credentials) 

    # Create a new service account for the VM
    print("Creating service account", args.service_acct_name)
    service_account = create_service_account(args.project_id, args.service_acct_name, args.service_acct_name, user_credentials)
    email = service_account["email"]
    print("Creating service account key")
    create_key(email, user_credentials, args.service_acct_credentials)

    print("Allowing read access to", args.bucket_name)
    allow_bucket_read(args.project_id, args.bucket_name, email, user_credentials)

if __name__ == "__main__":
    main()
