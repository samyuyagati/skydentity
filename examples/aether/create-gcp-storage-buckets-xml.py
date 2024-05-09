import argparse

from google.oauth2 import service_account
from googleapiclient import discovery

# Set up argument parsing with argparse
parser = argparse.ArgumentParser()
parser.add_argument("--credentials", type=str, help="Path to credentials file")
parser.add_argument("--project", type=str, help="Project name")
parser.add_argument("--name", type=str, help="Bucket name")
args = parser.parse_args()

credentials = service_account.Credentials.from_service_account_file(
        filename=args.credentials
    )
storage_service = discovery.build(
        "storage", "v1", credentials=credentials, cache_discovery=False
    )

try:
    storage_service.buckets().insert(
        project=args.project,
        body={
            "name": args.name,
            "iamConfiguration": {"bucketPolicyOnly": {"enabled": True}},
        },
    ).execute()
    print(f"Created bucket {args.name}")
except Exception as e:
    print(f"Failed to create {args.name}: {e}")