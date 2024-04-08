"""
Create GCP buckets for use in concurrency testing.
"""

import logging
import time

from google.oauth2 import service_account
from googleapiclient import discovery

logging.getLogger().setLevel(logging.DEBUG)

BUCKET_NAME_PREFIX = "skydentity-test-storage"


def main(credentials_path: str, num_buckets: int, project: str):
    credentials = service_account.Credentials.from_service_account_file(
        filename=credentials_path
    )
    storage_service = discovery.build(
        "storage", "v1", credentials=credentials, cache_discovery=False
    )

    for i in range(1, num_buckets + 1):
        bucket_name = f"{BUCKET_NAME_PREFIX}-{i}"
        logging.info(f"Creating bucket {bucket_name}")
        try:
            storage_service.buckets().insert(
                project=project,
                body={
                    "name": bucket_name,
                    "iamConfiguration": {"bucketPolicyOnly": {"enabled": True}},
                },
            ).execute()
            logging.info(f"Created bucket {bucket_name}")

        except Exception as e:
            logging.exception(f"Failed to create {bucket_name}", exc_info=e)

        # wait to prevent timeouts
        time.sleep(5)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()

    parser.add_argument("--credentials", type=str, help="Path to credentials file")
    parser.add_argument(
        "-n", "--num-buckets", type=int, help="Number of buckets to create"
    )
    parser.add_argument(
        "-p", "--project", type=str, default="sky-identity", help="GCP project id"
    )

    args = parser.parse_args()
    main(
        credentials_path=args.credentials,
        num_buckets=args.num_buckets,
        project=args.project,
    )
