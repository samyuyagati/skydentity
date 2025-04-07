import argparse
from pprint import pprint
from typing import cast

from skydentity.policies.checker.crosscloud_resources.clouds.gcp.gcp_permission import (
    GCPPermission,
)
from skydentity.policies.checker.crosscloud_resources.crosscloud_resource_policy import (
    CrossCloudPolicy,
)
from skydentity.policies.iam.gcp_crosscloud_service_account_manager import (
    GCPCrossCloudServiceAccountManager,
)
from skydentity.policies.managers.crosscloud_policy_manager import (
    CrossCloudPolicyManager,
)
from skydentity.utils.hash_util import hash_public_key_from_file

DESCRIPTION = """
Upload a cross-cloud resource policy to cloud storage.

This script also updates access control policies in each cloud environment that is included in the policy,
so credentials for each of these clouds must also be provided.
"""


def main():
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument(
        "--policy", type=str, required=True, help="Path to the policy file to upload"
    )
    parser.add_argument(
        "--public-key-path",
        type=str,
        help="Path to the public key of the orchestrator",
    )

    parser.add_argument(
        "--gcp-credentials",
        type=str,
        help="Path to credentials for GCP",
    )
    parser.add_argument(
        "--global-state-credentials",
        type=str,
        help="Path to credentials for the global state (i.e. in GCP)",
    )

    args = parser.parse_args()

    cross_cloud_policy = CrossCloudPolicy(policy_file=args.policy)
    print(cross_cloud_policy.policy)

    cross_cloud_service_account_manager = GCPCrossCloudServiceAccountManager(
        args.gcp_credentials
    )

    for role in cross_cloud_policy.policy:
        for cloud_obj in role.clouds:
            if cloud_obj.cloud == "gcp":
                service_account_email = (
                    cross_cloud_service_account_manager.create_account_with_permissions(
                        cast(list[GCPPermission.Permission], cloud_obj.permissions)
                    )
                )

                # save the service account email
                cloud_obj.access_identity = service_account_email

    pprint(cross_cloud_policy.policy)

    # upload policy to global state
    policy_manager = CrossCloudPolicyManager(args.global_state_credentials)
    public_key_hash = hash_public_key_from_file(args.public_key_path)
    policy_manager.upload_policy(public_key_hash, cross_cloud_policy)


if __name__ == "__main__":
    main()
