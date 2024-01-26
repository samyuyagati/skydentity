import argparse
import os
from google.oauth2 import service_account
import googleapiclient.discovery

class GCPServiceAccountManager:

    def __init__(self, credentials_path: str) -> None:
        """
        :param credentials_path: path to service account json
        """
        self._service_accounts = {}
        self._credentials = service_account.Credentials.from_service_account_file(
            filename=credentials_path,
            scopes=["https://www.googleapis.com/auth/cloud-platform"],
        )
        self._iam_service = googleapiclient.discovery.build("iam", "v1", credentials=self._credentials)
        self._cloudresourcemanager_service = googleapiclient.discovery.build("cloudresourcemanager", "v1", credentials=self._credentials)

    def create_service_account(self, project_id, service_account_name, display_name):
        # Create service account if it doesn't exist
        if service_account_name not in self._service_accounts:
            
            # Check if service account exists
            try:
                self._iam_service.projects().serviceAccounts().get(
                    name=f"projects/{project_id}/serviceAccounts/{service_account_name}@{project_id}.iam.gserviceaccount.com"
                ).execute()
                return
            except:
                # Now create service account

                self._service_accounts[service_account_name] = (
                    self._iam_service.projects()
                                    .serviceAccounts()
                                    .create(
                                        name=f"projects/{project_id}",
                                        body={
                                            "accountId": service_account_name,
                                            "serviceAccount": {
                                                "displayName": display_name
                                            }
                                        }
                                    ).execute()
                                    )
        
    def add_roles_to_service_account(self, project_id, service_account_name, roles):
        service_account = None
        if service_account_name in self._service_accounts:
            service_account = self._service_accounts[service_account_name]
        else:
            service_account = self._iam_service.projects().serviceAccounts().get(
                name=f"projects/{project_id}/serviceAccounts/{service_account_name}@{project_id}.iam.gserviceaccount.com"
            ).execute()
            self._service_accounts[service_account_name] = service_account

        # Get current policy to modify and add roles
        policy = (
            self._cloudresourcemanager_service.projects()
            .getIamPolicy(
                resource=project_id,
            )
            .execute()
        )

        # Add roles to service account
        role_set = set(roles)
        for binding in policy["bindings"]:
            if binding["role"] in role_set:
                binding["members"].append(f"serviceAccount:{service_account['email']}")
                role_set.remove(binding["role"])

        # Add roles that are not yet in the policy
        for role in role_set:
            policy["bindings"].append({
                "role": f'roles/{role}',
                "members": [
                    f"serviceAccount:{service_account['email']}"
                ]
            })

        self._cloudresourcemanager_service.projects().setIamPolicy(
            resource=project_id,
            body={
                "policy": policy
            }
        ).execute()
