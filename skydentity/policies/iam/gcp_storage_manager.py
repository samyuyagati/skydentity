from google.oauth2 import service_account
from googleapiclient import discovery


class GCPStorageManager:

    def __init__(self, credentials_path: str) -> None:
        """
        :param credentials_path: path to service account json
        """

        self._credentials = service_account.Credentials.from_service_account_file(
            filename=credentials_path,
            scopes=["https://www.googleapis.com/auth/cloud-platform"],
        )
        self._storage_service = discovery.build(
            "storage", "v1", credentials=self._credentials
        )
        self._cloudresourcemanager_service = discovery.build(
            "cloudresourcemanager", "v3", credentials=self._credentials
        )

    def get_project_id_from_bucket_name(self, bucket: str) -> str:
        """
        Retrieve the project ID from the given bucket name.

        :param bucket: bucket name
        """

        bucket_metadata = self._storage_service.buckets().get(bucket=bucket).execute()
        bucket_proj_number = bucket_metadata["projectNumber"]
        project_metadata = self._cloudresourcemanager_service.projects().get(name=f"projects/{bucket_proj_number}").execute()

        return project_metadata["projectId"]
