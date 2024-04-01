# Modified from gcloud example https://cloud.google.com/storage/docs/access-control/signing-urls-with-helpers#client-libraries_1
import datetime

from google.cloud import storage

def get_credentials_from_service_account_key(key_file: str) -> service_account.Credentials:
    return service_account.Credentials.from_service_account_file(
        key_file)


def generate_upload_signed_url_v4(bucket_name: str, blob_name: str, key_file: str):
    """Generates a v4 signed URL for uploading a blob using HTTP PUT.

    Note that this method requires a service account key file. You can not use
    this if you are using Application Default Credentials from Google Compute
    Engine or from the Google Cloud SDK.
    """

    storage_client = storage.Client(credentials=get_credentials_from_service_account_key(key_file))
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(blob_name)

    url = blob.generate_signed_url(
        version="v4",
        # This URL is valid for 15 minutes
        expiration=datetime.timedelta(minutes=15),
        # Allow PUT requests using this URL.
        method="PUT",
        content_type="application/octet-stream",
    )

    print("Generated PUT signed URL:")
    print(url)
    print("You can use this URL with any user agent, for example:")
    print(
        "curl -X PUT -H 'Content-Type: application/octet-stream' "
        "--upload-file my-file '{}'".format(url)
    )
    return url

generate_upload_signed_url_v4("test_bucket_signedurl", "blob1", "/Users/samyu/.cloud_creds/gcp/sky-identity-ac2febc1b9b3.json")
