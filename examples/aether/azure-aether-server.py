"""
Clone of https://github.com/romilbhardwaj/aether

Modified to only upload to Azure, with other configuration options.
"""

import logging
import os
import random
import socket
import string
import tempfile

from flask import Flask, request, send_file
from azure.storage.blob import BlobServiceClient

LOGGER = logging.getLogger()
# logging.basicConfig(filename='aether_azure.log',
#                     filemode='a',
#                     format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
#                     datefmt='%H:%M:%S',
#                     level=logging.INFO)

app = Flask(__name__)

# Aether configuration
AETHER_PORT = int(os.environ.get("AETHER_PORT", 9999))

# Configure your GCS and Azure storage credentials and bucket/container names
# Read configuration from environment variables
AZURE_CONNECTION_STRING = os.environ.get('AZURE_CONNECTION_STRING')
AZURE_CONTAINER_NAME = os.environ.get('AZURE_CONTAINER_NAME')
CHUNK_SIZE_MB = int(os.environ.get("CHUNK_SIZE", 1))  # default chunk size is 1MB

# Verify that all required environment variables are set
if not AZURE_CONNECTION_STRING or not AZURE_CONTAINER_NAME:
    raise EnvironmentError(
        "Missing required environment variables. Please ensure AZURE_CONNECTION_STRING and AZURE_CONTAINER_NAME is set."
    )

# Initialize GCS and Azure clients
endpoint = os.environ.get("CLOUDSDK_API_ENDPOINT_OVERRIDES_COMPUTE", None)
LOGGER.debug("endpoint:", endpoint)

azure_blob_service_client = BlobServiceClient.from_connection_string(
    AZURE_CONNECTION_STRING,
) if not endpoint else BlobServiceClient(endpoint)


# extend default socket timeout
REQUEST_TIMEOUT = 300
socket.setdefaulttimeout(REQUEST_TIMEOUT)


# Function to split file into chunks
def split_file(file, chunk_size=CHUNK_SIZE_MB * (2**20)):
    while True:
        chunk = file.read(chunk_size)
        if not chunk:
            break
        yield chunk


def generate_file_id():
    # Generates a 5-character unique file ID
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=5))

# ctr = 0
# import time

@app.route("/upload", methods=["POST"])
def upload():
    # global ctr
    file = request.files["file"]
    file_id = generate_file_id()  # Generate or obtain a unique ID for the file
    chunk_index = 0

    for chunk in split_file(file):
        # Upload to GCS
        # LOGGER.info(f"Upload {ctr} time: {time.perf_counter()}")
        # ctr += 1

        LOGGER.info(f"uploading blob {file_id}_chunk_{chunk_index}")
        blob_client = azure_blob_service_client.get_blob_client(
            container=AZURE_CONTAINER_NAME,
            blob=f"{file_id}_chunk_{chunk_index}")
        blob_client.upload_blob(chunk)
        chunk_index += 1

    return {"message": "Upload successful", "file_id": file_id}


@app.route("/download/<file_id>", methods=["GET"])
def download(file_id):
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    chunk_index = 0

    while True:
        try:
            # Download from GCS
            LOGGER.info(f"downloading blob {file_id}_chunk_{chunk_index}")
            blob_client = azure_blob_service_client.get_blob_client(
                container=AZURE_CONTAINER_NAME,
                blob=f"{file_id}_chunk_{chunk_index}")

            chunk = blob_client.download_blob().readall()

            if not chunk:
                break

            temp_file.write(chunk)
            chunk_index += 1
        except Exception as e:
            # Break the loop if a chunk is not found, indicating we've reached the end
            break

    temp_file.close()
    return send_file(
        temp_file.name, as_attachment=True, download_name=f"{file_id}.merged"
    )


# TODO(romilb): Deletion doesn't work right now. And this deletion logic is inefficient.
@app.route("/delete/<file_id>", methods=["DELETE"])
def delete(file_id):
    chunk_index = 0
    errors = []

    while True:
        # Construct chunk names as they were during upload
        chunk_name = f"{file_id}_chunk_{chunk_index}"

        try:
            # Attempt to delete from GCS
            bucket = gcs_client.bucket(GCS_BUCKET_NAME)
            blob = bucket.blob(chunk_name)
            blob.delete()
        except Exception as e:
            errors.append(f"Failed to delete {chunk_name} from GCS: {e}")

        # try:
        #     # Attempt to delete from Azure
        #     blob_client = azure_blob_service_client.get_blob_client(container=AZURE_CONTAINER_NAME, blob=chunk_name)
        #     blob_client.delete_blob()
        # except Exception as e:
        #     errors.append(f"Failed to delete {chunk_name} from Azure: {e}")

        # Increment chunk_index and continue until a chunk is not found in both storages
        chunk_index += 1

        # Check if chunk was absent in both storages indicating end of file chunks
        if (
            f"Failed to delete {chunk_name} from GCS" in errors[-2:]
            and f"Failed to delete {chunk_name} from Azure" in errors[-2:]
        ):
            # Remove the last two errors as they indicate the file chunks have ended
            errors = errors[:-2]
            break

    if errors:
        return {
            "message": "Some errors occurred during deletion",
            "errors": errors,
        }, 400
    else:
        return {"message": "File and its chunks deleted successfully"}, 200


if __name__ == "__main__":
    app.run(debug=True, port=AETHER_PORT)
