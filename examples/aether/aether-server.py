"""
Clone of https://github.com/romilbhardwaj/aether

Modified to add more configuration options.
"""

import logging
import os
import random
import socket
import string
import tempfile
import time

from azure.storage.blob import BlobServiceClient
from flask import Flask, request, send_file
from google.cloud import storage as gcs_storage

# set up flask
app = Flask(__name__)

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)

# set up logging
FILE_HANDLER = logging.FileHandler(f"aether-server.log")
FORMATTER = logging.Formatter(
    fmt=f"%(asctime)s %(levelname)s[{os.getpid()}] %(filename)s:%(lineno)d - %(message)s"
)
FILE_HANDLER.setFormatter(FORMATTER)
LOGGER.addHandler(FILE_HANDLER)


# Aether configuration
AETHER_PORT = int(os.environ.get("AETHER_PORT", 9999))

# Configure your GCS and Azure storage credentials and bucket/container names
# Read configuration from environment variables
GCS_BUCKET_NAME = os.environ.get("GCS_BUCKET_NAME")

AZURE_CONNECTION_STRING = os.environ.get("AZURE_CONNECTION_STRING")
AZURE_CONTAINER_NAME = os.environ.get("AZURE_CONTAINER_NAME")

CHUNK_SIZE_MB = int(os.environ.get("CHUNK_SIZE", 1))  # default chunk size is 1MB

# Verify that all required environment variables are set
if not GCS_BUCKET_NAME:
    raise EnvironmentError(
        "Missing required environment variables. Please ensure GCS_BUCKET_NAME is set."
    )
if not AZURE_CONTAINER_NAME:
    raise EnvironmentError(
        "Missing required environment variables. Please ensure AZURE_CONTAINER_NAME is set."
    )

# Initialize GCS and Azure clients
gcp_endpoint = os.environ.get("CLOUDSDK_API_ENDPOINT_OVERRIDES_COMPUTE", None)
LOGGER.debug("GCP ENDPOINT %s", gcp_endpoint)
client_options = {}
if gcp_endpoint:
    LOGGER.debug("Using GCP endpoint %s", gcp_endpoint)
    client_options = {"api_endpoint": gcp_endpoint.strip()}
gcs_client = gcs_storage.Client(client_options=client_options)

azure_endpoint = os.environ.get("AZURE_API_ENDPOINT_OVERRIDE", None)
LOGGER.debug("AZURE ENDPOINT %s", azure_endpoint)
if azure_endpoint:
    LOGGER.debug("Using Azure endpoint %s", azure_endpoint)
    azure_blob_service_client = BlobServiceClient(azure_endpoint)
else:
    if not AZURE_CONNECTION_STRING:
        raise EnvironmentError(
            "Missing required environment variables. Please ensure AZURE_CONNECTION_STRING is set if AZURE_API_ENDPOINT_OVERRIDE is not set."
        )
    azure_blob_service_client = BlobServiceClient.from_connection_string(
        AZURE_CONNECTION_STRING
    )

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


@app.route("/upload", methods=["POST"])
def upload():
    file = request.files["file"]
    file_id = generate_file_id()  # Generate or obtain a unique ID for the file

    for chunk_index, chunk in enumerate(split_file(file)):

        blob_name = f"{file_id}_chunk_{chunk_index}"
        if chunk_index % 2 == 0:
            # Upload to GCS
            LOGGER.info(f"Uploading blob {blob_name} to GCP")
            bucket = gcs_client.bucket(GCS_BUCKET_NAME)
            blob = bucket.blob(blob_name)

            chunk_start_time = time.perf_counter()
            blob.upload_from_string(chunk, timeout=REQUEST_TIMEOUT)
            chunk_latency = time.perf_counter() - chunk_start_time

            LOGGER.info(
                f"[GCP/{GCS_BUCKET_NAME}] {blob_name} upload latency: {chunk_latency}"
            )
        else:
            # Upload to Azure
            LOGGER.info(f"Uploading blob {blob_name} to Azure")
            blob_client = azure_blob_service_client.get_blob_client(
                container=AZURE_CONTAINER_NAME, blob=blob_name
            )

            chunk_start_time = time.perf_counter()
            blob_client.upload_blob(chunk)
            chunk_latency = time.perf_counter() - chunk_start_time
            LOGGER.info(
                f"[AZURE/{AZURE_CONTAINER_NAME}] {blob_name} upload latency: {chunk_latency}"
            )

    return {"message": "Upload successful", "file_id": file_id}


@app.route("/download/<file_id>", methods=["GET"])
def download(file_id):
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    chunk_index = 0

    last_cloud = None
    while True:
        blob_name = f"{file_id}_chunk_{chunk_index}"
        chunk_start_time = time.perf_counter()
        chunk_latency = None
        try:
            if chunk_index % 2 == 0:
                last_cloud = "GCP"

                # Download from GCS
                LOGGER.info(f"downloading blob {blob_name} from GCP")
                bucket = gcs_client.bucket(GCS_BUCKET_NAME)
                blob = bucket.blob(blob_name)

                chunk_start_time = time.perf_counter()
                chunk = blob.download_as_bytes(timeout=REQUEST_TIMEOUT)
                chunk_latency = time.perf_counter() - chunk_start_time

                LOGGER.info(
                    f"[GCP/{GCS_BUCKET_NAME}] {blob_name} download latency: {chunk_latency}"
                )
            else:
                last_cloud = "AZURE"

                # Download from Azure
                LOGGER.info(f"downloading blob {blob_name} from Azure")
                blob_client = azure_blob_service_client.get_blob_client(
                    container=AZURE_CONTAINER_NAME,
                    blob=blob_name,
                )

                chunk_start_time = time.perf_counter()
                chunk = blob_client.download_blob().readall()
                chunk_latency = time.perf_counter() - chunk_start_time

                LOGGER.info(
                    f"[AZURE/{AZURE_CONTAINER_NAME}] {blob_name} download latency: {chunk_latency}"
                )

            if not chunk:
                break

            temp_file.write(chunk)
            chunk_index += 1
        except Exception as e:
            if chunk_latency is None:
                chunk_latency = time.perf_counter() - chunk_start_time
            if last_cloud == "GCP":
                LOGGER.info(
                    f"[GCP/{GCS_BUCKET_NAME}] {blob_name} downlaod EOF latency: {chunk_latency}"
                )
            elif last_cloud == "AZURE":
                LOGGER.info(
                    f"[AZURE/{AZURE_CONTAINER_NAME}] {blob_name} download EOF latency: {chunk_latency}"
                )

            # Break the loop if a chunk is not found, indicating we've reached the end
            break

    temp_file.close()
    return send_file(
        temp_file.name, as_attachment=True, download_name=f"{file_id}.merged"
    )


if __name__ == "__main__":
    app.run(debug=False, port=AETHER_PORT)
