import csv
import logging
import os
import subprocess
import sys
import tempfile
import time
from typing import List, Optional, Tuple

import requests

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)
FORMATTER = logging.Formatter(
    fmt="%(asctime)s %(levelname)s %(filename)s:%(lineno)d - %(message)s"
)

# set file handler for logging to a file
FILE_HANDLER = logging.FileHandler("intercloud-interleave-read-write-results.log")
FILE_HANDLER.setFormatter(FORMATTER)
LOGGER.addHandler(FILE_HANDLER)
# set stream handler for logging to stdout
STREAM_HANDLER = logging.StreamHandler(sys.stdout)
STREAM_HANDLER.setFormatter(FORMATTER)
LOGGER.addHandler(STREAM_HANDLER)


def start_aether(
    *,  # require keyword args for clarity
    aether_path: str,
    port: int,
    gcp_bucket: str,
    gcp_proxy_url: Optional[str],
    azure_container: str,
    azure_connection_string: Optional[str],
    azure_proxy_url: Optional[str],
) -> subprocess.Popen:
    """
    Start an aether server for the given bucket.
    """
    abs_aether_path = os.path.abspath(aether_path)
    assert os.path.exists(
        abs_aether_path
    ), f"{abs_aether_path} must exist as a path to the aether server file"

    aether_environment = {
        "AETHER_PORT": str(port),
        "GCS_BUCKET_NAME": gcp_bucket,
        "AZURE_CONTAINER_NAME": azure_container,
        "AZURE_CONNECTION_STRING": azure_connection_string or "",
        "CLOUDSDK_API_ENDPOINT_OVERRIDES_COMPUTE": gcp_proxy_url or "",
        "AZURE_API_ENDPOINT_OVERRIDE": azure_proxy_url or "",
    }

    process = subprocess.Popen(
        [
            "python3",
            abs_aether_path,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={
            **os.environ,
            **aether_environment,
        },
    )

    return process


def send_requests(
    num_requests: int,
    aether_url: str,
    file: tempfile._TemporaryFileWrapper,
    file_content: bytes,
) -> List[Tuple[str, float]]:
    download_url = aether_url + "/download"
    upload_url = aether_url + "/upload"

    request_times = []

    for i in range(num_requests):
        # reset file descriptor
        file.seek(0)

        # upload
        LOGGER.info(f"Upload request {i}")
        upload_start_time = time.perf_counter()
        upload_response = requests.post(upload_url, files={"file": file})
        upload_end_time = time.perf_counter()

        upload_time = upload_end_time - upload_start_time
        request_times.append(("UPLOAD", upload_time))

        if not upload_response.ok:
            LOGGER.error(f"UPLOAD FAILED (took {upload_time} seconds)")
            return []

        # parse response to get file id
        upload_response_json = upload_response.json()
        upload_file_id = upload_response_json.get("file_id", None)
        if upload_file_id is None:
            LOGGER.error(f"UPLOAD FAILED (took {upload_time} seconds)")
            return []
        else:
            LOGGER.info(f"Upload took {upload_time} seconds")

        sys.stdout.flush()

        # read
        LOGGER.info(f"Read request {i}")
        read_start_time = time.perf_counter()
        read_response = requests.get(f"{download_url}/{upload_file_id}")
        read_end_time = time.perf_counter()

        read_time = read_end_time - read_start_time
        request_times.append(("READ", read_time))

        # check response data
        read_response_data = read_response.content
        if read_response_data != file_content:
            LOGGER.error(f"READ MISMATCH (took {read_time} seconds)")
            return []
        else:
            LOGGER.info(f"Read took {read_time} seconds")

        sys.stdout.flush()

    return request_times


def upload_policy(
    policy_upload_script: str,
    policy_path: str,
    public_key_path: str,
    upload_credentials_path: str,
    cloud: str,
):
    """
    Run the upload policy script to upload the given policy
    and run checks to ensure that corresponding service accounts
    have been pre-created.
    """

    # convert everything to absolute paths to be safe
    abs_script_path = os.path.abspath(policy_upload_script)
    abs_policy_path = os.path.abspath(policy_path)
    abs_key_path = os.path.abspath(public_key_path)
    abs_creds_path = os.path.abspath(upload_credentials_path)

    LOGGER.info("Sending policy upload request")

    response = subprocess.run(
        [
            "python3",
            abs_script_path,
            "--storage",
            "--policy",
            abs_policy_path,
            "--cloud",
            cloud,
            "--public-key-path",
            abs_key_path,
            "--credentials",
            abs_creds_path,
        ],
        capture_output=True,
    )
    LOGGER.debug(response.stdout)
    if response.stderr:
        LOGGER.warning(response.stderr)

    # make sure command ran fine
    response.check_returncode()

    LOGGER.info("Waiting 15 seconds for service account changes to propagate")
    time.sleep(15)


def main(
    # main options
    file_size: int,
    num_requests: int,
    gcp_bucket: str,
    azure_container: str,
    azure_connection_string: Optional[str],
    gcp_proxy_url: str,
    azure_proxy_url: str,
    # aether options
    aether_path: str,
    aether_host: str,
    aether_port: int,
):
    # create temporary file of random bytes
    file = tempfile.NamedTemporaryFile()
    # hex doubles size; don't use binary file for ease of testing
    # sometimes requests hang due to weird bytes
    file_content = os.urandom(file_size // 2).hex().encode()
    file.write(file_content)

    # normalize aether url
    aether_process = start_aether(
        aether_path=aether_path,
        port=aether_port,
        gcp_bucket=gcp_bucket,
        gcp_proxy_url=gcp_proxy_url,
        azure_container=azure_container,
        azure_connection_string=azure_connection_string,
        azure_proxy_url=azure_proxy_url,
    )
    aether_url = f"{aether_host}:{aether_port}"
    LOGGER.info("Waiting for aether process to start")
    time.sleep(5)

    try:
        request_times = send_requests(
            num_requests=num_requests,
            aether_url=aether_url,
            file=file,
            file_content=file_content,
        )

        # save data
        if len(request_times) > 0:
            with open("intercloud-interleave-read-write-data.csv", "w") as f:
                csv_writer = csv.DictWriter(f, ["type", "time"])
                csv_writer.writeheader()
                for request_type, request_time in request_times:
                    csv_writer.writerow({"type": request_type, "time": request_time})
    finally:
        LOGGER.info("CLEANUP")

        # close temporary file descriptor
        file.close()
        # kill process
        aether_process.kill()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-s",
        "--file-size",
        type=int,
        default=10 * 2**20,  # 10MB
        help="Size of the file in bytes",
    )
    parser.add_argument(
        "-n",
        "--num-requests",
        type=int,
        default=40,
        help="Number of interleaved read/upload requests to make (total individual requests is twice this value)",
    )

    gcp_group = parser.add_argument_group("GCP settings")
    gcp_group.add_argument(
        "--gcp-bucket",
        type=str,
        default="skydentity-test-storage",
        help="GCP bucket to use",
    )
    gcp_group.add_argument(
        "--gcp-proxy-url",
        type=str,
        default="http://127.0.0.1:5000",
        help="URL of the GCP proxy to use",
    )

    azure_group = parser.add_argument_group("Azure settings")
    azure_group.add_argument(
        "--azure-container",
        type=str,
        default="skydentity-test-storage",
        help="Azure container to use",
    )
    azure_group.add_argument(
        "--azure-connection-string",
        type=str,
        default=None,
        help="Azure connection string to pass through to Aether",
    )
    azure_group.add_argument(
        "--azure-proxy-url",
        type=str,
        default="https://127.0.0.1:4000",
        help="URL of the Azure proxy to use",
    )

    aether_group = parser.add_argument_group("Aether settings")
    aether_group.add_argument(
        "--aether-path",
        type=str,
        default="./aether-server.py",
        help="Path to the Aether server python executable",
    )
    aether_group.add_argument(
        "--aether-host",
        type=str,
        default="http://127.0.0.1",
        help="Host of the Aether server",
    )
    aether_group.add_argument(
        "--aether-port",
        type=int,
        default=9999,
        help="Port of the Aether server",
    )

    args = parser.parse_args()
    main(
        file_size=args.file_size,
        num_requests=args.num_requests,
        # GCP
        gcp_bucket=args.gcp_bucket,
        gcp_proxy_url=args.gcp_proxy_url,
        # Azure
        azure_container=args.azure_container,
        azure_connection_string=args.azure_connection_string,
        azure_proxy_url=args.azure_proxy_url,
        # Aether
        aether_path=args.aether_path,
        aether_host=args.aether_host,
        aether_port=args.aether_port,
    )
