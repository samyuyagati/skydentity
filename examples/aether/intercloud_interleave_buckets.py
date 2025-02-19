import csv
import logging
import os
import subprocess
import sys
import tempfile
import time
from typing import List, Optional, Tuple

import requests

# Aether ports start from this value, and increment by 1 for every new server started.
AETHER_START_PORT = 9990

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)
FORMATTER = logging.Formatter(
    fmt="%(asctime)s %(levelname)s %(filename)s:%(lineno)d - %(message)s"
)

# set file handler for logging to a file
FILE_HANDLER = logging.FileHandler("intercloud-interleave-buckets-results.log")
FILE_HANDLER.setFormatter(FORMATTER)
LOGGER.addHandler(FILE_HANDLER)
# set stream handler for logging to stdout
STREAM_HANDLER = logging.StreamHandler(sys.stdout)
STREAM_HANDLER.setFormatter(FORMATTER)
LOGGER.addHandler(STREAM_HANDLER)


def start_aether(
    *,
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
    gcp_buckets: List[str],
    azure_containers: List[str],
    aether_urls: List[str],
    file: tempfile._TemporaryFileWrapper,
    file_content: bytes,
) -> List[Tuple[str, str, str, float]]:
    # tuple of (type, gcp_bucket, azure_container, time)
    request_times = []

    for req_num in range(num_requests):
        for bucket_num, (gcp_bucket, azure_container) in enumerate(
            zip(gcp_buckets, azure_containers)
        ):
            # get URL to the corresponding aether server
            aether_url = aether_urls[bucket_num]
            upload_url = aether_url + "/upload"
            download_url = aether_url + "/download"

            # reset file descriptor
            file.seek(0)

            # upload
            LOGGER.info(f"[{gcp_bucket}/{azure_container}] Upload request {req_num}")
            upload_start_time = time.perf_counter()
            upload_response = requests.post(upload_url, files={"file": file})
            upload_end_time = time.perf_counter()

            upload_time = upload_end_time - upload_start_time
            request_times.append(("UPLOAD", gcp_bucket, azure_container, upload_time))

            if not upload_response.ok:
                LOGGER.error(
                    f"[{gcp_bucket}/{azure_container}] UPLOAD FAILED (took {upload_time} seconds)"
                )
                return []

            # parse response to get file id
            upload_response_json = upload_response.json()
            upload_file_id = upload_response_json.get("file_id", None)
            if upload_file_id is None:
                LOGGER.error(
                    f"[{gcp_bucket}/{azure_container}] UPLOAD FAILED (took {upload_time} seconds)"
                )
                return []
            else:
                LOGGER.info(
                    f"[{gcp_bucket}/{azure_container}] Upload took {upload_time} seconds"
                )

            sys.stdout.flush()

            # read
            LOGGER.info(f"[{gcp_bucket}/{azure_container}] Read request {req_num}")
            read_start_time = time.perf_counter()
            read_response = requests.get(f"{download_url}/{upload_file_id}")
            read_end_time = time.perf_counter()

            read_time = read_end_time - read_start_time
            request_times.append(("READ", gcp_bucket, azure_container, read_time))

            # check response data
            read_response_data = read_response.content
            if read_response_data != file_content:
                LOGGER.error(
                    f"[{gcp_bucket}/{azure_container}] READ MISMATCH (took {read_time} seconds)"
                )
                return []
            else:
                LOGGER.info(
                    f"[{gcp_bucket}/{azure_container}] Read took {read_time} seconds"
                )

            sys.stdout.flush()

    return request_times


def main(
    # main options
    file_size: int,
    num_requests: int,
    # GCP
    gcp_buckets: List[str],
    gcp_proxy_url: str,
    # Azure
    azure_containers: List[str],
    azure_connection_string: str,
    azure_proxy_url: str,
    # Aether
    aether_host: str,
    aether_path: str,
):
    # input checks
    if len(gcp_buckets) != len(azure_containers):
        raise ValueError(
            "Must have the same number of buckets/containers between GCP and Azure"
        )

    # create temporary file of random bytes
    file = tempfile.NamedTemporaryFile()
    # hex doubles size; don't use binary file for ease of testing
    # sometimes requests hang due to weird bytes
    file_content = os.urandom(file_size // 2).hex().encode()
    file.write(file_content)

    # start servers
    aether_processes: List[subprocess.Popen] = []
    aether_urls: List[str] = []
    for i, (gcp_bucket, azure_container) in enumerate(
        zip(gcp_buckets, azure_containers)
    ):
        port = AETHER_START_PORT + i
        aether_processes.append(
            start_aether(
                aether_path=aether_path,
                port=port,
                gcp_bucket=gcp_bucket,
                gcp_proxy_url=gcp_proxy_url,
                azure_container=azure_container,
                azure_connection_string=azure_connection_string,
                azure_proxy_url=azure_proxy_url,
            )
        )
        aether_urls.append(f"{aether_host}:{port}")
    LOGGER.info("Waiting for aether processes to start")
    time.sleep(5)

    try:
        # send requests
        request_times = send_requests(
            num_requests=num_requests,
            gcp_buckets=gcp_buckets,
            azure_containers=azure_containers,
            aether_urls=aether_urls,
            file=file,
            file_content=file_content,
        )

        if len(request_times) > 0:
            # save data
            with open("intercloud-interleave-buckets-data.csv", "w") as f:
                csv_writer = csv.DictWriter(
                    f, ["type", "gcp_bucket", "azure_container", "time"]
                )
                csv_writer.writeheader()
                for (
                    request_type,
                    gcp_bucket,
                    azure_container,
                    request_time,
                ) in request_times:
                    csv_writer.writerow(
                        {
                            "type": request_type,
                            "gcp_bucket": gcp_bucket,
                            "azure_container": azure_container,
                            "time": request_time,
                        }
                    )
    finally:
        LOGGER.info("CLEANUP")

        # close temporary file descriptor
        file.close()
        # kill processes
        for process in aether_processes:
            process.kill()


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
        help=(
            "Number of interleaved read/upload requests to make; "
            "total individual requests is requests * buckets * 2"
        ),
    )

    gcp_group = parser.add_argument_group("GCP settings")
    gcp_group.add_argument(
        "--gcp-buckets",
        type=str,
        nargs="+",
        default=[
            "skydentity-test-storage-1",
            "skydentity-test-storage-2",
            "skydentity-test-storage-3",
        ],
        help="GCP buckets to alternate between",
    )
    gcp_group.add_argument(
        "--gcp-proxy-url",
        type=str,
        default="http://127.0.0.1:5000",
        help="URL of the GCP proxy to use",
    )

    azure_group = parser.add_argument_group("Azure settings")
    azure_group.add_argument(
        "--azure-containers",
        type=str,
        nargs="+",
        default=[
            "skydentity-test-storage-1",
            "skydentity-test-storage-2",
            "skydentity-test-storage-3",
        ],
        help="Azure containers to alternate between",
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

    args = parser.parse_args()
    main(
        file_size=args.file_size,
        num_requests=args.num_requests,
        # GCP
        gcp_buckets=args.gcp_buckets,
        gcp_proxy_url=args.gcp_proxy_url,
        # Azure
        azure_containers=args.azure_containers,
        azure_connection_string=args.azure_connection_string,
        azure_proxy_url=args.azure_proxy_url,
        # Aether
        aether_host=args.aether_host,
        aether_path=args.aether_path,
    )
