import csv
import logging
import os
import subprocess
import sys
import tempfile
import time
from typing import List, Tuple

import requests

# Aether ports start from this value, and increment by 1 for every new server started.
AETHER_START_PORT = 9990

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)
FORMATTER = logging.Formatter(
    fmt="%(asctime)s %(levelname)s %(filename)s:%(lineno)d - %(message)s"
)

# set file handler for logging to a file
FILE_HANDLER = logging.FileHandler("interleave-buckets-results.log")
FILE_HANDLER.setFormatter(FORMATTER)
LOGGER.addHandler(FILE_HANDLER)
# set stream handler for logging to stdout
STREAM_HANDLER = logging.StreamHandler(sys.stdout)
STREAM_HANDLER.setFormatter(FORMATTER)
LOGGER.addHandler(STREAM_HANDLER)


def start_aether(
    aether_path: str, port: int, proxy_url: str, bucket: str
) -> subprocess.Popen:
    """
    Start an aether server for the given bucket.
    """
    abs_aether_path = os.path.abspath(aether_path)
    assert os.path.exists(
        abs_aether_path
    ), f"{abs_aether_path} must exist as a path to the aether server file"

    process = subprocess.Popen(
        [
            "python3",
            abs_aether_path,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={
            **os.environ,
            "CLOUDSDK_API_ENDPOINT_OVERRIDES_COMPUTE": proxy_url,
            "GCS_BUCKET_NAME": bucket,
            "AETHER_PORT": str(port),
        },
    )

    return process


def send_requests(
    num_requests: int,
    buckets: List[str],
    aether_urls: List[str],
    file: tempfile._TemporaryFileWrapper,
    file_content: bytes,
) -> List[Tuple[str, str, float]]:
    # tuple of (type, bucket, time)
    request_times = []

    for req_num in range(num_requests):
        for bucket_num, bucket in enumerate(buckets):
            # get URL to the corresponding aether server
            aether_url = aether_urls[bucket_num]
            upload_url = aether_url + "/upload"
            download_url = aether_url + "/download"

            # reset file descriptor
            file.seek(0)

            # upload
            LOGGER.info(f"[{bucket}] Upload request {req_num}")
            upload_start_time = time.perf_counter()
            upload_response = requests.post(upload_url, files={"file": file})
            upload_end_time = time.perf_counter()

            upload_time = upload_end_time - upload_start_time
            request_times.append(("UPLOAD", bucket, upload_time))

            if not upload_response.ok:
                LOGGER.error(f"[{bucket}] UPLOAD FAILED (took {upload_time} seconds)")
                return []

            # parse response to get file id
            upload_response_json = upload_response.json()
            upload_file_id = upload_response_json.get("file_id", None)
            if upload_file_id is None:
                LOGGER.error(f"[{bucket}] UPLOAD FAILED (took {upload_time} seconds)")
                return []
            else:
                LOGGER.info(f"[{bucket}] Upload took {upload_time} seconds")

            sys.stdout.flush()

            # read
            LOGGER.info(f"[{bucket}] Read request {req_num}")
            read_start_time = time.perf_counter()
            read_response = requests.get(f"{download_url}/{upload_file_id}")
            read_end_time = time.perf_counter()

            read_time = read_end_time - read_start_time
            request_times.append(("READ", bucket, read_time))

            # check response data
            read_response_data = read_response.content
            if read_response_data != file_content:
                LOGGER.error(f"[{bucket}] READ MISMATCH (took {read_time} seconds)")
                return []
            else:
                LOGGER.info(f"[{bucket}] Read took {read_time} seconds")

            sys.stdout.flush()

    return request_times


def upload_policy(
    policy_upload_script: str,
    policy_path: str,
    public_key_path: str,
    upload_credentials_path: str,
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
            "gcp",
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
    buckets: List[str],
    proxy_url: str,
    # aether options
    aether_host: str,
    aether_path: str,
    # policy upload options
    policy_upload_script: str,
    policy_path: str,
    public_key_path: str,
    upload_credentials_path: str,
    # script options
    with_policy_upload: bool = True,
):
    if with_policy_upload:
        # first upload policy
        upload_policy(
            policy_upload_script=policy_upload_script,
            policy_path=policy_path,
            public_key_path=public_key_path,
            upload_credentials_path=upload_credentials_path,
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
    for i, bucket in enumerate(buckets):
        port = AETHER_START_PORT + i
        aether_processes.append(start_aether(aether_path, port, proxy_url, bucket))
        aether_urls.append(f"{aether_host}:{port}")
    LOGGER.info("Waiting for aether processes to start")
    time.sleep(5)

    try:
        # send requests
        request_times = send_requests(
            num_requests=num_requests,
            buckets=buckets,
            aether_urls=aether_urls,
            file=file,
            file_content=file_content,
        )

        if len(request_times) > 0:
            # save data
            with open("interleave-buckets-data.csv", "w") as f:
                csv_writer = csv.DictWriter(f, ["type", "bucket", "time"])
                csv_writer.writeheader()
                for request_type, bucket, request_time in request_times:
                    csv_writer.writerow(
                        {"type": request_type, "bucket": bucket, "time": request_time}
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
    parser.add_argument(
        "--proxy-url",
        type=str,
        default="http://127.0.0.1:5000",
        help="URL of the proxy to use",
    )
    parser.add_argument(
        "--buckets",
        type=str,
        nargs="+",
        default=[
            "skydentity-test-storage-1",
            "skydentity-test-storage-2",
            "skydentity-test-storage-3",
        ],
        help="Buckets to alternate between",
    )

    parser.add_argument(
        "--no-policy-upload",
        action="store_false",
        dest="with_policy_upload",
        help="Disable initial policy upload",
    )

    aether_group = parser.add_argument_group("Aether settings")
    aether_group.add_argument(
        "--aether-path",
        type=str,
        default="./gcp-aether-server.py",
        help="Path to the Aether server python executable",
    )
    aether_group.add_argument(
        "--aether-host",
        type=str,
        default="http://127.0.0.1",
        help="Host of the Aether server",
    )

    policy_upload_group = parser.add_argument_group("Policy upload settings")
    policy_upload_group.add_argument(
        "--policy-upload-script",
        type=str,
        default="../../skydentity/scripts/upload_policy.py",
        help="Path to the policy upload script to use",
    )
    policy_upload_group.add_argument(
        "--policy-path",
        type=str,
        default="./config/storage_policy_buckets.yaml",
        help="Path to the policy to upload",
    )
    policy_upload_group.add_argument(
        "--public-key-path",
        type=str,
        default="./keys/public.pem",
        help="Path to the public key for uploading the policy",
    )
    policy_upload_group.add_argument(
        "--upload-credentials-path",
        type=str,
        required=True,
        help="Path to credentials file for uploading the policy",
    )

    args = parser.parse_args()
    main(
        file_size=args.file_size,
        num_requests=args.num_requests,
        buckets=args.buckets,
        proxy_url=args.proxy_url,
        aether_host=args.aether_host,
        aether_path=args.aether_path,
        policy_upload_script=args.policy_upload_script,
        policy_path=args.policy_path,
        public_key_path=args.public_key_path,
        upload_credentials_path=args.upload_credentials_path,
        with_policy_upload=args.with_policy_upload,
    )
