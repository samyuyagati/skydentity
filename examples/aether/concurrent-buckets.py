"""
Concurrency test over multiple buckets.
"""

import csv
import logging
import multiprocessing
import multiprocessing.pool
import os
import subprocess
import sys
import tempfile
import time
from multiprocessing.pool import AsyncResult
from typing import List, Literal, Optional, Tuple, Union

import requests

# Aether ports start from this value, and increment by 1 for every new server started.
AETHER_START_PORT = 9990

# number of pings to serverless proxy
NUM_PINGS = 3

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)
FORMATTER = logging.Formatter(
    fmt="%(asctime)s %(levelname)s %(filename)s:%(lineno)d - %(message)s"
)

# set file handler for logging to a file
FILE_HANDLER = logging.FileHandler("concurrent-buckets-results.log")
FILE_HANDLER.setFormatter(FORMATTER)
LOGGER.addHandler(FILE_HANDLER)
# set stream handler for logging to stdout
STREAM_HANDLER = logging.StreamHandler(sys.stdout)
STREAM_HANDLER.setFormatter(FORMATTER)
LOGGER.addHandler(STREAM_HANDLER)

def start_aether(
    aether_path: str, port: int, proxy_url: str, bucket: str, cloud: str
) -> subprocess.Popen:
    """
    Start an aether server for the given bucket.
    """
    abs_aether_path = os.path.abspath(aether_path)
    assert os.path.exists(
        abs_aether_path
    ), f"{abs_aether_path} must exist as a path to the aether server file"

    aether_environment = {
            **os.environ,
            "AETHER_PORT": str(port),
        }

    if proxy_url:
        aether_environment["CLOUDSDK_API_ENDPOINT_OVERRIDES_COMPUTE"] = proxy_url
    if cloud == "gcp":
        aether_environment["GCS_BUCKET_NAME"] = bucket
    elif cloud == "azure":
        aether_environment["AZURE_CONTAINER_NAME"] = bucket
    else:
        raise ValueError(f"Invalid cloud: {cloud}")

    process = subprocess.Popen(
        [
            "python3",
            abs_aether_path,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=aether_environment
    )

    return process


def ping_proxy(serverless_proxy_url: Optional[str]):
    """
    Ping the serverless proxy to ensure that it is alive.

    Weird things happen if concurrent requests are sent on the container startup.

    If the proxy URL is not specified, this is a no-op.
    """
    if serverless_proxy_url is not None:
        # wait some time to allow for container to automatically stop
        LOGGER.info("Waiting 15 seconds between batches of requests")
        time.sleep(15)
        # send any request and ignore any response
        LOGGER.info("Sending pings to serverless proxy")
        for _ in range(NUM_PINGS):
            requests.get(serverless_proxy_url)
            time.sleep(3)

        LOGGER.info("Waiting 15 seconds for serverless proxy to start")
        time.sleep(15)


def send_request(
    req_num: int,
    aether_url: str,
    bucket: str,
    file_path: str,
    file_content: bytes,
    request_type: Union[Literal["READ"], Literal["UPLOAD"]] = "READ",
    request_file_id: Optional[str] = None,
) -> Tuple[float, Optional[str]]:
    """
    Send a request.

    If request_type is READ:
        - request_file_id is required
        - returns (time, None)
    If request_type is UPLOAD:
        - request_file_id is not used
        - returns (time, file_id)
    """
    file = open(file_path, "rb")
    upload_url = aether_url + "/upload"
    download_url = aether_url + "/download"

    if request_type == "UPLOAD":
        LOGGER.info(f"[{bucket}] Upload request {req_num}")
        upload_start_time = time.perf_counter()
        upload_response = requests.post(upload_url, files={"file": file})
        upload_end_time = time.perf_counter()

        upload_time = upload_end_time - upload_start_time

        if not upload_response.ok:
            LOGGER.error(f"[{bucket}] UPLOAD FAILED (took {upload_time} seconds)")
            return -1, None

        # parse response to get file id
        upload_response_json = upload_response.json()
        upload_file_id = upload_response_json.get("file_id", None)
        if upload_file_id is None:
            LOGGER.error(f"[{bucket}] UPLOAD FAILED (took {upload_time} seconds)")
            return -1, None
        else:
            LOGGER.info(f"[{bucket}] Upload took {upload_time} seconds")

        return upload_time, upload_file_id
    elif request_type == "READ":
        assert request_file_id is not None

        LOGGER.info(f"[{bucket}] Read request {req_num}")
        read_start_time = time.perf_counter()
        read_response = requests.get(f"{download_url}/{request_file_id}")
        read_end_time = time.perf_counter()

        read_time = read_end_time - read_start_time

        # check response data
        read_response_data = read_response.content
        if read_response_data != file_content:
            LOGGER.error(f"[{bucket}] READ MISMATCH (took {read_time} seconds)")
            return -1, None
        else:
            LOGGER.info(f"[{bucket}] Read took {read_time} seconds")
            return read_time, None


def send_requests(
    process_pool: multiprocessing.pool.Pool,
    num_requests: int,
    aether_urls: List[str],
    buckets: List[str],
    file: tempfile._TemporaryFileWrapper,
    file_content: bytes,
    serverless_proxy_url: Optional[str],
) -> List[Tuple[str, str, float]]:
    def send_write_requests():
        # send writes
        write_processes: List[Tuple[int, AsyncResult[Tuple[float, Optional[str]]]]] = []
        for req_num in range(num_requests):
            aether_url = aether_urls[req_num]
            bucket = buckets[req_num]

            req_process = process_pool.apply_async(
                send_request,
                kwds={
                    "req_num": req_num,
                    "aether_url": aether_url,
                    "bucket": bucket,
                    "file_path": file.name,
                    "file_content": file_content,
                    "request_type": "UPLOAD",
                },
            )
            write_processes.append((req_num, req_process))
        return write_processes

    def send_read_requests(file_ids: List[Tuple[int, str]]):
        # send reads
        read_processes: List[Tuple[int, AsyncResult[Tuple[float, Optional[str]]]]] = []
        for req_num, file_id in file_ids:
            aether_url = aether_urls[req_num]
            bucket = buckets[req_num]

            req_process = process_pool.apply_async(
                send_request,
                kwds={
                    "req_num": req_num,
                    "aether_url": aether_url,
                    "bucket": bucket,
                    "file_path": file.name,
                    "file_content": file_content,
                    "request_type": "READ",
                    "request_file_id": file_id,
                },
            )
            read_processes.append((req_num, req_process))
        return read_processes

    # tuple of (type, bucket, time)
    request_times = []

    # ping_proxy(serverless_proxy_url)
    LOGGER.info("===== SENDING WRITES =====")

    write_processes = send_write_requests()

    # get results
    write_results: List[Tuple[int, str]] = []
    for req_num, req_process in write_processes:
        write_time, write_file_id = req_process.get()
        assert write_file_id is not None
        write_results.append((req_num, write_file_id))

        request_times.append((f"UPLOAD-{req_num}", buckets[req_num], write_time))

    ping_proxy(serverless_proxy_url)
    LOGGER.info("===== SENDING READS =====")

    read_processes = send_read_requests(write_results)

    # get results
    for req_num, req_process in read_processes:
        read_time, _ = req_process.get()
        request_times.append((f"READ-{req_num}", buckets[req_num], read_time))

    ping_proxy(serverless_proxy_url)
    LOGGER.info("===== SENDING WRITES =====")

    write_processes = send_write_requests()

    # get results
    write_results: List[Tuple[int, str]] = []
    for req_num, req_process in write_processes:
        write_time, write_file_id = req_process.get()
        assert write_file_id is not None
        write_results.append((req_num, write_file_id))

        request_times.append((f"UPLOAD-{req_num}", buckets[req_num], write_time))

    ping_proxy(serverless_proxy_url)
    LOGGER.info("===== SENDING READS =====")

    read_processes = send_read_requests(write_results)

    # get results
    for req_num, req_process in read_processes:
        read_time, _ = req_process.get()
        request_times.append((f"READ-{req_num}", buckets[req_num], read_time))

    ping_proxy(serverless_proxy_url)
    LOGGER.info("===== SENDING READ/WRITES =====")

    # wave of reads
    read_processes = send_read_requests(write_results)
    # wave of writes
    write_processes = send_write_requests()

    # get results
    for req_num, req_process in read_processes:
        read_time, _ = req_process.get()
        request_times.append((f"SIMUL-READ-{req_num}", buckets[req_num], read_time))
    for req_num, req_process in write_processes:
        write_time, _ = req_process.get()
        request_times.append((f"SIMUL-UPLOAD-{req_num}", buckets[req_num], write_time))

    return request_times


def upload_policy(
    policy_upload_script: str,
    policy_path: str,
    public_key_path: str,
    upload_credentials_path: str,
    cloud: str
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
    bucket_prefix: str,
    proxy_url: str,
    serverless_proxy_url: Optional[str],
    # aether options
    aether_host: str,
    aether_path: str,
    # policy upload options
    policy_upload_script: str,
    policy_path: str,
    public_key_path: str,
    upload_credentials_path: str,
    cloud: str
):
    # first upload policy
    upload_policy(
        policy_upload_script=policy_upload_script,
        policy_path=policy_path,
        public_key_path=public_key_path,
        upload_credentials_path=upload_credentials_path,
        cloud=cloud
    )

    # create temporary file of random bytes
    file = tempfile.NamedTemporaryFile()
    # hex doubles size; don't use binary file for ease of testing
    # sometimes requests hang due to weird bytes
    file_content = os.urandom(file_size // 2).hex().encode()
    file.write(file_content)

    # start servers
    LOGGER.info("Starting aether processes")
    aether_processes: List[subprocess.Popen] = []
    aether_urls: List[str] = []
    buckets: List[str] = []
    for i in range(num_requests):
        port = AETHER_START_PORT + i
        bucket = f"{bucket_prefix}-{i+1}"
        aether_processes.append(start_aether(aether_path, port, proxy_url, bucket, cloud))
        aether_urls.append(f"{aether_host}:{port}")
        buckets.append(bucket)
    LOGGER.info("Waiting 5 seconds for aether processes to start")
    time.sleep(5)

    # one process for each request;
    # maximum 2 * num_requests, when both reads and writes are sent
    process_pool = multiprocessing.Pool(num_requests * 2)

    try:
        request_times = send_requests(
            process_pool=process_pool,
            num_requests=num_requests,
            aether_urls=aether_urls,
            buckets=buckets,
            file=file,
            file_content=file_content,
            serverless_proxy_url=serverless_proxy_url,
        )

        if len(request_times) > 0:
            # save data
            with open("concurrent-buckets-data.csv", "w") as f:
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
        # kill aether processes
        for process in aether_processes:
            process.kill()
        # kill subprocesses
        process_pool.terminate()


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
        default=16,
        help=("Number of concurrent read/upload requests to make"),
    )
    parser.add_argument(
        "--proxy-url",
        type=str,
        default=None,
        help="URL of the proxy to use",
    )
    parser.add_argument(
        "--serverless-proxy-url",
        type=str,
        default=None,
        help="Serverless proxy url; used to ping the serverless proxy to ensure that it is alive prior to sending concurrent requests",
    )
    parser.add_argument(
        "--bucket-prefix",
        type=str,
        default="skydentity-test-storage",
        help="Bucket prefix for concurrent requests; format of bucket will be '{prefix}-{idx}'",
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
        default="./config/storage_policy_concurrent.yaml",
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
    policy_upload_group.add_argument(
        "--cloud",
        type=str,
        default="gcp",
        help="Cloud used for the benchmark. One of gcp, azure",
    )

    args = parser.parse_args()

    main(
        file_size=args.file_size,
        num_requests=args.num_requests,
        aether_host=args.aether_host,
        aether_path=args.aether_path,
        proxy_url=args.proxy_url,
        bucket_prefix=args.bucket_prefix,
        policy_upload_script=args.policy_upload_script,
        policy_path=args.policy_path,
        public_key_path=args.public_key_path,
        upload_credentials_path=args.upload_credentials_path,
        serverless_proxy_url=args.serverless_proxy_url,
        cloud=args.cloud
    )
