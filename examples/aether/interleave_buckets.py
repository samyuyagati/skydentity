import csv
import os
import subprocess
import sys
import tempfile
import time
from typing import List, Tuple

import requests

# Aether ports start from this value, and increment by 1 for every new server started.
AETHER_START_PORT = 9990


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
    file: tempfile._TemporaryFileWrapper[bytes],
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
            print(f"[{bucket}] Upload request {req_num}")
            upload_start_time = time.perf_counter()
            upload_response = requests.post(upload_url, files={"file": file})
            upload_end_time = time.perf_counter()

            upload_time = upload_end_time - upload_start_time
            request_times.append(("UPLOAD", bucket, upload_time))

            if not upload_response.ok:
                print(f"\tUPLOAD FAILED (took {upload_time} seconds)")
                return []

            # parse response to get file id
            upload_response_json = upload_response.json()
            upload_file_id = upload_response_json.get("file_id", None)
            if upload_file_id is None:
                print(f"\tUPLOAD FAILED (took {upload_time} seconds)")
                return []
            else:
                print(f"\tUpload took {upload_time} seconds")

            sys.stdout.flush()

            # read
            print(f"[{bucket}] Read request {req_num}")
            read_start_time = time.perf_counter()
            read_response = requests.get(f"{download_url}/{upload_file_id}")
            read_end_time = time.perf_counter()

            read_time = read_end_time - read_start_time
            request_times.append(("READ", bucket, read_time))

            # check response data
            read_response_data = read_response.content
            if read_response_data != file_content:
                print(f"\tREAD MISMATCH (took {read_time} seconds)")
                return []
            else:
                print(f"\tRead took {read_time} seconds")

            sys.stdout.flush()

    return request_times


def main(
    file_size: int,
    num_requests: int,
    aether_host: str,
    aether_path: str,
    proxy_url: str,
    buckets: List[str],
):
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
    print("Waiting for aether processes to start")
    time.sleep(5)

    # send requests
    request_times = send_requests(
        num_requests=num_requests,
        buckets=buckets,
        aether_urls=aether_urls,
        file=file,
        file_content=file_content,
    )

    # cleanup
    file.close()

    # kill processes
    for process in aether_processes:
        process.kill()

    if len(request_times) > 0:
        # save data
        with open("interleave-bucket-workload-data.csv", "w") as f:
            csv_writer = csv.DictWriter(f, ["type", "bucket", "time"])
            csv_writer.writeheader()
            for request_type, bucket, request_time in request_times:
                csv_writer.writerow(
                    {"type": request_type, "bucket": bucket, "time": request_time}
                )


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
        "--aether-path",
        type=str,
        default="./gcp-aether-server.py",
        help="Path to the Aether server python executable",
    )
    parser.add_argument(
        "--aether-host",
        type=str,
        default="http://127.0.0.1",
        help="Host of the Aether server",
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
            "skydentity-test-storage",
            "skydentity-test-storage-2",
            "skydentity-test-storage-3",
        ],
        help="Buckets to alternate between",
    )

    args = parser.parse_args()
    main(
        file_size=args.file_size,
        num_requests=args.num_requests,
        aether_host=args.aether_host,
        aether_path=args.aether_path,
        proxy_url=args.proxy_url,
        buckets=args.buckets,
    )
