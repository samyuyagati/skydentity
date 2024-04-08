import csv
import sys
import os
import tempfile
import time

import requests


def main(file_size, num_requests, aether_url):
    # create temporary file of random bytes
    file = tempfile.NamedTemporaryFile()
    # hex doubles size; don't use binary file for ease of testing
    # sometimes requests hang due to weird bytes
    file_content = os.urandom(file_size // 2).hex().encode()
    file.write(file_content)

    upload_times = []
    read_times = []

    # normalize aether url
    normalized_aether_url = aether_url.strip("/") + "/"

    download_url = normalized_aether_url + "download/"
    upload_url = normalized_aether_url + "upload"

    for i in range(num_requests):
        # reset file descriptor
        file.seek(0)

        # upload
        print(f"Upload request {i}")
        upload_start_time = time.perf_counter()
        upload_response = requests.post(upload_url, files={"file": file})
        upload_end_time = time.perf_counter()

        upload_time = upload_end_time - upload_start_time
        upload_times.append(upload_time)

        if not upload_response.ok:
            print(f"\tUPLOAD FAILED (took {upload_time} seconds)")
            return

        # parse response to get file id
        upload_response_json = upload_response.json()
        upload_file_id = upload_response_json.get("file_id", None)
        if upload_file_id is None:
            print(f"\tUPLOAD FAILED (took {upload_time} seconds)")
            return
        else:
            print(f"\tUpload took {upload_time} seconds")

        # read
        print(f"Read request {i}")
        read_start_time = time.perf_counter()
        read_response = requests.get(download_url + upload_file_id)
        read_end_time = time.perf_counter()

        read_time = read_end_time - read_start_time
        read_times.append(read_time)

        # check response data
        read_response_data = read_response.content
        if read_response_data != file_content:
            print(f"\tREAD MISMATCH (took {read_time} seconds)")
            return
        else:
            print(f"\tRead took {read_time} seconds")

        sys.stdout.flush()

    # cleanup
    file.close()

    # save data
    with open("interleave-workload-data.csv", "w") as f:
        csv_writer = csv.DictWriter(f, ["type", "time"])
        csv_writer.writeheader()
        for upload_time, read_time in zip(upload_times, read_times):
            csv_writer.writerow({"type": "UPLOAD", "time": upload_time})
            csv_writer.writerow({"type": "READ", "time": read_time})


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
    parser.add_argument(
        "-u",
        "--aether-url",
        type=str,
        default="http://127.0.0.1:9999",
        help="URL for the Aether server to send requests to",
    )

    args = parser.parse_args()
    main(
        file_size=args.file_size,
        num_requests=args.num_requests,
        aether_url=args.aether_url,
    )
