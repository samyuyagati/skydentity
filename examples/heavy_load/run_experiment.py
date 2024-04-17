from typing import List
import argparse
import subprocess
import time

from test_server import create_instance, delete_instance, get_image

parser = argparse.ArgumentParser(
                    prog='RunHeavyLoadExperiment',
                    description='Tests large volume of VM creation requests to Skydentity')

parser.add_argument('--num-requests', type=int, default=1, help='Number of VM creation requests to send to Skydentity')
parser.add_argument('--project', type=str, default='sky-identity', help='Project ID of the GCP project you want to use')
parser.add_argument('--zone', type=str, default='us-west1-b', help='Name of the zone to create the instance in')
parser.add_argument('--api-endpoint', type=str, default=None, help='API endpoint to send requests to; defaults to compute.googleapis.com')
parser.add_argument("--credentials", type=str, default=None, help="Path to the service account key file")
parser.add_argument("--concurrent", action="store_true", help="Run requests concurrently")
parser.add_argument("--batch-size", type=int, default=None, help="Number of requests per batch")
parser.add_argument("--delete", action="store_true", help="Delete instances after creation")
args = parser.parse_args()

if args.api_endpoint != None:
    LOGS_DIR = f"logs/with_skydentity_{args.batch_size}"
else:
    LOGS_DIR = f"logs/baseline_{args.batch_size}"

def run_sequential(num_requests):
    for i in range(num_requests):
        disks = get_image(api_endpoint=args.api_endpoint)
        start = time.time()
        create_instance(args.project, args.zone, f"gcp-clilib-{i}", disks, api_endpoint=args.api_endpoint)
        print(f"Time to send instance creation req {i}: ", time.time() - start)

def run_concurrent(num_requests, batch_size=None):
    if batch_size is None:
        batch_size = num_requests
    
    num_batches = num_requests // batch_size if num_requests % batch_size == 0 else (num_requests // batch_size) + 1

    i = 0
    start = time.perf_counter()
    for batch in range(num_batches):
        batch_start = time.perf_counter()
        subprocesses: list[subprocess.Popen] = []
        fds = []
        if (num_requests - i) < batch_size:
            batch_size = num_requests - i
        for j in range(batch_size):
            print(f"Creating VM {i} ({j + 1} of {batch_size} in batch {batch})")

            out_fd = open(f"{LOGS_DIR}/stdout_{i}.txt", "wb")
            err_fd = open(f"{LOGS_DIR}/stderr_{i}.txt", "wb")
            fds.append(out_fd)
            fds.append(err_fd)
            
            # Skydentity
            if (args.api_endpoint != None):
                cur_subprocess = subprocess.Popen(
                    [
                        "/usr/bin/time",
                        "python",
                        "test_server.py",
                        "--project",
                        f"{args.project}",
                        "--zone",
                        f"{args.zone}",
                        "--api-endpoint",
                        f"{args.api_endpoint}",
                        "--vm-id",
                        f"{i}"
                    ],
                    stdout=out_fd,
                    stderr=err_fd,
                )
            # Baseline
            else:
                cur_subprocess = subprocess.Popen(
                    [
                        "/usr/bin/time",
                        "python",
                        "test_server.py",
                        "--credentials",
                        f"{args.credentials}",
                        "--project",
                        f"{args.project}",
                        "--zone",
                        f"{args.zone}",
                        "--vm-id",
                        f"{i}"
                    ],
                    stdout=out_fd,
                    stderr=err_fd,
                )
            subprocesses.append(cur_subprocess)
            i += 1

        # wait for all subprocesses to complete
        for proc in subprocesses:
            print("Waiting for subprocess to complete...")
            proc.wait()

        batch_end = time.perf_counter()

        # close all file descriptors
        for fd in fds:
            fd.flush()
            fd.close()

        print("BATCH TIME (s):", batch_end - batch_start)
    print("TOTAL TIME: ", time.perf_counter() - start)

def main():
    if args.concurrent:
        print("Running concurrent requests")
        run_concurrent(args.num_requests, batch_size=args.batch_size)
    else:
        print("Running sequential requests")
        run_sequential(args.num_requests)
    if args.delete:
        print("Waiting thirty seconds for instances to come up...")
        time.sleep(30)
        print("Deleting instances...")
        for i in range(args.num_requests):
            delete_instance(args.project, args.zone, f"gcp-clilib-{i}")
        print("Waiting two minutes for deletion to complete...")
        time.sleep(120)

if __name__ == "__main__":
    main()