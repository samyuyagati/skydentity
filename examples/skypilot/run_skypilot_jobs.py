import time
import os
import argparse
import os
import subprocess
import time

parser = argparse.ArgumentParser(
    prog="RunSkyPilotJobs", description="Launches SkyPilot jobs"
)

parser.add_argument(
    "--num-jobs", type=int, default=40, help="Number of instances to launch"
)
parser.add_argument(
    "--batch-size", type=int, default=10, help="Requests per batch"
)
parser.add_argument(
    "--with-skydentity", action="store_true", help="Whether to use Skydentity"
)
parser.add_argument(
    "--cloud", type=str, default="gcp", help="Cloud to use"
)
args = parser.parse_args()

job = """\
resources:
  instance_type: n1-standard-1
  cloud: gcp
  zone: us-west1-b
  image_id: projects/ubuntu-os-cloud/global/images/ubuntu-2204-jammy-v20240223

run: |
  secs=$(python -S -c 'import random; random.seed({i}); print(random.randint(20*60, 30*60))')

  echo Job duration $secs seconds.
  sleep $secs
  echo Job done.
"""

if args.cloud == "azure":
    job = """\
resources:
  instance_type: Standard_B1ms
  cloud: azure
  region: westus

run: |
  secs=$(python -S -c 'import random; random.seed({i}); print(random.randint(20*60, 30*60))')

  echo Job duration $secs seconds.
  sleep $secs
  echo Job done.
"""


# NOTE: if concurrent experiments - change name!
prefix = "skydentity-test"

NUM_JOBS = args.num_jobs
api_endpoint = "https://compute.googleapis.com/"
if args.cloud == "azure":
    api_endpoint = "https://management.azure.com/"
if args.with_skydentity:
    api_endpoint = "https://127.0.0.1:5000/"

start_time = time.perf_counter()

jobs_per_batch = args.batch_size
num_batches = NUM_JOBS // jobs_per_batch if NUM_JOBS % jobs_per_batch == 0 else (NUM_JOBS // jobs_per_batch) + 1

i = 0
for batch in range(num_batches):
    batch_start = time.perf_counter()
    subprocesses: list[subprocess.Popen] = []
    fds = []
    if (NUM_JOBS - i) < jobs_per_batch:
        jobs_per_batch = NUM_JOBS - i
    for j in range(jobs_per_batch):
        with open("job.yaml", "w") as f:
            f.write(job.format(i=i))

        print(f"Launching job {i}")

        out_fd = open(f"skypilot_benchmark_stdout_{i}.txt", "wb")
        err_fd = open(f"skypilot_benchmark_stderr_{i}.txt", "wb")
        fds.append(out_fd)
        fds.append(err_fd)

        # Paper used subprocess.Run (fully sequential, waits for completion)
        cur_subprocess = subprocess.Popen(
            [
                "time",
                "sky",
                "launch",
                "--retry-until-up",
                "-y",
                "-d",
                "-n",
                f"{prefix}-{i}",
                "job.yaml",
                "-c",
                f"skydentity-{i}"
            ],
            stdout=out_fd,
            stderr=err_fd,
            env={
                **os.environ,
                "CLOUDSDK_API_ENDPOINT_OVERRIDES_COMPUTE": f"{api_endpoint}",
                "REQUESTS_CA_BUNDLE": "/home/kdharmarajan/skydentity/local_tokens/cert.pem"
            },
        )
        subprocesses.append(cur_subprocess)
        i += 1

    # wait for all subprocesses to complete
    for proc in subprocesses:
        proc.wait()

    batch_end = time.perf_counter()

    # close all file descriptors
    for fd in fds:
        fd.flush()
        fd.close()

    print("BATCH TIME (s):", batch_end - batch_start)
print("TOTAL TIME (s):", time.perf_counter() - start_time)