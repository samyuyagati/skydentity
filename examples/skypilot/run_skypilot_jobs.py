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

# NOTE: if concurrent experiments - change name!
prefix = "skydentity-test"

NUM_JOBS = args.num_jobs

subprocesses: list[subprocess.Popen] = []
fds = []

start_time = time.perf_counter()

for i in range(NUM_JOBS):
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
        ],
        stdout=out_fd,
        stderr=err_fd,
        env={
            **os.environ,
            "CLOUDSDK_API_ENDPOINT_OVERRIDES_COMPUTE": "http://127.0.0.1:5000/",
            # "CLOUDSDK_API_ENDPOINT_OVERRIDES_COMPUTE": "https://compute.googleapis.com/",
        },
    )
    subprocesses.append(cur_subprocess)

# wait for all subprocesses to complete
for proc in subprocesses:
    proc.wait()

end_time = time.perf_counter()

# close all file descriptors
for fd in fds:
    fd.flush()
    fd.close()

print("TOTAL TIME (s):", end_time - start_time)