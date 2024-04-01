import argparse
import os
import subprocess
import time

parser = argparse.ArgumentParser(
                    prog='RunSkyPilotJobs',
                    description='Launches SkyPilot jobs')

parser.add_argument('--num-jobs', type=int, default=40, help='Number of instances to launch')
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

for i in range(NUM_JOBS):
    with open("job.yaml", "w") as f:
        f.write(job.format(i=i))

    print(f"Launching job {i}")
    # Paper used subprocess.Run (fully sequential, waits for completion)
    # The -d flag detaches, so the call will return after provisioning.
    start = time.time()
#    subprocess.run(
#            f"CLOUDSDK_API_ENDPOINT_OVERRIDES_COMPUTE='http://127.0.0.1:5000/' sky launch {prefix}-{i} job.yaml",
#        shell=True,
#        check=True
#    )
    p = subprocess.Popen(
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
        env={
            **os.environ,
            "CLOUDSDK_API_ENDPOINT_OVERRIDES_COMPUTE": "http://127.0.0.1:5000/",
        },
        stdout=subprocess.PIPE
    )
    (output, err) = p.communicate() 
    p_status = p.wait()
    
    subprocess.run(
            f"CLOUDSDK_API_ENDPOINT_OVERRIDES_COMPUTE='http://127.0.0.1:5000/' sky launch --retry-until-up -y -d -n {prefix}-{i} job.yaml",
        shell=True,
        check=True
    )
    print(f"Time to provision job {i}: {time.time() - start}")