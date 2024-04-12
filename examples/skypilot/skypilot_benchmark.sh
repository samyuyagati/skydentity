#!/bin/bash
# Usage: ./skypilot_benchmark.sh <path-to-firebase-creds> <# jobs>

FIREBASE_CREDS=$1
NUM_JOBS=$2

# Set endpoint to redirector
CLOUDSDK_API_ENDPOINT_OVERRIDES_COMPUTE="http://127.0.0.1:5000/"

./setup_skypilot_benchmark.sh "$FIREBASE_CREDS"

python run_skypilot_jobs.py --num-jobs $NUM_JOBS --batch-size 10 --with-skydentity 2>&1 | tee "$3"

#grep "Time to provision job" skypilot_benchmark_output.txt | awk '{print $6}' > job_times_with_skydentity.txt

unset CLOUDSDK_API_ENDPOINT_OVERRIDES_COMPUTE
#sky down -a -y
