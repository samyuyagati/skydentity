#!/bin/bash
# Usage: ./skypilot_baseline.sh <# jobs>

NUM_JOBS=$1

python run_skypilot_jobs.py --num-jobs $NUM_JOBS 2>&1 | tee $2

#grep "Time to provision job" skypilot_benchmark_output.txt | awk '{print $6}' >> job_times_baseline.txt

#sky down -a