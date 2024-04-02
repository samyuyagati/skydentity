#!/bin/bash

mkdir -p sequential_skydentity
mkdir -p sequential_baseline

python run_skypilot_jobs.py --num-jobs 40 --batch-size 1 --with-skydentity 2>&1 | tee sequential_skydentity/batch_times.txt
mv skypilot_benchmark_std*.txt sequential_skydentity/

sky down -a -y

python run_skypilot_jobs.py --num-jobs 40 --batch-size 1 2>&1 | tee sequential_baseline/batch_times.txt
mv skypilot_benchmark_std*.txt sequential_baseline/

sky down -a -y