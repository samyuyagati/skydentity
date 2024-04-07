#!/bin/bash

# Usage: ./test_load_baseline.sh <path to service acct key that can create VMs>

python run_experiment.py --credentials $1 --num-requests $2 --concurrent --delete
