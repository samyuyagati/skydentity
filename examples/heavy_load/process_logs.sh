#!/bin/bash

# Get logs
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=skyidproxy-service AND severity=DEBUG" --project sky-identity --limit $1 > logs.txt

# Process logs
python process_logs.py --authorizer-logs logs.txt --rt-logs laptop_rt_time_logs.txt --plots-dir $2