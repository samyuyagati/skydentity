#!/bin/bash

python3 -m flask run --host="0.0.0.0" --port=5000 --cert=../serverless-gcp-skydentity/certs/domain_dir/domain.crt --key=../serverless-gcp-skydentity/certs/domain_dir/domain.key

