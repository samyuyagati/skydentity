#!/bin/bash

source ../serverless-gcp-skydentity/skyid/bin/activate
export REQUESTS_CA_BUNDLE="/home/samyu/skydentity/certs/skyidcert.crt"
python test_server.py
