#!/bin/bash
CA_CERT="../serverless-gcp-skydentity/certs/CA_dir/rootCA.crt"
source ../serverless-gcp-skydentity/skyid/bin/activate
env REQUESTS_CA_BUNDLE=$CA_CERT SSL_CERT_FILE=$CA_CERT bash -c 'python3 test_server.py'
