#!/bin/bash
CA_CERT="../serverless-gcp-skydentity/certs/CA_dir/rootCA.crt"
env REQUESTS_CA_BUNDLE=/opt/az/lib/python3.10/site-packages/certifi/skydentity.pem SSL_CERT_FILE=$CA_CERT bash -c 'python3 azure_test_server.py'
