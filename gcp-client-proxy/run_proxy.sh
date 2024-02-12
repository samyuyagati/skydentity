#!/bin/bash

# service account information;
# JSON file containing an "email" key and a "cred_filename" key
export SERVICE_ACCOUNT_INFO_FILE="tokens/.cloud_creds/gcp/service_account.json"
# official compute api endpoint
export COMPUTE_API_ENDPOINT="https://compute.googleapis.com/"

# certificate information
export CERT_FILE="certs/domain_dir/domain.crt"
export CERT_KEY="certs/domain_dir/domain.key"

flask run --host="0.0.0.0" --port=5001 --cert=$CERT_FILE --key=$CERT_KEY
