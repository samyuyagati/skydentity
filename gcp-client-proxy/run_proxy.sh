#!/bin/bash

# service account information;
# JSON file containing an "email" key and a "cred_filename" key
export SERVICE_ACCOUNT_INFO_FILE="tokens/.cloud_creds/gcp/service_account.json"
# official compute api endpoint
export COMPUTE_API_ENDPOINT="https://compute.googleapis.com/"
# capability encoding key
export CAPABILITY_ENC_KEY_FILE="local_tokens/capability_enc.key"

# Default to HTTP
SECURE=false

while getopts "si" option; do
  case $option in
    i)
        echo "Encountered flag i"
        # Insecure (HTTP)
        SECURE=false
        ;;
    s)
        echo "Encountered flag s"
        # Secure (HTTPS)
        SECURE=true
        # certificate information
        export CERT_FILE="certs/domain_dir/domain.crt"
        export CERT_KEY="certs/domain_dir/domain.key"
        ;;
    *)
        echo "Usage: run_proxy.sh [-s]" 
        exit 1
        ;;
  esac
done

echo "SECURE: $SECURE"

if $SECURE; then
    # HTTPS
    echo "Running local client proxy as HTTPS server..."
    flask run --host="0.0.0.0" --port=5001 --cert=$CERT_FILE --key=$CERT_KEY
else
    # HTTP
    echo "Running local client proxy as HTTP server..."
    flask run --host="0.0.0.0" --port=5001
fi
