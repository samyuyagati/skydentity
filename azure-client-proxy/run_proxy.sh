#!/bin/bash

# service account information;
# official compute api endpoint
export COMPUTE_API_ENDPOINT="https://management.azure.com/"
# capability encoding key
export CAPABILITY_ENC_KEY_FILE="local_tokens/capability_enc.key"
# db endpoint
if [ -z "$AZURE_DB_ENDPOINT" ]; then
    export AZURE_DB_ENDPOINT=""
fi

# db key
if [ -z "$AZURE_DB_KEY" ]; then
    export AZURE_DB_KEY=""
fi

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
