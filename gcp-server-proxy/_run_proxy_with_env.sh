#!/usr/bin/env bash

SKYID_CLIENT_ADDRESS="http://127.0.0.1:5001" \
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    PRIVATE_KEY_PATH=../examples/terraform/keys/private.pem \
    ./run_proxy_http.sh
