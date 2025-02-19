#!/bin/env sh

SKYID_CLIENT_ADDRESS="https://skyidproxy-storage-service-ozttcth4mq-uw.a.run.app/" \
    PRIVATE_KEY_PATH="../examples/aether/keys/gcp-private.pem" \
    PORT=5000 \
    ./run_proxy_http.sh
