#!/usr/bin/env bash

REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    PUBLIC_KEY_PATH=../examples/terraform/keys/public.pem \
    ./run_proxy.sh
