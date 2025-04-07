#!/bin/bash

export CAPABILITY_FILE="./tokens/capability.json"

export CERT_FILE="./certs/proxy.crt"
export CERT_KEY="./certs/proxy.key"

flask run --host="0.0.0.0" --port=5000 --cert=$CERT_FILE --key=$CERT_KEY
