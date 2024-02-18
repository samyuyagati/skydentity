#!/bin/bash
#
export CERT_FILE="certs/domain_dir/domain.crt"
export CERT_KEY="certs/domain_dir/domain.key"

flask run --host="0.0.0.0" --port=5000 --cert=$CERT_FILE --key=$CERT_KEY
