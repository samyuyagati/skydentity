#!/bin/bash

flask run --host="0.0.0.0" --port=5001 --cert=certs/ca_certificates.crt --key=certs/domain_dir/domain.key
