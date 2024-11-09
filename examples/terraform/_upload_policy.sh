#!/usr/bin/env bash

set -x

# upload authorization policy
python3 ../../skydentity/scripts/upload_policy.py \
    --policy ./config/auth_policy_example.yaml \
    --cloud gcp \
    --public-key ./keys/public.pem \
    --credentials ../../tokens/gcp/sky-identity_test-proxy-account.json \
    --authorization

# send auth request
python3 ../../skydentity/scripts/send_auth_request.py \
    --resource_yaml_input ./config/terraform.yaml \
    --resource_yaml_output ./config/terraform_with_auth.yaml \
    --auth_request_yaml ./config/auth_request_example.yaml \
    --capability_enc_key ../../gcp-client-proxy/local_tokens/capability_enc.key \
    --cloud gcp

# upload policy with authorization
python3 ../../skydentity/scripts/upload_policy.py \
    --policy ./config/terraform_with_auth.yaml \
    --cloud gcp \
    --public-key ./keys/public.pem \
    --credentials ../../tokens/gcp/sky-identity_test-proxy-account.json \
