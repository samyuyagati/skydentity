python3 send_auth_request.py \
    --resource_yaml_input ../../examples/skypilot/config/skypilot.yaml \
    --resource_yaml_output ../../examples/skypilot/config/skypilot_with_auth.yaml \
    --auth_request_yaml ../../examples/skypilot/config/auth_request_example.yaml \
    --capability_enc_key ../../gcp-client-proxy/local_tokens/capability_enc.key
