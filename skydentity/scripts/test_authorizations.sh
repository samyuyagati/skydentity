#!/bin/bash
ROOT=""
HOME=""
CREDS=""
SKYID_CLIENT_ADDRESS=""
LOCAL=false

# 0a. Run server and client proxies.
while getopts "r:c:l" option; do
  case $option in
    r)
        HOME=$OPTARG
        ROOT=$OPTARG/skydentity
        ;;
    c)
        CREDS=$OPTARG
        ;;
    l)
        # local client proxy
        LOCAL=true
        ;;
    *)
        echo "Usage: test_authorizations.sh -r <root> -c <credentials> [-l]"
        exit 1
        ;;
  esac
done

if [ $LOCAL ]; then
    # local client proxy
    echo "Running local client proxy"
    echo $ROOT
    pushd $ROOT/serverless-gcp-skydentity
    ./run_proxy_http.sh 
    popd
    SKYID_CLIENT_ADDRESS="http://127.0.0.1:5001/"
else
    # serverless client proxy
    $ROOT/serverless-gcp-skydentity/deploy_setup.sh
    $ROOT/serverless-gcp-skydentity/deploy.sh
    SKYID_CLIENT_ADDRESS=$(gcloud run services list | grep "https://skyidproxy-service")
fi

echo "Client proxy address: $SKYID_CLIENT_ADDRESS"
pushd $ROOT/gcp-server-proxy
./run_proxy_http.sh 
popd

# 0b. Upload skydentity/skydentity/policies/config/auth_policy_example.yaml 
#    to Firestore using upload_policy.py with the --authorization flag
python upload_policy.py --policy $ROOT/skydentity/policies/config/auth_policy_example.yaml --cloud gcp --public-key skypilot_eval --credentials $CREDS --authorization

# 1. Run send_auth_request.py. In skydentity/skydentity/policies/config/skypilot_eval_with_auth.yaml, 
# modify the email address of the service account to match the created one.
python send_auth_request.py --resource_yaml_input="$ROOT/skydentity/policies/config/skypilot_eval.yaml" \
    --resource_yaml_output="$ROOT/skydentity/policies/config/skypilot_eval_with_auth.yaml" \
    --auth_request_yaml="$ROOT/skydentity/policies/config/auth_request_example.yaml" \
    --capability_enc_key="$HOME/.cloud_creds/gcp/proxy-enc/capability_enc.key"

# 2. Upload skypilot_eval_with_auth.yaml to Firestore using upload_policy.py
python upload_policy.py --policy $ROOT/skydentity/policies/config/skypilot_eval_with_auth.yaml --cloud gcp --public-key skypilot_eval --credentials $CREDS

# 3. Run skydentity/python-server/test_server.py.
python $ROOT/python-server/test_server.py

# 4. Check that the service account attached to the created VM matches the one from step 2.
ATTACHED=$(gcloud compute instances describe gcp-clilib | grep -F3 "serviceAccounts:" | grep "email" | cut -c 10-)
EXPECTED=$(grep -F1 "authorization:" ../policies/config/skypilot_eval_with_auth.yaml | tail -1 | cut -c 7-)
echo "Service account attached to the created VM: $ATTACHED. Expected: $EXPECTED."