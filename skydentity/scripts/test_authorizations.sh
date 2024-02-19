#!/bin/bash
# Example usage: ./test_authorizations.sh -l -r <path to dir containing skydentity repo> -k <path to public key file> -s <path to corresponding secret key> -c <path to key file of service account w/ firestore access> -y <yaml-dir> -p <project id> -t <test script dir>

ROOT=""
CREDS=""
PUBLIC_KEY_PATH=""
SECRET_KEY_PATH=""
CLIENT_ADDRESS=""
YAML_DIR=""
LOCAL=false
PROJECT=""
TEST_SCRIPT_DIR=""
DEFAULT_TEST=true
TEST_SCRIPT="test_server.py"

# 0a. Run server and client proxies.
while getopts "r:c:k:s:y:p:t:l" option; do
  case $option in
    r)
        ROOT=$OPTARG/skydentity
        ;;
    c)
        CREDS=$OPTARG
        ;;
    k)
        PUBLIC_KEY_PATH=$OPTARG
        ;;
    s)
        SECRET_KEY_PATH=$OPTARG
        ;;
    l)
        # local client proxy
        LOCAL=true
        ;;
    y)
        YAML_DIR=$OPTARG
        ;;
    p)
        PROJECT=$OPTARG
        ;;
    t)
        TEST_SCRIPT_DIR=$OPTARG
        DEFAULT_TEST=false
        ;;
    *)
        echo "Usage: test_authorizations.sh -r <root> -c <credentials> -k <public-key-path> -s <private-key-path> -p <gcp-project-id> [-l]"
        exit 1
        ;;
  esac
done

# Clean up previously running client and/or server proxies
pgrep -f "flask run --host=0.0.0.0 --port=5000" | awk '{print $1}' | xargs kill -9
pgrep -f "flask run --host=0.0.0.0 --port=5001" | awk '{print $1}' | xargs kill -9

# Start client proxy
if $LOCAL; then
    # local client proxy
    echo "Running local client proxy as HTTP server..."
    echo $ROOT
    pushd $ROOT/gcp-client-proxy
    ./run_proxy.sh &
    CLIENT_PROCESS=$!
    echo "Client proxy process: $CLIENT_PROCESS"
    popd
    CLIENT_ADDRESS="http://127.0.0.1:5001/"
else
    # serverless client proxy
    pushd $ROOT/gcp-client-proxy
    ./deploy_setup.sh -p $PROJECT
    ./deploy.sh $PROJECT
    CLIENT_ADDRESS=$(gcloud run services list | grep "https://skyidproxy-service")
fi

echo "Client proxy address: $CLIENT_ADDRESS"

# Start server proxy
pushd $ROOT/gcp-server-proxy
SKYID_CLIENT_ADDRESS=$CLIENT_ADDRESS PRIVATE_KEY_PATH=$SECRET_KEY_PATH ./run_proxy_http.sh &
SERVER_PROCESS=$!
echo "Server proxy process: $SERVER_PROCESS"
popd

# Wait for the server and client proxies to start
echo "Waiting for the server and client proxies to start..."
sleep 10

# 0b. Upload skydentity/skydentity/policies/config/auth_policy_example.yaml 
#    to Firestore using upload_policy.py with the --authorization flag
echo "Uploading $YAML_DIR/auth_policy_example.yaml to Firestore..."
python upload_policy.py --policy $YAML_DIR/auth_policy_example.yaml --cloud gcp --public-key $PUBLIC_KEY_PATH --credentials $CREDS --authorization

# 1. Run send_auth_request.py. In skydentity/skydentity/policies/config/skypilot_eval_with_auth.yaml, 
# modify the email address of the service account to match the created one.
echo "Sending auth request..."
python send_auth_request.py --resource_yaml_input="$YAML_DIR/skypilot.yaml" \
    --resource_yaml_output="$YAML_DIR/skypilot_eval_with_auth.yaml"\
    --auth_request_yaml="$YAML_DIR/auth_request_example.yaml" \
    --capability_enc_key="$ROOT/gcp-client-proxy/local_tokens/capability_enc.key"

# 2. Upload skypilot_eval_with_auth.yaml to Firestore using upload_policy.py
echo "Uploading skypilot_eval_with_auth.yaml to Firestore..."
python upload_policy.py --policy $YAML_DIR/skypilot_eval_with_auth.yaml --cloud gcp --public-key $PUBLIC_KEY_PATH --credentials $CREDS

# 3. Run skydentity/python-server/test_server.py.
if $DEFAULT_TEST; then
  echo "Attempting to start VM..."
  pushd $ROOT/python-server
  python $TEST_SCRIPT
  popd
else
  pushd $ROOT/$TEST_SCRIPT_DIR
  python $TEST_SCRIPT
  popd
fi

# 4. Check that the service account attached to the created VM matches the one from step 2.
ATTACHED=$(gcloud compute instances describe gcp-clilib | grep -F3 "serviceAccounts:" | grep "email" | cut -c 10-)
EXPECTED=$(grep -F1 "authorization:" $YAML_DIR/skypilot_eval_with_auth.yaml | tail -1 | cut -c 7-)
echo "Service account attached to the created VM: $ATTACHED. Expected: $EXPECTED."
echo "Remember to delete the created VM!"

# Cleanup
echo "Cleaning up..."
pgrep -f "flask run --host=0.0.0.0 --port=5000" | awk '{print $1}' | xargs kill -9
pgrep -f "flask run --host=0.0.0.0 --port=5001" | awk '{print $1}' | xargs kill -9

rm $YAML_DIR/skypilot_eval_with_auth.yaml
