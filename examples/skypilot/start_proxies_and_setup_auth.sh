#!/bin/bash
# Example usage: ./test_authorizations.sh -l -m <URL of VM-based proxy> -r <path to dir containing skydentity repo> -k <path to public key file> -s <path to corresponding secret key> -c <path to key file of service account w/ firestore access> -y <yaml-dir> -p <project id>

ROOT=""
CREDS=""
PUBLIC_KEY_PATH=""
SECRET_KEY_PATH=""
CLIENT_ADDRESS=""
YAML_DIR=""
LOCAL=false
PROJECT=""
VM_PROXY=""

# 0a. Run server and client proxies.
while getopts "r:m:c:k:s:y:p:l" option; do
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
    m)
        VM_PROXY=$OPTARG
        echo "VM-based client proxy address: $VM_PROXY"
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
elif [ "" != "$VM_PROXY" ]; then
    # VM-based client proxy
    echo "Expect client proxy to be running at $VM_PROXY"
    CLIENT_ADDRESS="$VM_PROXY"
elif [[ $(gcloud run services list | grep "skyidproxy-service" | wc -l) -eq 0 ]]; then
    # serverless client proxy
    pushd $ROOT/gcp-client-proxy/serverless
    ./deploy_setup.sh -p "$PROJECT" 
    ./deploy.sh $PROJECT
    CLIENT_ADDRESS=$(gcloud run services list | grep "https://skyidproxy-service" | awk '{ print $4 }')
    CLIENT_ADDRESS="$CLIENT_ADDRESS/"
else
    echo "Serverless client proxy is already running."
    CLIENT_ADDRESS=$(gcloud run services list | grep "https://skyidproxy-service" | awk '{ print $4 }')
    CLIENT_ADDRESS="$CLIENT_ADDRESS/"
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
pushd $ROOT/skydentity/scripts
echo "Uploading $YAML_DIR/auth_policy_example.yaml to Firestore..."
time python upload_policy.py --policy $YAML_DIR/auth_policy_example.yaml --cloud gcp --public-key $PUBLIC_KEY_PATH --credentials $CREDS --authorization

# 1. Run send_auth_request.py. In skydentity/skydentity/policies/config/skypilot_eval_with_auth.yaml, 
# modify the email address of the service account to match the created one.
echo "Sending auth request..."
time python send_auth_request.py --resource_yaml_input="$YAML_DIR/skypilot.yaml" \
    --resource_yaml_output="$YAML_DIR/skypilot_eval_with_auth.yaml"\
    --auth_request_yaml="$YAML_DIR/auth_request_example.yaml" \
    --capability_enc_key="$ROOT/gcp-client-proxy/local_tokens/capability_enc.key"

# 2. Upload skypilot_eval_with_auth.yaml to Firestore using upload_policy.py
echo "Uploading skypilot_eval_with_auth.yaml to Firestore..."
time python upload_policy.py --policy $YAML_DIR/skypilot_eval_with_auth.yaml --cloud gcp --public-key $PUBLIC_KEY_PATH --credentials $CREDS
popd