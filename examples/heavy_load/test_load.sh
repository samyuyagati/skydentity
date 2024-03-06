#!/bin/bash

# Usage: ./test_load.sh <path-to-firebase-creds> <# instance reqs to send>

mkdir -p keys
if ! [ -f keys/public.pem ]; then
  python gen_key_pair.py
fi

FIREBASE_CREDS=$1
NUM_REQUESTS=$2

ROOT=$(dirname $(dirname $(dirname $(pwd))))
echo "Root: $ROOT"
# Setup authorizations and start servers
echo "Setting up authorizations..."
./setup_authorization.sh -l -r $ROOT \
                         -k $ROOT/skydentity/examples/heavy_load/keys/public.pem \
                         -s $ROOT/skydentity/examples/heavy_load/keys/private.pem -p "sky-identity" \
                         -c $FIREBASE_CREDS -y $ROOT/skydentity/examples/heavy_load/config 

# Run test_server.py
python test_server.py --num-requests $NUM_REQUESTS --api-endpoint "http://127.0.0.1:5000/"

# Clean up
echo "Cleaning up..."
pgrep -f "flask run --host=0.0.0.0 --port=5000" | awk '{print $1}' | xargs kill -9
pgrep -f "flask run --host=0.0.0.0 --port=5001" | awk '{print $1}' | xargs kill -9

rm config/skypilot_eval_with_auth.yaml
