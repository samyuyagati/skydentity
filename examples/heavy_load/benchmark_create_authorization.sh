#!/bin/bash

mkdir -p keys
if ! [ -f keys/public.pem ]; then
  python gen_key_pair.py
fi

FIREBASE_CREDS=$1

ROOT=$(dirname $(dirname $(dirname $(pwd))))
echo "Root: $ROOT"
# Setup authorizations and start servers

echo "Setting up authorizations $num..."
time ./setup_authorization.sh -r $ROOT \
                         -k $ROOT/skydentity/examples/heavy_load/keys/public.pem \
                         -s $ROOT/skydentity/examples/heavy_load/keys/private.pem -p "sky-identity" \
                         -c $FIREBASE_CREDS -y $ROOT/skydentity/examples/heavy_load/config 2>&1 > logs/setup_authorization_$num.txt