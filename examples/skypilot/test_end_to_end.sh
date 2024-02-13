#!/bin/bash

# Usage: ./test_end_to_end.sh <path-to-firebase-creds>

ROOT=$(dirname $(dirname $(dirname $(pwd))))
echo "Root: $ROOT" 
pushd $ROOT/skydentity/skydentity/scripts
./test_authorizations.sh -l -r $ROOT \
                            -p $ROOT/skydentity/examples/skypilot/keys/public.pem \
                            -s $ROOT/skydentity/examples/skypilot/keys/private.pem \
                            -c $1 -y $ROOT/skydentity/examples/skypilot/config 
popd
