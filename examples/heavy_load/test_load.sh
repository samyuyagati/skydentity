#!/bin/bash

# Usage: ./test_end_to_end.sh <path-to-firebase-creds>

mkdir -p keys
if ! [ -f keys/public.pem ]; then
  python gen_key_pair.py
fi


ROOT=$(dirname $(dirname $(dirname $(pwd))))
echo "Root: $ROOT" 
pushd $ROOT/skydentity/skydentity/scripts
./test_authorizations.sh -r $ROOT \
                            -k $ROOT/skydentity/examples/heavy_load/keys/public.pem \
                            -s $ROOT/skydentity/examples/heavy_load/keys/private.pem \
                            -t $ROOT/skydentity/examples/heavy_load
                            -c $1 -y $ROOT/skydentity/examples/heavy_load/config 
popd
