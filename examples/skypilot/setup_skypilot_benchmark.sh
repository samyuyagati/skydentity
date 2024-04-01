# Usage: ./setup_skypilot_benchmark.sh <path-to-firebase-creds>

mkdir -p keys
if ! [ -f keys/public.pem ]; then
  python gen_key_pair.py
fi

FIREBASE_CREDS=$1

ROOT=$(dirname $(dirname $(dirname $(pwd))))
echo "Root: $ROOT"
# Setup authorizations and start servers
echo "Setting up authorizations..."
./start_proxies_and_setup_auth.sh -l -r $ROOT \
                         -p "sky-identity" \
                         -k $ROOT/skydentity/examples/skypilot/keys/public.pem \
                         -s $ROOT/skydentity/examples/skypilot/keys/private.pem \
                         -c $FIREBASE_CREDS -y $ROOT/skydentity/examples/skypilot/config 