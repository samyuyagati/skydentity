#!/usr/bin/env bash

CA_DIR="root-ca"
CONFIG_DIR="config"

ROOT_CA_NAME="skydentity-root-ca"

# Ensure CA directory exists for outputs
mkdir -p $CA_DIR

# Create and self-sign root CA
openssl req \
    -config $CONFIG_DIR/root-ca.cnf \
    -x509 \
    -sha256 \
    -days 1825 \
    -newkey rsa:2048 \
    -nodes \
    -keyout $CA_DIR/${ROOT_CA_NAME}.key \
    -out $CA_DIR/${ROOT_CA_NAME}.crt

# Trust root CA locally
echo "Please enter your administrator password to trust your newly-created root CA certificate."
if [[ "$OSTYPE" == "darwin"* ]]; then
    # For Mac
    sudo security add-trusted-cert \
        -d \
        -r trustAsRoot \
        -k /Library/Keychains/System.keychain \
        $CA_DIR/${ROOT_CA_NAME}.crt
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # For Ubuntu
    sudo cp $CA_DIR/${ROOT_CA_NAME}.crt /usr/local/share/ca-certificates/
    sudo update-ca-certificates
else
    # unknown
    echo "Unknown OS type; root CA certificates are not trusted"
    exit 1
fi
