#!/usr/bin/env bash

CA_DIR="root-ca"
CONFIG_DIR="config"
ROOT_CA_NAME="skydentity-root-ca"

# output directory for the proxy certificates
PROXY_DIR="${1:-proxy}"

# Ensure proxy directory exists for outputs
mkdir -p "$PROXY_DIR"

# Configure the templates used for the proxy certs;
# default to 127.0.0.1 if not given
PROXY_IP=${2:-127.0.0.1}
echo "Configuring leaf certificate with IP $PROXY_IP"
python3 config_domain.py "$PROXY_IP"

# Create proxy CSR
openssl req \
    -config $CONFIG_DIR/proxy.cnf \
    -newkey rsa:2048 \
    -nodes \
    -keyout "$PROXY_DIR/proxy.key" \
    -out "$PROXY_DIR/proxy.csr"

# Use root CA key to sign proxy CSR
openssl x509 \
    -req \
    -CA $CA_DIR/${ROOT_CA_NAME}.crt \
    -CAkey $CA_DIR/${ROOT_CA_NAME}.key \
    -days 365 \
    -CAcreateserial \
    -extfile $CONFIG_DIR/proxy.ext \
    -in "$PROXY_DIR/proxy.csr" \
    -out "$PROXY_DIR/proxy.crt"

# Remove CSR now that it has been signed
rm "$PROXY_DIR/proxy.csr"

echo "Proxy certificate is now at '$PROXY_DIR/proxy.crt', with key at '$PROXY_DIR/proxy.key'"
