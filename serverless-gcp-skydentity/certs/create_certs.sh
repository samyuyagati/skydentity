#!/bin/bash

CA_DIR="CA_dir"
PROXY_DIR="domain_dir"
CONFIG_DIR="configs"

# First argument should be string IP addr of proxy (e.g., "34.168.128.47")
python config_domain.py $1

# Create and self-sign root CA
openssl req -config $CONFIG_DIR/rootCA.cnf -x509 -sha256 -days 1825 -newkey rsa:2048 -nodes -keyout $CA_DIR/rootCA.key -out $CA_DIR/rootCA.crt

# Create proxy CSR
openssl req -config $CONFIG_DIR/domain.cnf -newkey rsa:2048 -nodes -keyout $PROXY_DIR/domain.key -out $PROXY_DIR/domain.csr

# Use root CA key to sign proxy CSR
openssl x509 -req -CA $CA_DIR/rootCA.crt -CAkey $CA_DIR/rootCA.key -in $PROXY_DIR/domain.csr -out $PROXY_DIR/domain.crt -days 365 -CAcreateserial -extfile $CONFIG_DIR/domain.ext

# Trust root CA locally
# For Mac 
echo "Please enter your administrator password to trust your newly-created root CA certificate."
sudo security add-trusted-cert \
  -d \
  -r trustAsRoot \
  -k /Library/Keychains/System.keychain \
  $CA_DIR/rootCA.crt

# For Ubuntu
#sudo cp rootCA.crt /usr/local/share/ca-certificates/
#sudo update-ca-certificates
