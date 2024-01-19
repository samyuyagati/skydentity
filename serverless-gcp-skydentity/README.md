# Run the proxy locally as an HTTP server:
Run the following:
```
flask run --host="0.0.0.0" --port=5001
```
This will run the proxy at http://localhost:5001.

# Run the proxy locally as an HTTPS server:
## Create proxy certificate
Run the following:
```
cd certs
./create_certs.sh 127.0.0.1
```
MacOS:
You may need to manually trust the self-signed root CA (CA\_dir/rootCA.crt) in Keychain.

Next, create a certificate bundle of the root CA certificate and the domain (Skydentity proxy) certificate:
```
cat domain_dir/domain.crt CA_dir/rootCA.crt > ca_certificates.crt
```

Then, copy and combine your Python site package certs with the certs you just created for your proxy.
```
cp /usr/local/lib/python3.11/site-packages/certifi/cacert.pem CA_dir
cat CA_dir/cacert.pem CA_dir/rootCA.crt > CA_dir/ca_skydentity.pem
```

## Run the proxy
MacOS:
```
cd .. # To serverless-gcp-skydentity
REQUESTS_CA_BUNDLE=certs/CA_dir/ca_skydentity.pem ./run_proxy.sh
``` 

Linux (you may need to change the certificate path if it is installed elsewhere):
```
cd .. # To serverless-gcp-skydentity
REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt ./run_proxy.sh
```

# Testing
Replace the certificate path with the root CA path from the previous two steps.
```
cd ../python-server
REQUESTS_CA_BUNDLE=../serverless-gcp-skydentity/certs/CA_dir/rootCA.crt python test_server.py
```

