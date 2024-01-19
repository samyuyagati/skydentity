# Run the proxy locally as an HTTP server:
Run the following:
```
flask run --host="0.0.0.0" --port=5001
```
or
```
./run_proxy_http.sh
```
This will run the proxy at http://localhost:5001.

## Testing
Check that api_endpoint in test_server.py is set to http://127.0.0.1:5001.
```
cd ../python-server
python test_server.py
```

# Run the proxy locally as an HTTPS server:
## Create proxy certificate
Run the following:
```
cd certs
./create_certs.sh 127.0.0.1
```
### MacOS
You may need to manually trust the self-signed root CA (CA\_dir/rootCA.crt) in Keychain.

Next, create a certificate bundle of the root CA certificate and the domain (Skydentity proxy) certificate:
```
cat domain_dir/domain.crt CA_dir/rootCA.crt > ca_certificates.crt
```

Then, copy and combine your Python site package certs with the certs you just created for your proxy.
```
python get_cert_path.py # Prints <CERT_PATH>
cp <CERT_PATH> CA_dir/cacert.pem
cat CA_dir/cacert.pem CA_dir/rootCA.crt > CA_dir/ca_skydentity.pem
```

## Run the proxy
### MacOS
```
cd .. # To serverless-gcp-skydentity
REQUESTS_CA_BUNDLE=certs/CA_dir/ca_skydentity.pem ./run_proxy_https.sh
``` 

### Linux 
You may need to change the certificate path if it is installed elsewhere; you may also need to modify the certificate path in run_proxy_https.sh to `domain_dir/domain.crt`.
```
cd .. # To serverless-gcp-skydentity
REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt ./run_proxy_https.sh
```

## Testing
Check that api_endpoint in test_server.py is set to https://127.0.0.1:5001.

Replace the certificate path with the root CA path from the previous two steps.
```
cd ../python-server
REQUESTS_CA_BUNDLE=../serverless-gcp-skydentity/certs/CA_dir/rootCA.crt python test_server.py
```

