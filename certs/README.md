# Generating certificates for HTTPS proxies

In order to run the proxies on an HTTPS connection, self-signed certificates must be generated.

The scripts in this folder help with generating a self-signed root CA, along with leaf certificates to be used for each proxy.

To generate the root CA and trust the certificate locally, run

```sh
./create_ca_cert.sh
```

This will create a new file in `./root-ca/skydentity-root-ca.crt` containing the new root CA certificate, along with its key at `./root-ca/skydentity-root-ca.key`.

To use this root CA to sign additional certificates for each proxy, run

```sh
./create_proxy_cert.sh <PROXY_CERTS_DIR> <IP_ADDR>
```

Fill in `<PROXY_CERTS_DIR>` with the directory that the certificate and key should be written to. By default, if omitted, outputs are written to the `./proxy` directory.

Fill in `<IP_ADDR>` with the IP address of the proxy. Typically, if running the proxy locally, this will be `127.0.0.1`, which is the default (so the argument can be omitted).

This script will generate a new `proxy.crt` file containing the leaf certificate signed by our new root CA, along with its key at `proxy.key`.

To generate certificates for each of the proxies in this repository, run the following:

```sh
./create_proxy_cert.sh ../azure-client-proxy/certs
./create_proxy_cert.sh ../azure-server-proxy/certs
./create_proxy_cert.sh ../gcp-client-proxy/certs
./create_proxy_cert.sh ../gcp-server-proxy/certs
```

(Add the relevant IP address as the second argument if required.)
