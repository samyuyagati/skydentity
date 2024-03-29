## Running Proxies Locally

### Setup

Certificates need to be created for both proxies (follow instructions in parent folder, running `create_certs.sh` with the appropriate IP addresses).

Additionally, for the client proxy, a service account needs to be created on GCP, and its credentials should be saved. A JSON file should then be created with the service account email and credentials path, as follows:
```json
{
    "email": "service-account-email@project.iam.gserviceaccount.com",
    "credentials": "path/to/service-account-credentials.json"
}
```
The credentials path should be written relative to the `gcp-client-proxy` directory (default `tokens/.cloud_creds/gcp/service_account.json`).

This JSON file is specified with the `SERVICE_ACCOUNT_INFO_FILE` environment variable (see `run_proxy.sh`), and by default is `tokens/.cloud_creds/gcp/service_account.json` (relative to the `gcp-client-proxy` directory).


### Running proxies

(Note that these commands are only tested for Linux.)

To run the server proxy,
```sh
cd gcp-server-proxy
REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt ./run_proxy.sh
```
Change the path of the certificates if it is different on your system (this certificate bundle should include the self-signed certificates for the proxies).

To run the client proxy,
```sh
cd gcp-client-proxy
REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt ./run_proxy.sh
```

When running SkyPilot commands, you should have an `.env` file with the following:
```sh
CLOUDSDK_API_ENDPOINT_OVERRIDES_COMPUTE="https://127.0.0.1:5000/"
```


### mitmproxy

If you have mitmproxy, you will need to add the following to your `.env` file:
```sh
CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE="/etc/ssl/certs/ca-certificates.crt"
REQUESTS_CA_BUNDLE="/etc/ssl/certs/ca-certificates.crt"
HTTPLIB2_CA_CERTS="/etc/ssl/certs/ca-certificates.crt"

CLOUDSDK_PROXY_ADDRESS="127.0.0.1"
CLOUDSDK_PROXY_PORT="8080"
CLOUDSDK_PROXY_TYPE="http"

http_proxy="http://127.0.0.1:8080/"
https_proxy="http://127.0.0.1:8080/"
```
You may need to change the port of the proxy to match the mitmproxy port, and the certificates would need to be changed to match your system certificates file (with the generated self-signed certificates for the proxies).

Additionally, mitmproxy will need to be run with the `-k` flag (equivalently `--ssl-insecure`) to disable SSL verification.

## Running SkyPilot

To run SkyPilot with the above configuration, you can run
```sh
env $(cat .env | xargs) sky <command>
```
This will take the contents of the `.env` file, and run the SkyPilot commands with those environment variables set.
