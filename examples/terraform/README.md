# Terraform Integration

## Proxies

To run the client proxy, within `gcp-client-proxy`, run
```sh
PUBLIC_KEY_PATH=../examples/terraform/keys/public.pem \
    ./run_proxy.sh
```
The client proxy must have credentials to access cloud resources; if you've logged out of your `gcloud` CLI, then you must provide service account credentials here through an environment variable:
```sh
GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account-credentials.json \
    PUBLIC_KEY_PATH=../examples/terraform/keys/public.pem \
    ./run_proxy.sh
```

To run the server proxy, within `gcp-server-proxy`, run
```sh
SKYID_CLIENT_ADDRESS="http://127.0.0.1:5001" \
    PRIVATE_KEY_PATH=../examples/terraform/keys/private.pem \
    ./run_proxy_http.sh
```
To fully emulate a real environment, the server proxy should not have any credentials to access cloud resources; if you've logged out of your `gcloud` CLI, then you should provide a valid service account credential with no permissions:
```sh
GOOGLE_APPLICATION_CREDENTIALS=/path/to/no-access-credentials.json \
    SKYID_CLIENT_ADDRESS="http://127.0.0.1:5001" \
    PRIVATE_KEY_PATH=../examples/terraform/keys/private.pem \
    ENABLE_GCP_LOGGING=0 \
    ./run_proxy_http.sh
```
The `ENABLE_GCP_LOGGING=0` configuration disables GCP logging from being set up and used throughout the server proxy; by default, the proxy will try to set up logging via GCP, but this will error if the active account does not have permissions.

## Terraform

The terraform project should be set up as follows:
1. Copy `main.tf` within `examples/terraform/starter-code/` to a new directory where you will be running terraform
2. Copy `startup.sh` within `examples/terraform/starter-code/` to the same terraform directory
3. Run `terraform init` to initialize terraform within the new project
4. Run `terraform validate` to make sure that the configuration is valid
5. Create a file to store the following environment variables:


### Running Terraform

Any terraform calls made should utilize the following environment variables:
```sh
GOOGLE_APPLICATION_CREDENTIALS="/path/to/credentials/with/no/access"
GOOGLE_COMPUTE_CUSTOM_ENDPOINT="http://127.0.0.1:5000/compute/v1/"
```
Note that the credentials given in `GOOGLE_APPLICATION_CREDENTIALS` must be valid (since terraform will request an access token using these credentials, and there isn't an endpoint override for OAuth2).
There's a service account named `no-access` within the `SkyIdentity` project that should suffice---it has no permissions granted to it. To ensure that the terraform commands do not get any valid credentials, it can be good to log out of `gcloud` as well.

To send a terraform request to create the VM, utilizing this configuration, you can run
```sh
GOOGLE_APPLICATION_CREDENTIALS="/path/to/credentials/with/no/access" \
    GOOGLE_COMPUTE_CUSTOM_ENDPOINT="http://127.0.0.1:5000/compute/v1/" \
    terraform apply
```
Alternatively, it is recommended that you put these environment variables into a file, so that you don't have to write out everything each time:
```sh
env $(cat /path/to/env | xargs) terraform apply
```

The proxy currently only supports resource creation, so any other requests should use credentials for an account that does have full permissions; just replace the path in `GOOGLE_APPLICATION_CREDENTIALS`.

