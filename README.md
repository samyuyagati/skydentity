# skydentity
SkyIdentity is a proxy built to handle VM request permissions. It removes the need for brokers to have access to cloud credentials forcing them to make requests through the proxy, which can accept or reject those requests. The proxy creates VMs with the minimum permissions necessary to complete the requested job, which are enforced by existing cloud IAM systems.

# How to Configure and Run the Proxy
1. Install dependencies and activate the virutal environment
   ```
   ./install_deps.sh
   ```
   To activate or re-activate the virtual environment, run
   ```
   source skyid/bin/activate
   ```
2. Optionally, you may verify that your system works correctly by testing with the `provision_gcp_vm.py` and/or `provision_azure_vm.py` scripts using your cloud account credentials
3. To run the proxy, first run the cloud specific setup script (`setup.sh`), if it exists 
4. Generate certificates
   ```
   ./certs/create_certs.sh PROXY_IP_ADDRESS
   ```
   replacing PROXY_IP_ADDRESS with a string IP address of the proxy, i.e. "127.0.0.1".

   If you are on Ubuntu, comment out the "For Mac" section of `create_certs.sh` and uncomment the "For Ubuntu" section first.

   You may run into an issue where you are not prompted for a password leading to a failure on the "add-trusted-cert" step. To resolve this issue on Mac:
      1. Open KeychainAccess
      2. Navigate to the login keychain and open the certificates tab
      3. Drag `skydentity/serverless-gcp-skydentity/acerts/CA_dir/rootCA.crt` into the list of certificates
      4. Control click on the newly added certificate
      5. Change SSL setting to "Always trust"
      6. Close KeychainAccess and enter password when prompted to save changes
5. To run the proxy locally
   ```
   ./run_proxy.sh
   ```
6. Or to deploy the proxy to run as a serverless function
   ```
   ./deploy.sh
   ```
   See the section "Making the Proxy Serverless" below for information about how to setup serverless deployment for the first time.
7. To test the proxy, you may start a test server which will send API requests that should be intercepted by the running proxy. You may need to update user-specific credential and certification
      directories in the cloud specific flask app (i.e. CREDS_PATH in `serverless-gcp-skydentity/app.py` and CERT_DIR in `python-server/run_app.py` for gcp).
   ```
   cd ../python-server
   ./run_test_server.sh
   ```

# How to Create a Proxy for a New Cloud
1. Update `requirements.txt` with new cloud-specific requirements and re-run `install_deps.sh`
2. Optionally, use the new cloud's Python SDK to write a script similar to `provision_gcp_vm.py` and `provision_azure_vm.py` that creates a VM using a personal account to verify that dependencies are correctly installed.
3. Create a flask app to proxy requests to relevant endpoints used to create vms in the new cloud. For example, `serverless-gcp-skydentity/app.py` is the flask app proxying gcp vm creation requests.
4. If the cloud requires additional environment setup beyond the dependencies installed through `requirements.txt`, optionally add a `setup.sh` script (can also be used to activate the virtual environment).


# Making the Proxy Serverless
1. First identify the right service for deploying your flask app (cloud specific, i.e. Azure Functions)
2. Create a service account or appropriate role for the proxy to use.
3. Save the new service account key to a local path (i.e. `tokens/.cloud_creds/gcp/<token_id>.json` for gcp)
4. Create two deployment scripts: one to setup the proxy for deployment, and the other to deploy it.
   1. The setup script should add the service account secret key and the domain cert private key to your cloud's secrets store and create the build image. See `serverless-gcp-skydentity/deploy_setup.sh` for an example. To check if a secret already exists in gcp, use `gcloud secrets versions access version-id --secret="secret-id" --out-file="path/to/secret"` and modify the setup script according to whether or not a given secret needs to be added.
   2. The deployment script should run the build created in the previous step using the provided service account and credentials. See `serverless-gcp-skydentity/deploy.sh` for an example.
5. If possible, create a Dockerfile (or even better, reuse a single shared Dockerfile i.e. the existing Dockerfile in the project root) to dockerize the proxy. Make sure that your chosen cloud service has an option to mount volumes in order to deploy secrets with your container.
   
