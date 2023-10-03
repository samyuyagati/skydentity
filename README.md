# skydentity
SkyIdentity is a proxy built to handle VM request permissions. It removes the need for brokers to have access to cloud credentials forcing them to make requests through the proxy, which can accept or reject those requests. The proxy creates VMs with the minimum permissions necessary to complete the requested job, which are enforced by existing cloud IAM systems.

# How to Configure and Run the Proxy
1. Generate a self-signed certificate (TODO: Is this necessary in addition to create_certs.sh in serverless-gcp-skydentity folder?)
   ```
   cd certs
   ./gen_self_signed_certs.sh
   ```
2. Install dependencies and activate the virutal environment
   ```
   cd ..
   ./install_deps.sh
   ```
   To re-activate the virtual environment, run
   ```
   source ENV_NAME/bin/activate
   ```
   where ENV_NAME is dependent on the cloud, i.e. gcp-env
3. Optionally, you may verify that your system works correctly by testing with the provision_gcp_vm.py and/or provision_azure_vm.py scripts using your cloud account credentials
4. To run the proxy, first run the cloud specific setup script 
   ```
   cd serverless-gcp-skydentity
   ./setup.sh
   ```
5. Generate certificates
   ```
   ./certs/create_certs.sh PROXY_IP_ADDRESS
   ```
   replacing PROXY_IP_ADDRESS with a string IP address of the proxy, i.e. "127.0.0.1".

   You may run into an issue where you are not prompted for a password leading to a failure on the "add-trusted-cert" step. To resolve this issue on Mac:
      1. Open KeychainAccess
      2. Navigate to the login keychain and open the certificates tab
      3. Drag skydentity/serverless-gcp-skydentity/acerts/CA_dir/rootCA.crt into the list of certificates
      4. Control click on the newly added certificate
      5. Change SSL setting to "Always trust"
      6. Close KeychainAccess and enter password when prompted to save changes
6. To run the proxy locally
   ```
   ./run_proxy.sh
   ```
7. Or to deploy the proxy to run as a serverless function
   ```
   ./deploy.sh
   ```
8. To test the proxy, you may start a test server which will send API requests that should be intercepted by the running proxy. You may need to update user-specific credential and certification
      directories in app.py and run_app.py (i.e. CREDS_PATH and CERT_DIR in app.py and cert_dir in run_app.py).
   ```
   cd ../python-server
   ./run_test_server.sh
   ```

# How to Create a Proxy for a New Cloud
1. Update requirements.txt with new cloud-specific requirements and re-run install_deps.sh
2. Optionally, use the new cloud's Python SDK to write a script similar to provision_gcp_vm.py and provision_azure_vm.py that creates a VM using a personal account to verify that dependencies are correctly installed.
3. Create a flask app to proxy requests to relevant endpoints used to create vms in the new cloud
4. If the cloud requires additional environment setup beyond the dependencies installed through requirements.txt, optionally ad a setup.sh script (can also be used to activate the virtual environment).
5. Make the flask app serverless
   To do so:
   1. First identify the right service for deploying your flask app (cloud specific, i.e. Azure Functions)
   2. If possible, create a Dockerfile to dockerize the proxy. Make sure that your chosen cloud service has an option to mount volumes in order to deploy secrets with your container.
   3. Create a deploy.sh script using documentation for your chosen cloud and serverless function
   
