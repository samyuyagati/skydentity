# skydentity

# Notes
To test proxy locally, pass localhost ip to create_certs.sh (i.e. ./create_certs.sh "127.0.0.1")

# Setup issues + fixes
1. create_certs.sh doesn't prompt you for a password and fails the add-trusted-cert step on line 26
   -To fix:
     1. Open KeychainAccess
     2. Navigate to the login keychain and open the certificates tab
     3. Drag skydentity/serverless-gcp-skydentity/acerts/CA_dir/rootCA.crt into the list of certificates
     4. Control click on the newly added certificate
     5. Change SSL setting to "Always trust"
     6. Close KeychainAccess and enter password when prompted to save changes
2. run_proxy.sh Bad interpreter error
   -To fix:
     1. Check skyid/bin/flask and see if the first line hardcodes the interpreter path to samyu's local path
     2. If so, replace with your local path
3. run_proxy.sh Address already in use
   -To fix:
     1. Follow error prompt instructions i.e. disable Airplay Receiver
