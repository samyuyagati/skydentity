#!/bin/bash

SERVICE_ACCT_KEY_PATH=""
GCP_PROJECT=""
CREATE_SECRETS=false

while getopts "k:p:c" option; do
  case $option in
    k)
        SERVICE_ACCT_KEY_PATH=$OPTARG 
        ;;
    p)
        GCP_PROJECT=$OPTARG
        ;;
    c)
        CREATE_SECRETS=true 
        ;;
    *)
        echo "Usage: deploy_setup.sh -k [path to key file of client proxy service acct] -p [id of GCP project] [-c]. Must provide key file if creating secrets (-c)."
        exit 1
        ;;
  esac
done

# Create secrets if requested (-c flag is set)
if $CREATE_SECRETS; then
  gcloud secrets create sa-key --data-file=$SERVICE_ACCT_KEY_PATH
  openssl rand 32 > ../local_tokens/capability_enc.key
  gcloud secrets create enc-key --data-file=../local_tokens/capability_enc.key

  # Private key for domain certificate is only needed for testing local Docker containers
  #gcloud secrets create cert-key --data-file=certs/domain_dir/domain.key

  # Create service account for cloud run wrapper (not the docker container inside it)
  gcloud iam service-accounts create gcr-skyidproxy 
    --description="Automatically created service account for Cloud Run wrappper around Skydentity client GCP proxy"
    --display-name="gcr-skyidproxy"

  # Give it roles to access the secrets its attaching access limited compute resources
  gcloud projects add-iam-policy-binding $GCP_PROJECT \
    --member="serviceAccount:gcr-skyidproxy@$GCP_PROJECT.iam.gserviceaccount.com" \
    --role=roles/compute.serviceAgent

  gcloud projects add-iam-policy-binding $GCP_PROJECT \
    --member="serviceAccount:gcr-skyidproxy@$GCP_PROJECT.iam.gserviceaccount.com" \
    --role=roles/secretmanager.secretAccessor
fi

# Update value of enc-key to the local_tokens value that test_authorizations uses
gcloud secrets versions add enc-key --data-file=local_tokens/capability_enc.key

# Set region
gcloud config set run/region us-west1

# Copy app.py into current directory
cp ../app.py .

# Copy skydentity package and setup code to current directory
cp ../../setup.py .
mkdir skydentity
cp -r ../../skydentity/policies ./skydentity/
cp -r ../../skydentity/utils ./skydentity/
cp -r ../../skydentity/proxy_util ./skydentity/
echo "copied skydentity policy checking module and utils"

ls skydentity
ls .

# Create the image in Google Cloud run (takes several minutes)
gcloud builds submit --tag gcr.io/$GCP_PROJECT/skyidproxy

# Cleanup
rm -r ./skydentity
rm setup.py
rm app.py
