#!/bin/bash

# Script assumes this secret (proxy's service account key) hasn't been added before
#gcloud secrets create sa-key --data-file=tokens/.cloud_creds/gcp/sky-identity-ac2febc1b9b3.json

# Script assumes this secret (private key corresponding to domain cert) hasn't been added before
#gcloud secrets create cert-key --data-file=certs/domain_dir/domain.key

# Set region
gcloud config set run/region us-west1

# Create the image in Google Cloud run (takes several minutes)
gcloud builds submit --tag gcr.io/sky-identity/skyidproxy

# Deploy the service (deploys a new version if previously deployed)
gcloud run deploy skyidproxy-service --image gcr.io/sky-identity/skyidproxy --set-secrets="/cloud_creds/gcp/sky-identity-ac2febc1b9b3.json=sa-key:latest, /certs/domain.key=cert-key:latest" --service-account gcr-skyidproxy@sky-identity.iam.gserviceaccount.com
