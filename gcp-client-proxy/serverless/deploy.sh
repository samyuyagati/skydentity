#!/bin/bash

# Deploy the service (deploys a new version if previously deployed)
gcloud run deploy skyidproxy-service --image gcr.io/$1/skyidproxy --set-secrets="/cloud_creds/gcp/proxy_service_account_key.json=sa-key:latest, /cloud_creds/enc/capability_enc.key=enc-key:latest" --service-account gcr-skyidproxy@$1.iam.gserviceaccount.com