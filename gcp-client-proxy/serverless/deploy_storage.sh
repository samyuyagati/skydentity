#!/bin/bash

# Deploy the service (deploys a new version if previously deployed)
gcloud run deploy skyidproxy-storage-service \
    --image gcr.io/$1/skyidproxy-storage \
    --set-secrets="/cloud_creds/gcp/proxy_service_account_key.json=sa-key-storageproxy:latest, /cloud_creds/enc/capability_enc.key=enc-key-storageproxy:latest" \
    --service-account gcr-skyidproxy-storage@$1.iam.gserviceaccount.com \
    --execution-environment gen2
