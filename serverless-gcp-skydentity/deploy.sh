#!/bin/bash

# Deploy the service (deploys a new version if previously deployed)
gcloud run deploy skyidproxy-service --image gcr.io/sky-identity/skyidproxy --set-secrets="/cloud_creds/gcp/sky-identity-ac2febc1b9b3.json=sa-key:latest, /certs/domain.key=cert-key:latest" --service-account gcr-skyidproxy@sky-identity.iam.gserviceaccount.com
