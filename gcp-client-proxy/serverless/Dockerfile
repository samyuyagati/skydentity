# syntax=docker/dockerfile:1

FROM python:3.12-slim-bullseye

WORKDIR /skydentity-proxy

ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Copy required files
COPY requirements.txt .
#COPY certs/domain_dir/domain.crt ./certs/domain.crt # Only required for local container testing
COPY app.py .
COPY skydentity/ ./skydentity
COPY setup.py .

# Install dependencies
RUN pip3 install -r requirements.txt

# Install the skydentity package which provides core code for policy checking
RUN pip3 install -e .

# Install google cloud SDK
# Install required dependencies
RUN apt-get update && \
    apt-get install -y \
        curl 

# Downloading gcloud package
RUN curl https://dl.google.com/dl/cloudsdk/release/google-cloud-sdk.tar.gz > /tmp/google-cloud-sdk.tar.gz

# Installing the package
RUN mkdir -p /usr/local/gcloud \
  && tar -C /usr/local/gcloud -xvf /tmp/google-cloud-sdk.tar.gz \
  && /usr/local/gcloud/google-cloud-sdk/install.sh

# Adding the package path to local
ENV PATH $PATH:/usr/local/gcloud/google-cloud-sdk/bin

# Setting environment variables for GCP client proxy
# Service account key file downloaded from GCP
ENV SERVICE_ACCOUNT_INFO_FILE="/cloud_creds/gcp/proxy_service_account_key.json"
# official compute api endpoint
ENV COMPUTE_API_ENDPOINT="https://compute.googleapis.com/"
# capability encryption key
ENV CAPABILITY_ENC_KEY_FILE="/cloud_creds/enc/capability_enc.key"

# setting gcloud ADC
ENV GOOGLE_APPLICATION_CREDENTIALS=$SERVICE_ACCOUNT_INFO_FILE

# Launch HTTP server
CMD exec gunicorn --bind :$PORT --workers 1 --threads 20 --timeout 0 app:app

# Launch HTTPS server; only for local docker testing.
#CMD exec gunicorn --bind :$PORT --workers 1 --threads 4 --timeout 0 --keyfile /certs/domain.key --certfile ./certs/domain.crt app:app 
