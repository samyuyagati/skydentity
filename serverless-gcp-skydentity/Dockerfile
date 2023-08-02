# syntax=docker/dockerfile:1

FROM python:3.9-slim-bullseye 

WORKDIR /skydentity-proxy

ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Copy required files
COPY requirements.txt .
COPY certs/domain_dir ./certs
COPY app.py .
COPY tokens/.cloud_creds/gcp ./.cloud_creds/gcp 

RUN pip3 install -r requirements.txt

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

CMD [ "python3", "-m" , "flask", "run", "--host=0.0.0.0", "--port=5000", "--cert=certs/domain.crt", "--key=certs/domain.key"]