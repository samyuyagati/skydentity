# syntax=docker/dockerfile:1

FROM python:3.9-slim-bullseye 

WORKDIR /skydentity-proxy

ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Copy required files
COPY requirements.txt .
COPY certs/domain_dir/domain.crt ./certs/domain.crt
COPY app.py .
COPY skydentity/ .
#COPY wsgi.py .

RUN pip3 install -r requirements.txt

# Install the skydentity package which provides core code for policy checking
RUN pip3 install ./skydentity

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

# Launch HTTP server
CMD exec gunicorn --bind :$PORT --workers 1 --threads 4 --timeout 0 app:app

# Launch HTTPS server
#CMD exec gunicorn --bind :$PORT --workers 1 --threads 4 --timeout 0 --keyfile /certs/domain.key --certfile ./certs/domain.crt app:app 
