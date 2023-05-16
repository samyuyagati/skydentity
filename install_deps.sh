#!/bin/bash

pip install -r requirements.txt

export PATH=$PATH:~/.local/bin

# GCP
ENV_NAME=gcp-env
virtualenv $ENV_NAME
source $ENV_NAME/bin/activate
$ENV_NAME/bin/pip install google-cloud-compute
