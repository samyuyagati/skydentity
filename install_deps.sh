#!/bin/bash

pip install -r requirements.txt

export PATH=$PATH:~/.local/bin

# GCP
ENV_NAME=skyid
virtualenv $ENV_NAME
source $ENV_NAME/bin/activate
$ENV_NAME/bin/pip install google-cloud-compute
$ENV_NAME/bin/pip install google-cloud-storage
$ENV_NAME/bin/pip install Flask requests
