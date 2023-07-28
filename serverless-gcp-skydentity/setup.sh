#!/bin/bash

# Install Flask and gcp 
sudo apt install python3 python3-pip python3-venv
python3 -m venv skyid
skyid/bin/pip3 install Flask requests
skyid/bin/pip3 install google-cloud-compute
