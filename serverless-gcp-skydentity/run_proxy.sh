#!/bin/bash

flask run --host="0.0.0.0" --port=5000 --cert=../certs/domain.crt --key=../certs/domain.key
