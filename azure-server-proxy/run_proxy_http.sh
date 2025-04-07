#!/bin/bash

export CAPABILITY_FILE="./tokens/capability.json"

flask run --host="0.0.0.0" --port="${PORT:-6000}"
