#!/bin/bash

flask run --host="0.0.0.0" --port="${PORT:-5000}" --with-threads
