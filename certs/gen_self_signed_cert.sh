#!/bin/bash

COUNTRY=US
STATE=California
CITY=Berkeley
COMPANY=skyid
HOSTNAME='127.0.0.1'

openssl req -x509 -newkey rsa:4096 -keyout skyidcert.key -out skyidcert.crt -sha256 -days 3650 -nodes -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$COMPANY/OU=$COMPANY/CN=$HOSTNAME"
