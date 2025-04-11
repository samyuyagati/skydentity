import base64
import json
from datetime import datetime

import requests
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from google.cloud.storage.client import Client
from google.oauth2.credentials import Credentials

SKYDENTITY_CONFIG_PATH = "/run/skydentity/config.json"

with open(SKYDENTITY_CONFIG_PATH, "r", encoding="utf-8") as f:
    config = json.load(f)

# get authorizer URL
config_urls = config["urls"]
GCP_AUTHORIZER_URL = config_urls["gcp"].rstrip("/")

# TODO: move to secret store
# fetch RSA private key for the VM
vm_private_key_raw = config["private_key"]
vm_private_key = RSA.import_key(vm_private_key_raw)

# fetch VM id from instance metadata
metadata_response = requests.get(
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    headers={"Metadata": "true"},
    proxies={"http": "", "https": ""},
    timeout=60,
)
metadata_json = metadata_response.json()
VM_ID = metadata_json["compute"]["vmId"]

# sign request body
signature_body = {
    "vm_id": VM_ID,
    "source_cloud": "azure",
    "dest_cloud": "gcp",
    "timestamp": int(datetime.now().timestamp()),
}
# normalize signature body by sorting by key
signature_body_bytes = json.dumps(signature_body, sort_keys=True).encode("utf-8")
signature_body_hash = SHA256.new(signature_body_bytes)
signature = pkcs1_15.new(vm_private_key).sign(signature_body_hash)
signature_b64 = base64.b64encode(signature).decode("utf-8")

# request credentials
credentials_request_body = {**signature_body, "signature": signature_b64}
credentials_response = requests.post(
    f"{GCP_AUTHORIZER_URL}/skydentity/cross-cloud/credentials",
    json=credentials_request_body,
    timeout=60,
)

# get credentials from response
credentials_json = credentials_response.json()
access_token = credentials_json["access_token"]

credentials = Credentials(token=access_token)
client = Client(project="sky-identity", credentials=credentials)

# send request to GCP with the given credentials
blobs = client.bucket("skydentity-test-bucket").list_blobs()

all_bytes = b""
for blob in blobs:
    print("Blob:", blob.name)
    all_bytes += str(blob.name).encode("utf-8")
    all_bytes += b"\n"
    blob_content = blob.download_as_string()
    print("Content:", blob_content)
    all_bytes += blob_content
    all_bytes += b"\n\n"

# write output to a file
with open("/run/skydentity/out", "wb") as f:
    f.write(all_bytes)
