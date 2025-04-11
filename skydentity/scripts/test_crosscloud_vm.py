"""
Test script to register a fake VM with the global state,
and then requests credentials to access resources across clouds.

Sends the same requests as an authorizer would to generate and store a public/private key pair.
"""

import argparse
import base64
import json
from datetime import datetime
from pprint import pprint

import requests
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from google.cloud.storage import Client
from google.oauth2.credentials import Credentials

from skydentity.policies.managers.gcp_global_state_manager import (
    CrossCloudGlobalState,
    GCPGlobalStateManager,
)
from skydentity.proxy_util.crosscloud_resources.signature import generate_vm_keypair
from skydentity.utils.hash_util import hash_public_key

parser = argparse.ArgumentParser()
parser.add_argument(
    "--public-key", required=True, type=str, help="Path to the orchestrator public key"
)
parser.add_argument(
    "--credentials",
    required=True,
    type=str,
    help="Path to credentials for accessing the global state",
)
parser.add_argument("--role", required=True, type=str, help="VM role")
parser.add_argument(
    "--gcp-auth-address",
    default="https://127.0.0.1:5001",
    help="URL to the GCP authorizer proxy",
)
parser.add_argument("--vm-id", default="test", help="ID of the VM")
parser.add_argument("--source-cloud", default="azure", help="Source cloud name")

args = parser.parse_args()

with open(args.public_key, "r", encoding="utf-8") as f:
    orchestrator_pubkey = RSA.import_key(f.read())

with open(args.credentials, "r", encoding="utf-8") as f:
    global_state_cred_info = json.load(f)

orchestrator_pubkey_hash = hash_public_key(orchestrator_pubkey.export_key())

# generate a new keypair
vm_keypair = generate_vm_keypair()

global_state_manager = GCPGlobalStateManager(credentials_info=global_state_cred_info)
global_state = CrossCloudGlobalState(
    cloud="azure",
    vm_id="test",
    vm_public_key=vm_keypair.public_key.export_key().decode("utf-8"),
    vm_role=args.role,
    orchestrator_key_hash=orchestrator_pubkey_hash,
)
global_state_manager.update_state(global_state)

print("Uploaded global state:")
pprint(global_state)

print("Private key (PEM):")
print(vm_keypair.private_key.export_key().decode("utf-8"))

# use the private key to request credentials from GCP

# sign request body
signature_body = {
    "vm_id": args.vm_id,
    "source_cloud": args.source_cloud,
    "dest_cloud": "gcp",
    "timestamp": int(datetime.now().timestamp()),
}
# normalize signature body by sorting by key
signature_body_bytes = json.dumps(signature_body, sort_keys=True).encode("utf-8")
signature_body_hash = SHA256.new(signature_body_bytes)
signature = pkcs1_15.new(vm_keypair.private_key).sign(signature_body_hash)

# normalize auth proxy address to remove the slash
normalized_auth_address = args.gcp_auth_address.rstrip("/")
request_credentials_url = (
    f"{normalized_auth_address}/skydentity/cross-cloud/credentials"
)

# send request for credentials
print(f"Sending request for credentials to {request_credentials_url}")
response = requests.post(
    request_credentials_url,
    json={
        **signature_body,
        "signature": base64.b64encode(signature).decode("utf-8"),
    },
    timeout=30,
)
print(response.content)
response_json = response.json()

print("Response:")
print(response_json)

access_token = response_json["access_token"]

print("Testing GCP request using access token...")

# test access token with a GCP storage request
test_gcp_creds = Credentials(token=access_token)
gcp_storage_client = Client(project="sky-identity", credentials=test_gcp_creds)
print("Listing blobs...")
blobs = gcp_storage_client.bucket("skydentity-test-bucket").list_blobs()

all_bytes = b""
for blob in blobs:
    all_bytes += str(blob.name).encode("utf-8")
    print("Downloading blob...")
    all_bytes += b"\n"
    all_bytes += blob.download_as_string()
    all_bytes += b"\n\n"

print(all_bytes)
