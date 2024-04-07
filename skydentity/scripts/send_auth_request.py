import argparse
import json
import os
import requests
import yaml

from base64 import b64decode
from Crypto.Cipher import AES

from urllib.parse import urljoin

AUTHORIZATION_ENDPOINT = "create-authorization"

parser = argparse.ArgumentParser(
                    prog='ProgramName',
                    description='What the program does',
                    epilog='Text at the bottom of help')

parser.add_argument("--resource_yaml_input", type=str, help="The path to the input resource yaml file")
parser.add_argument("--resource_yaml_output", type=str, help="The path to write the output resource yaml file")
parser.add_argument("--auth_request_yaml", type=str, help="The path to the auth request yaml file")
parser.add_argument("--capability_enc_key", type=str, help="The path to the capability encryption key file")
parser.add_argument("--cloud", type=str, help="The cloud to send the request to")
args = parser.parse_args()


def send_auth_creation_request(url, json=None, headers=None):
    """
    Sends an authorization request to the authorization server.
    :param url: The url of the server proxy.
    :param json: The json to send with the request.
    :param headers: The headers to send with the request.
    :return: The response from the server.
    """
    full_url = urljoin(url, AUTHORIZATION_ENDPOINT)
    print(full_url)
    return requests.request("POST", full_url, json=json, headers=headers)

def check_capability(capability: dict, capability_enc_path: str) -> (str, bool):
    """
    Decrypts the capability and returns True, along with the service account id, if it is valid.
    """
    with open(capability_enc_path, 'rb') as f:
        capability_enc = f.read()

    nonce = b64decode(capability['nonce'])
    header = b64decode(capability['header']) # If checking broker public key, check that the header matches the public key attached to the request
    ciphertext = b64decode(capability['ciphertext'])
    tag = b64decode(capability['tag'])
    cipher = AES.new(capability_enc, AES.MODE_GCM, nonce=nonce)
    cipher.update(header)
    try:
        candidate_service_account_id = cipher.decrypt_and_verify(ciphertext, tag)
        return (candidate_service_account_id.decode('utf-8'), True)
    except ValueError:
        print("Invalid capability: could not decrypt or verify")
        return (None, False)

# How to test authorizations:
# 0. Run server and client proxies; upload skydentity/skydentity/policies/config/auth_policy_example.yaml 
#    to Firestore using upload_policy.py with the --authorization flag
# 1. Run this script
# 2. Check the email address of the created service account in the client proxy logs
# 3. In skydentity/skydentity/policies/config/skypilot_eval.yaml, modify the email address of the 
#    service account to match the one in the logs
# 4. Upload skypilot_eval.yaml to Firestore using upload_policy.py
# 5. Run skydentity/python-server/test_server.py.
# 6. Check that the service account attached to the created VM matches the one from step 2.
# This request should be sent by the client.

def main():
    with open(args.auth_request_yaml, 'r') as f:
        auth_request_dict = yaml.load(f, Loader=yaml.SafeLoader)
        print(auth_request_dict)
    if args.cloud == "gcp":
        protocol = "http"
    elif args.cloud == "azure":
        protocol = "https"
    response = send_auth_creation_request(f"{protocol}://127.0.0.1:5000/skydentity/cloud/{args.cloud}/", json=auth_request_dict)
    print("RESPONSE JSON", response.json())
    out_path = os.path.join(os.path.dirname(os.path.dirname(os.getcwd())), "tokens/")
    service_acct_id, valid_capability = check_capability(response.json(), args.capability_enc_key)
    if not valid_capability:
        raise RuntimeError("Invalid capability returned")

    with open(args.resource_yaml_input, 'r') as f:
        resource_dict = yaml.load(f, Loader=yaml.SafeLoader)
        print(resource_dict)
        if args.cloud == "gcp":
            resource_dict["attached_authorizations"][0]["gcp"][0]["authorization"] = service_acct_id
        elif args.cloud == "azure":
            resource_dict["virtual_machine"]["attached_authorizations"][0][args.cloud][0]["authorization"] = [service_acct_id]
        with open(args.resource_yaml_output, 'w') as f:
            yaml.dump(resource_dict, f)
    with open(os.path.join(out_path, "capability.json"), "w") as f:
            print("Output capability at:", os.path.join(out_path, "capability.json"))
            json.dump(response.json(), f)

if __name__== "__main__":
    main()
