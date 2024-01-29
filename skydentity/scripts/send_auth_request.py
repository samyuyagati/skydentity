import json
import os
import requests
import yaml

from urllib.parse import urljoin

AUTHORIZATION_ENDPOINT = "create-authorization"

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

def main():
    with open(os.path.join(os.path.dirname(os.getcwd()), "policies/config/auth_request_example.yaml"), 'r') as f:
        auth_request_dict = yaml.load(f, Loader=yaml.SafeLoader)
        print(auth_request_dict)
    response = send_auth_creation_request("http://127.0.0.1:5000/skydentity/cloud/gcp/", json=auth_request_dict)
    print("RESPONSE", response)
    out_path = os.path.join(os.path.dirname(os.path.dirname(os.getcwd())), "tokens/")
    with open(os.path.join(out_path, "capability.json"), "w") as f:
        print("Output capability at:", os.path.join(out_path, "capability.json"))
        json.dump(response.json(), f)

if __name__== "__main__":
    main()