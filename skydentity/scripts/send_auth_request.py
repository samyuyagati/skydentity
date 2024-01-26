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

def main():
    with open(os.path.join(os.path.dirname(os.getcwd()), "policies/config/auth_request_example.yaml"), 'r') as f:
        auth_request_dict = yaml.load(f, Loader=yaml.SafeLoader)['authorization']
        print(auth_request_dict)
    send_auth_creation_request("http://127.0.0.1:5000/skydentity/cloud/gcp/", json=auth_request_dict)

if __name__== "__main__":
    main()