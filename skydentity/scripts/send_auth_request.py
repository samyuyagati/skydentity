import requests
from urllib.parse import urljoin

AUTHORIZATION_ENDPOINT = "create_authorization"

def send_auth_creation_request(url, method, json=None, headers=None):
    """
    Sends an authorization request to the authorization server.
    :param url: The url of the server proxy.
    :param json: The json to send with the request.
    :param headers: The headers to send with the request.
    :return: The response from the server.
    """
    return requests.request("POST", urljoin(url, AUTHORIZATION_ENDPOINT), json=json, headers=headers)