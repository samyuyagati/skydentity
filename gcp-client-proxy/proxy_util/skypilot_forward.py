"""
Forwarding for SkyPilot requests.
"""
import base64
import datetime
import json
import os
import subprocess
from collections import namedtuple
from functools import cache
from http import HTTPStatus
from urllib.parse import urlparse

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from flask import Flask, Response, request

from skydentity.policies.managers.gcp_policy_manager import GCPPolicyManager

from .logging import get_logger, print_and_log

# global constants
COMPUTE_API_ENDPOINT = os.environ.get(
    "COMPUTE_API_ENDPOINT", "https://compute.googleapis.com/"
)
SERVICE_ACCT_INFO_FILE = os.environ.get("SERVICE_ACCOUNT_INFO_FILE", None)

# validate global constants from environment variables
assert SERVICE_ACCT_INFO_FILE is not None and os.path.isfile(SERVICE_ACCT_INFO_FILE)

SkypilotRoute = namedtuple(
    "SkypilotRoute",
    [
        "methods",  # HTTP methods for the route
        "path",  # Flask rule for the route path
        "fields",  # fields in the routing rule
        "view_func",  # explicit view function to use; optional
    ],
    defaults=[None, None],  # defaults for "fields" and "view_func"
)


# list of all routes required; must be defined after `build_generic_forward`
ROUTES: list[SkypilotRoute] = [
    SkypilotRoute(
        methods=["GET"],
        path="/compute/v1/projects/<project>/global/images/family/<family>",
        fields=["project", "family"],
    ),
    SkypilotRoute(
        methods=["POST", "GET"],
        path="/compute/v1/projects/<project>/zones/<region>/instances",
        fields=["project", "region"],
    ),
    SkypilotRoute(
        methods=["GET"],
        path="/compute/v1/projects/<project>/regions/<region>",
        fields=["project", "region"],
    ),
    SkypilotRoute(
        methods=["GET"],
        path="/compute/v1/projects/<project>/aggregated/reservations",
        fields=["project"],
    ),
    SkypilotRoute(
        methods=["GET"],
        path="/compute/v1/projects/<project>",
        fields=["project"],
    ),
    SkypilotRoute(
        methods=["GET", "POST"],
        path="/compute/v1/projects/<project>/global/networks",
        fields=["project"],
    ),
    SkypilotRoute(
        methods=["GET", "POST"],
        path="/compute/v1/projects/<project>/global/firewalls",
        fields=["project"],
    ),
    SkypilotRoute(
        methods=["GET"],
        path="/compute/v1/projects/<project>/global/networks/<network>/getEffectiveFirewalls",
        fields=["project", "network"],
    ),
    SkypilotRoute(
        methods=["GET"],
        path="/compute/v1/projects/<project>/regions/<region>/subnetworks",
        fields=["project", "region"],
    ),
    SkypilotRoute(
        methods=["GET"],
        path="/compute/v1/projects/<project>/global/operations/<operation>",
        fields=["project", "operation"],
    ),
    SkypilotRoute(
        methods=["GET"],
        path="/compute/v1/projects/<project>/zones/<region>/operations/<operation>",
        fields=["project", "region", "operation"],
    ),
    SkypilotRoute(
        methods=["POST"],
        path="/compute/v1/projects/<project>/zones/<region>/instances/<instance>/setLabels",
        fields=["project", "region", "instance"],
    ),
    SkypilotRoute(
        methods=["POST"],
        path="/compute/v1/projects/<project>/zones/<region>/instances/<instance>/stop",
        fields=["project", "region", "instance"],
    ),
    SkypilotRoute(
        methods=["DELETE"],
        path="/compute/v1/projects/<project>/zones/<region>/instances/<instance>",
        fields=["project", "region", "instance"],
    ),
    SkypilotRoute(
        methods=["POST"],
        path="/compute/v1/projects/<project>/zones/<region>/instances/<instance>/start",
        fields=["project", "region", "instance"],
    ),
]


def verify_request_signature(request):
    encoded_signature = request.headers["X-Signature"]
    timestamp = request.headers["X-Timestamp"]
    encoded_public_key_bytes = request.headers["X-PublicKey"]

    try:
        timestamp = float(timestamp)
        timestamp_datetime = datetime.datetime.fromtimestamp(
            timestamp, tz=datetime.timezone.utc
        )
    except ValueError:
        # invalid timestamp
        return False

    # decode signature and public key using base64
    signature = base64.b64decode(encoded_signature, validate=True)
    public_key_bytes = base64.b64decode(encoded_public_key_bytes, validate=True)

    now = datetime.datetime.now(datetime.timezone.utc)
    if now - datetime.timedelta(seconds=60) > timestamp_datetime:
        # if timestamp when request was sent is > 60 seconds old, deny the request
        return False

    host = request.headers.get("Host", "")
    reformed_message = f"{str(request.method)}-{host}-{timestamp}-{public_key_bytes}"
    reformed_message_bytes = reformed_message.encode("utf-8")

    public_key = serialization.load_pem_public_key(public_key_bytes)
    # raises InvalidSignature exception if the signature does not match
    public_key.verify(
        signature,
        reformed_message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )

    return True


def generic_forward_request(request, log_dict=None):
    """
    [SkyPilot Integration]
    Forward a generic request to google APIs.
    """
    logger = get_logger()
    if log_dict is not None:
        log_str = f"PATH: {request.full_path}\n"
        for key, val in log_dict.items():
            log_str += f"\t{key}: {val}\n"
        print_and_log(logger, log_str.strip())

    if not verify_request_signature(request):
        # Not sure if this is the correct status code. This case will only happen when the timestamp
        # associated with the signature is too old at the time when the signature is verified.
        return Response("", HTTPStatus.REQUEST_TIMEOUT, {})

    # Check the request
    if not check_request_from_policy(request.headers["X-PublicKey"], request):
        print_and_log(logger, "Request is unauthorized")
        return Response("Unauthorized", 401)

    # Get new endpoint and new headers
    new_url = get_new_url(request)
    new_headers = get_headers_with_auth(request)

    # don't modify the body in any way
    new_json = None
    if len(request.get_data()) > 0:
        new_json = request.json

    gcp_response = send_gcp_request(request, new_headers, new_url, new_json=new_json)
    return Response(gcp_response.content, gcp_response.status_code, new_headers)


def build_generic_forward(path: str, fields: list[str]):
    """
    Return the appropriate generic forward view function for the fields provided.

    The path is only used to create a unique and readable name for the anonymous function.
    """
    func = None
    if fields == ["project"]:
        func = lambda project: generic_forward_request(request, {"project": project})
    elif fields == ["project", "region"]:
        func = lambda project, region: generic_forward_request(
            request, {"project": project, "region": region}
        )
    elif fields == ["project", "family"]:
        func = lambda project, family: generic_forward_request(
            request, {"project": project, "family": family}
        )
    elif fields == ["project", "network"]:
        func = lambda project, network: generic_forward_request(
            request, {"project": project, "network": network}
        )
    elif fields == ["project", "operation"]:
        func = lambda project, operation: generic_forward_request(
            request, {"project": project, "operation": operation}
        )
    elif fields == ["project", "region", "operation"]:
        func = lambda project, region, operation: generic_forward_request(
            request, {"project": project, "region": region, "operation": operation}
        )
    elif fields == ["project", "region", "instance"]:
        func = lambda project, region, instance: generic_forward_request(
            request, {"project": project, "region": region, "instance": instance}
        )
    else:
        raise ValueError(
            f"Invalid list of variables to build generic forward for: {fields}"
        )

    # Flask expects all view functions to have unique names
    # (otherwise it complains about overriding view functions)
    func.__name__ = path

    return func


def setup_routes(app: Flask):
    """
    Set up all routes for SkyPilot forwarding.
    """
    for route in ROUTES:
        if route.view_func is not None:
            # use view_func if specified
            app.add_url_rule(
                route.path, view_func=route.view_func, methods=route.methods
            )
        elif route.fields is not None:
            # create a generic view function from the fields
            app.add_url_rule(
                route.path,
                view_func=build_generic_forward(route.path, route.fields),
                methods=route.methods,
            )
        else:
            raise ValueError(
                "Invalid route specification; missing either `view_func` or `fields`"
            )


@cache  # shouldn't change throughout the proxy lifespan
def get_service_account_info():
    """
    Retrieve the service account email from the
    """
    with open(SERVICE_ACCT_INFO_FILE, "r", encoding="utf-8") as service_account_file:
        service_account_file_json = json.load(service_account_file)

    assert "email" in service_account_file_json.keys()
    assert "credentials" in service_account_file_json.keys()

    service_account_creds = service_account_file_json["credentials"]
    assert os.path.isfile(
        service_account_creds
    ), f"Service account credentials file (from JSON: {service_account_creds}) does not exist."

    return (
        service_account_file_json["email"],
        service_account_creds,
    )


def get_json_with_service_account(request, service_account_email):
    """
    Modify the JSON of the request to include service account details.
    """
    json_dict = request.json
    service_account_dict = {
        "email": f"{service_account_email}",
        "scopes": [f"https://www.googleapis.com/auth/cloud-platform"],
    }
    new_dict = json_dict.copy()
    new_dict["serviceAccounts"] = [service_account_dict]
    return new_dict


@cache
def activate_service_account(credential_file):
    auth_command = f"gcloud auth activate-service-account --key-file={credential_file}"
    auth_process = subprocess.Popen(auth_command.split())
    auth_process.wait()


@cache
def get_service_account_auth_token():
    auth_token_command = "gcloud auth print-access-token"
    auth_token_process = subprocess.Popen(
        auth_token_command.split(), stdout=subprocess.PIPE
    )
    auth_token_process_out_bytes, _ = auth_token_process.communicate()

    return auth_token_process_out_bytes


def strip_signature_headers(headers):
    signature_headers = set(["X-Signature", "X-Timestamp", "X-PublicKey"])
    new_headers = {k: v for k, v in headers.items() if k not in signature_headers}
    return new_headers


def get_headers_with_auth(request):
    """
    Append authentication headers for a service account to the request.
    """
    # print_and_log(logger, "Entered get_headers_with_auth")
    ## Get authorization token and add to headers
    new_headers = {k: v for k, v in request.headers}  # if k.lower() == 'host'}

    # print_and_log(logger, f"ORIGINAL HEADERS: {new_headers}")
    parsed_compute_api_endpoint = urlparse(f"{COMPUTE_API_ENDPOINT}")
    hostname = parsed_compute_api_endpoint.netloc
    new_headers["Host"] = f"{hostname}"

    # Activate service account and get auth token
    _, service_acct_cred_file = get_service_account_info()
    activate_service_account(service_acct_cred_file)

    auth_token_process_out_bytes = get_service_account_auth_token()

    auth_token = auth_token_process_out_bytes.strip().decode("utf-8")
    # print_and_log(logger, f"AUTH TOKEN: {auth_token}")
    new_headers["Authorization"] = f"Bearer {auth_token}"

    clean_new_headers = strip_signature_headers(new_headers)
    return clean_new_headers


def get_new_url(request):
    """
    Redirect the URL (originally to the proxy) to the correct GCP endpoint.
    """
    new_url = request.url.replace(request.host_url, f"{COMPUTE_API_ENDPOINT}")
    logger = get_logger()
    print_and_log(logger, f"\tNew URL: {new_url}")
    return new_url


@cache  # should only be initialized once
def get_policy_manager():
    _, service_acct_cred_file = get_service_account_info()
    return GCPPolicyManager(service_acct_cred_file)


def check_request_from_policy(public_key, request) -> bool:
    logger = get_logger()
    print_and_log(
        logger, f"Check request public key: {public_key} (request: {request})"
    )

    policy_manager = get_policy_manager()
    policy = policy_manager.get_policy(public_key, None)
    print_and_log(logger, f"Got policy {policy}")
    return policy.check_request(request)


def send_gcp_request(request, new_headers, new_url, new_json=None):
    """
    Send a request to the GCP endpoint, with new headers, URL, and request body.
    """
    # If no JSON body, don't include a json body in proxied request
    if len(request.get_data()) == 0:
        return requests.request(
            method=request.method,
            url=new_url,
            headers=new_headers,
            cookies=request.cookies,
            allow_redirects=False,
        )
    return requests.request(
        method=request.method,
        url=new_url,
        headers=new_headers,
        json=new_json,
        cookies=request.cookies,
        allow_redirects=False,
    )
