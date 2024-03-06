"""
Forwarding for SkyPilot requests.
"""

import base64
import json
import os
from collections import namedtuple
from http import HTTPStatus
from urllib.parse import urlparse

import requests
from flask import Flask, Response, request

from skydentity.policies.checker.gcp_authorization_policy import GCPAuthorizationPolicy
from skydentity.utils.hash_util import hash_public_key

from .credentials import (
    activate_service_account,
    get_service_account_auth_token,
    get_service_account_path,
)
from .logging import get_logger, print_and_log
from .policy_check import check_request_from_policy, get_authorization_policy_manager
from .signature import strip_signature_headers, verify_request_signature

# global constants
COMPUTE_API_ENDPOINT = os.environ.get(
    "COMPUTE_API_ENDPOINT", "https://compute.googleapis.com/"
)

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
        methods=["GET"],
        path="/compute/v1/projects/<project>/global/images/<image>",
        fields=["project", "image"],
    ),
    SkypilotRoute(
        methods=["GET"],
        path="/compute/v1/projects/<project>/aggregated/instances",
        fields=["project"],
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
    # skydentity internal route
    SkypilotRoute(
        methods=["POST"],
        path="/skydentity/cloud/<cloud>/create-authorization",
        fields=["cloud"],
        # wrapper to allow for the function to be defined later
        view_func=lambda cloud: create_authorization_route(cloud),
    ),
]


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

    # Verify the request signature
    if not verify_request_signature(request):
        print_and_log(logger, "Request is unauthorized (signature verification failed)")
        return Response("Unauthorized", 401)

    # Check the request against the policy for this workload orchestrator
    public_key_bytes = base64.b64decode(request.headers["X-PublicKey"], validate=True)
    authorized, service_account_id = check_request_from_policy(
        public_key_bytes, request
    )
    if not authorized:
        print_and_log(logger, "Request is unauthorized (policy check failed)")
        return Response("Unauthorized", 401)

    # Get new endpoint and new headers
    new_url = get_new_url(request)
    new_headers = get_headers_with_auth(request)

    # If a valid service account was provided, attach it to the request
    new_json = None
    if len(request.get_data()) > 0:
        new_json = request.json
        if service_account_id:
            new_json = get_json_with_service_account(request, service_account_id)
            print_and_log(logger, f"Json with service account: {new_json}")

    gcp_response = send_gcp_request(request, new_headers, new_url, new_json=new_json)
    return Response(gcp_response.content, gcp_response.status_code, new_headers)


def build_generic_forward(path: str, fields: list[str]):
    """
    Return the appropriate generic forward view function for the fields provided.

    The path is only used to create a unique and readable name for the anonymous function.
    """
    func = lambda **kwargs: generic_forward_request(request, kwargs)
    # if fields == ["project"]:
    #     func = lambda project: generic_forward_request(request, {"project": project})
    # elif fields == ["project", "region"]:
    #     func = lambda project, region: generic_forward_request(
    #         request, {"project": project, "region": region}
    #     )
    # elif fields == ["project", "family"]:
    #     func = lambda project, family: generic_forward_request(
    #         request, {"project": project, "family": family}
    #     )
    # elif fields == ["projdct", "image"]:
    #     func = lambda project, image: generic_forward_request(
    #         request, {"project": project, "image": image}
    #     )
    # elif fields == ["project", "network"]:
    #     func = lambda project, network: generic_forward_request(
    #         request, {"project": project, "network": network}
    #     )
    # elif fields == ["project", "operation"]:
    #     func = lambda project, operation: generic_forward_request(
    #         request, {"project": project, "operation": operation}
    #     )
    # elif fields == ["project", "region", "operation"]:
    #     func = lambda project, region, operation: generic_forward_request(
    #         request, {"project": project, "region": region, "operation": operation}
    #     )
    # elif fields == ["project", "region", "instance"]:
    #     func = lambda project, region, instance: generic_forward_request(
    #         request, {"project": project, "region": region, "instance": instance}
    #     )
    # else:
    #     raise ValueError(
    #         f"Invalid list of variables to build generic forward for: {fields}"
    #     )

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
            # use view_func if specified; change name to be consistent with generic
            # (also allows lambda functions to be passed in)
            route.view_func.__name__ = route.path
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

    # set up default route
    default_view = lambda path: default_route_deny(request, path)
    default_view.__name__ = "default_view"
    app.add_url_rule("/", view_func=default_view, defaults={"path": ""})
    app.add_url_rule("/<path:path>", view_func=default_view)


def default_route_deny(request, path=None):
    """
    Default deny all unknown routes.
    """
    logger = get_logger()
    print_and_log(logger, f"UNKNOWN ROUTE: /{path}")
    return Response("Unknown route; permission denied", 401)


def forward_request_unchecked(request, path=None):
    """
    Default forward to google APIs, with no request or policy checking.

    Attaches credentials for the service account; this function should be used with caution,
    since credentials will be passed along to unchecked requests.
    """
    logger = get_logger()
    print_and_log(logger, f"UNCHECKED FORWARD: /{path}")

    new_url = get_new_url(request)
    new_headers = get_headers_with_auth(request)

    # don't modify the body in any way
    new_json = None
    if len(request.get_data()) > 0:
        new_json = request.json

    gcp_response = send_gcp_request(request, new_headers, new_url, new_json=new_json)
    return Response(gcp_response.content, gcp_response.status_code, new_headers)


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
    service_acct_cred_file = get_service_account_path()
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


def create_authorization_route(cloud):
    print("Create authorization handler")
    logger = get_logger()
    authorization_policy_manager = get_authorization_policy_manager()
    print_and_log(logger, f"Creating authorization (json: {request.json})")
    print(f"Creating authorization (json: {request.json})")

    # Get hash of public key
    public_key_bytes = base64.b64decode(request.headers["X-PublicKey"], validate=True)
    # Compute hash of public key
    public_key_hash = hash_public_key(public_key_bytes)
    print_and_log(logger, f"Public key hash: {public_key_hash}")

    # Retrieve authorization policy from firestore with public key hash
    request_auth_dict = authorization_policy_manager.get_policy_dict(public_key_hash)
    print("Request auth dict:", request_auth_dict)

    # Check request against authorization policy
    authorization_policy = GCPAuthorizationPolicy(policy_dict=request_auth_dict)
    authorization_request, success = authorization_policy.check_request(request)
    if success:
        service_account_id = (
            authorization_policy_manager.create_service_account_with_roles(
                authorization_request
            )
        )
        capability_dict = authorization_policy_manager.generate_capability(
            service_account_id
        )
        return Response(json.dumps(capability_dict), 200)
    return Response("Unauthorized", 401)
