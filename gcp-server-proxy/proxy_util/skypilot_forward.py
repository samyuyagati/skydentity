"""
Forwarding for SkyPilot requests.
"""
import base64
import datetime
import json
import os
from collections import namedtuple

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from flask import Flask, Response, request

from .logging import get_logger, print_and_log

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
    SkypilotRoute(
        methods=["POST"],
        path="/skydentity/cloud/<cloud>/create-authorization",
        fields=["cloud"]
    ),
]


def get_headers_with_signature(request):
    new_headers = {k: v for k, v in request.headers}

    with open("proxy_util/private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )

    # assume set, predetermined/agreed upon tolerance on client proxy/receiving end
    # use utc for consistency if server runs in cloud in different region
    timestamp = datetime.datetime.now(datetime.timezone.utc).timestamp()
    host = new_headers.get("Host", "")
    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    message = f"{str(request.method)}-{host}-{timestamp}-{public_key_bytes}"
    message_bytes = message.encode("utf-8")

    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )

    # base64 encode the signature and public key
    encoded_signature = base64.b64encode(signature)
    encoded_public_key_bytes = base64.b64encode(public_key_bytes)

    new_headers["X-Signature"] = encoded_signature
    new_headers["X-Timestamp"] = str(timestamp)
    new_headers["X-PublicKey"] = encoded_public_key_bytes

    del new_headers["Host"]

    return new_headers


def generic_forward_request(request, log_dict=None):
    """
    [SkyPilot Integration]
    Forward a generic request to google APIs.
    """
    logger = get_logger()
    print(log_dict, flush=True)
    if log_dict is not None:
        log_str = f"PATH: {request.full_path}\n"
        for key, val in log_dict.items():
            log_str += f"\t{key}: {val}\n"
        print(log_str, flush=True)
        print_and_log(logger, log_str.strip())

    new_url = get_new_url(request)
    new_headers = get_headers_with_signature(request)

    # Only modifies the body to attach the service account capability 
    new_json = None
    if len(request.get_data()) > 0:
        old_json = request.json
        if "serviceAccounts" not in old_json:
            new_json = request.json
        else:
            new_json = old_json
            # TODO don't hardcode the path to the capability
            parent_dir = os.path.dirname(os.getcwd())
            capability_dir = "tokens"
            capability_file = "capability.json"
            capability_path = os.path.join(parent_dir, capability_dir, capability_file)
            with open(capability_path, "r") as f:
                new_json["serviceAccounts"] = [json.load(f)]

            print("JSON with service acct capability:", new_json, flush=True)

    gcp_response = forward_to_client(
        request, new_url, new_headers=new_headers, new_json=new_json
    )
    return Response(gcp_response.content, gcp_response.status_code)


def build_generic_forward(path: str, fields: list[str]):
    """
    Return the appropriate generic forward view function for the fields provided.

    The path is only used to create a unique and readable name for the anonymous function.
    """
    func = None
    if fields == ["cloud"]:
        func = lambda cloud: generic_forward_request(request, {"cloud": cloud})
    elif fields == ["project"]:
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


def get_client_proxy_endpoint(request):
    """
    Retrieve the correct client proxy endpoint from the client identifier.
    """
    # user_agent = request.headers.get("User-Agent")
    # print(f"USER AGENT: {user_agent}")

    # TODO: replace with actual fetch
    return os.environ.get("SKYID_CLIENT_ADDRESS", "https://127.0.0.1:5001/")


def get_new_url(request):
    """
    Redirect the URL (originally to the proxy) to the correct client proxy.
    """
    redirect_endpoint = get_client_proxy_endpoint(request)
    logger = get_logger()
    print_and_log(logger, f"\tOld URL: {request.host_url} (Redirect endpoint: {redirect_endpoint})")
    new_url = request.url.replace(request.host_url, redirect_endpoint)
    
    print_and_log(logger, f"\tNew URL: {new_url}")
    return new_url


def forward_to_client(request, new_url: str, new_headers=None, new_json=None):
    """
    Forward the request to the client proxy, with new headers, URL, and request body.
    """
    if new_headers is None:
        # default to the current headers
        new_headers = request.headers

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
