"""
Forwarding for SkyPilot requests.
"""
import time

import random
import base64
import json
import os
<<<<<<< HEAD
import re
=======
>>>>>>> 692e67e (Azure Default Deny (#25))
from collections import namedtuple
from urllib.parse import urlparse

import requests
from flask import Flask, Response, request

from skydentity.policies.checker.azure_authorization_policy import AzureAuthorizationPolicy
from skydentity.utils.hash_util import hash_public_key

from .credentials import (
    get_managed_identity_auth_token,
    _generate_rsa_key_pair
)
from .logging import get_logger, print_and_log, build_time_logging_string
from .policy_check import check_request_from_policy, get_authorization_policy_manager
from .signature import strip_signature_headers, verify_request_signature

# global constants
COMPUTE_API_ENDPOINT = os.environ.get(
    "COMPUTE_API_ENDPOINT", "https://management.azure.com/"
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
        path="/subscriptions/<subscriptionId>/providers/Microsoft.Compute/virtualMachines",
        fields=["subscriptionId"],
    ),
    SkypilotRoute(
        methods=["GET", "PUT", "PATCH"],
        path="/subscriptions/<subscriptionId>/resourceGroups/<resourceGroupName>/providers/Microsoft.Compute/virtualMachines/<vmName>",
        fields=["subscriptionId", "resourceGroupName", "vmName"],
    ),
    SkypilotRoute(
        methods=["GET"],
        path="/subscriptions/<subscriptionId>/resourceGroups/<resourceGroupName>/providers/Microsoft.Compute/virtualMachines",
        fields=["subscriptionId", "resourceGroupName"],
    ),
    SkypilotRoute(
        methods=["PUT"],
        path="/subscriptions/<subscriptionId>/resourcegroups/<resourceGroupName>",
        fields=["subscriptionId", "resourceGroupName"],
    ),
    SkypilotRoute(
        methods=["GET", "PUT"],
        path="/subscriptions/<subscriptionId>/resourceGroups/<resourceGroupName>/providers/Microsoft.Network/networkInterfaces/<nicName>",
        fields=["subscriptionId", "resourceGroupName", "nicName"],
    ),
    SkypilotRoute(
        methods=["GET", "PUT"],
        path="/subscriptions/<subscriptionId>/resourceGroups/<resourceGroupName>/providers/Microsoft.Network/publicIPAddresses/<ipName>",
        fields=["subscriptionId", "resourceGroupName", "ipName"],
    ),
    SkypilotRoute(
        methods=["GET"],
        path="/subscriptions/<subscriptionId>/providers/Microsoft.Compute/locations/<region>/operations/<operationId>",
        fields=["subscriptionId", "region", "operationId"],
    ),
    SkypilotRoute(
        methods=["GET", "PUT"],
        path="/subscriptions/<subscriptionId>/resourceGroups/<resourceGroupName>/providers/Microsoft.Network/virtualNetworks/<virtualNetworkName>",
        fields=["subscriptionId", "resourceGroupName", "virtualNetworkName"],
    ),
    SkypilotRoute(
        methods=["GET", "PUT"],
        path="/subscriptions/<subscriptionId>/resourceGroups/<resourceGroupName>/providers/Microsoft.Network/virtualNetworks/<virtualNetworkName>/subnets/<subnetName>",
        fields=["subscriptionId", "resourceGroupName", "virtualNetworkName", "subnetName"],
    ),
    SkypilotRoute(
        methods=["GET", "PUT"],
        path="/subscriptions/<subscriptionId>/resourceGroups/<resourceGroupName>/providers/Microsoft.Network/networkSecurityGroups/<nsgName>",
        fields=["subscriptionId", "resourceGroupName", "nsgName"],
    ),
    SkypilotRoute(
        methods=["GET", "PUT"],
        path="/subscriptions/<subscriptionId>/resourcegroups/<resourceGroupName>/providers/Microsoft.Resources/deployments/<deploymentName>",
        fields=["subscriptionId", "resourceGroupName", "deploymentName"],
    ),
    SkypilotRoute(
        methods=["GET"],
        path="/subscriptions/<subscriptionId>/resourceGroups/<resourceGroupName>/providers/Microsoft.Compute/virtualMachines/<vmName>/instanceView",
        fields=["subscriptionId", "resourceGroupName", "vmName"],
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
    Forward a generic request to Azure APIs.
    """
    try:
        start = time.time()
        logger = get_logger()

        request_name = request.method.upper() + str(random.randint(0, 1000))
        caller = "skypilot_forward:generic_forward_request"

        # if log_dict is not None:
        #     log_str = f"PATH: {request.full_path}\n"
        #     for key, val in log_dict.items():
        #         log_str += f"\t{key}: {val}\n"
        #     print_and_log(logger, log_str.strip())

        print_and_log(logger, build_time_logging_string(request_name, caller, "setup_logs", start, time.time()))

        start_verify_request_signature = time.time()
        if not verify_request_signature(request):
            print_and_log(logger, "Request is unauthorized (signature verification failed)")
            print_and_log(logger, build_time_logging_string(request_name, caller, "total (signature verif. failed)", start, time.time()))
            return Response("Unauthorized", 401)
        print_and_log(logger, build_time_logging_string(request_name, caller, "verify_request_signature", start_verify_request_signature, time.time()))

        # Check the request
        start_check_request_from_policy = time.time()
        public_key_bytes = base64.b64decode(request.headers["X-PublicKey"], validate=True)
        authorized, managed_identity_id = check_request_from_policy(public_key_bytes, request, request_id=request_name, caller_name=caller)
        print_and_log(logger, build_time_logging_string(request_name, caller, "check_request_from_policy", start_check_request_from_policy, time.time()))
        if not authorized:
            print_and_log(logger, "Request is unauthorized (policy check failed)")
            print_and_log(logger, build_time_logging_string(request_name, caller, "total (policy check failed)", start, time.time()))
            return Response("Unauthorized", 401)

        # Get new endpoint and new headers
        start_get_new_url = time.time()
        new_url = get_new_url(request)
        print_and_log(logger, build_time_logging_string(request_name, caller, "get_new_url", start_get_new_url, time.time()))
        start_get_new_headers = time.time()
        new_headers = get_headers_with_auth(request)
        print_and_log(logger, build_time_logging_string(request_name, caller, "get_headers_with_auth", start_get_new_headers, time.time()))

        # Only modify the JSON if a valid service account capability was provided
        new_json = None
        if len(request.get_data()) > 0:
            start_get_json_with_sa = time.time()
            new_json = request.json
            if managed_identity_id:
                new_json = get_json_with_managed_identity(request, managed_identity_id)
                # print_and_log(logger, f"Json with service account: {new_json}")
            print_and_log(logger, build_time_logging_string(request_name, caller, "get_json_with_service_account", start_get_json_with_sa, time.time()))

            # Inject random public ssh keys if applicable
            inject_random_public_key(new_json, new_url)

        # Send the request to Azure
        start_send_azure_request = time.time()
        azure_response = send_azure_request(request, new_headers, new_url, new_json=new_json)
        
        print_and_log(logger, build_time_logging_string(request_name, caller, "send_azure_request", start_send_azure_request, time.time()))
        print_and_log(logger, build_time_logging_string(request_name, caller, "total", start, time.time()))
        return Response(azure_response.content, azure_response.status_code, headers=new_headers, content_type=azure_response.headers["Content-Type"])
    except Exception as e:
        print_and_log(logger, f"Error in generic_forward_request: {e}")
        return Response("Error", 500)

def build_generic_forward(path: str, fields: list[str]):
    """
    Return the appropriate generic forward view function for the fields provided.

    The path is only used to create a unique and readable name for the anonymous function.
    """
    func = lambda **kwargs: generic_forward_request(request, kwargs)

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

def get_json_with_managed_identity(request, managed_identity_id):
    """
    Modify the JSON of the request to include service account details.
    """
    json_dict = request.json
    managed_identity_dict = {
        "type": "UserAssigned",
        "userAssignedIdentities": {
            managed_identity_id: {}
        }
    }
    new_dict = json_dict.copy()

    # TODO(kdharmarajan): Clean this up later
    ssh_settings_dict = []
    if "deployments" in request.url:
        vm_resource = {}
        resources = new_dict["properties"]["template"]["resources"]
        for resource in resources:
            if resource["type"] == "Microsoft.Compute/virtualMachines":
                vm_resource = resource
                break
        vm_resource["identity"] = managed_identity_dict
    else:
        new_dict["identity"] = managed_identity_dict
    del new_dict["managedIdentities"]
    return new_dict

def inject_random_public_key(request_body, request_url):
    """
    Inject a random public key into the request JSON.

    This function directly modifies the request_body if applicable
    """
    vm_body = request_body
    if "deployments" in request.url:
        resources = vm_body["properties"]["template"]["resources"]
        for resource in resources:
            if resource["type"] == "Microsoft.Compute/virtualMachines":
                vm_body = resource
                break

    if "properties" in vm_body:
        if "osProfile" in vm_body["properties"]:
            if "linuxConfiguration" in vm_body["properties"]["osProfile"]:
                if "ssh" in vm_body["properties"]["osProfile"]["linuxConfiguration"]:
                    if "publicKeys" in vm_body["properties"]["osProfile"]["linuxConfiguration"]["ssh"]:
                        new_public_key = _generate_rsa_key_pair()
                        vm_body["properties"]["osProfile"]["linuxConfiguration"]["ssh"]["publicKeys"] = [{
                            "path": vm_body["properties"]["osProfile"]["linuxConfiguration"]["ssh"]["publicKeys"][0]["path"],
                            "keyData": new_public_key[0]
                        }]


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

    auth_token_process_out_bytes = get_managed_identity_auth_token()

    auth_token = auth_token_process_out_bytes.strip()
    # print_and_log(logger, f"AUTH TOKEN: {auth_token}")
    new_headers["Authorization"] = f"Bearer {auth_token}"

    clean_new_headers = strip_signature_headers(new_headers)
    return clean_new_headers


def get_new_url(request):
    """
    Redirect the URL (originally to the proxy) to the correct Azure endpoint.
    """
    new_url = request.url.replace(request.host_url, f"{COMPUTE_API_ENDPOINT}")
    # logger = get_logger()
    # print_and_log(logger, f"\tNew URL: {new_url}")
    return new_url


def send_azure_request(request, new_headers, new_url, new_json=None):
    """
    Send a request to the Azure endpoint, with new headers, URL, and request body.
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
    try:
        logger = get_logger()
        authorization_policy_manager = get_authorization_policy_manager()
        print_and_log(logger, f"Creating authorization (json: {request.json})")

        public_key_bytes = base64.b64decode(request.headers["X-PublicKey"], validate=True)
        # Compute hash of public key
        public_key_hash = hash_public_key(public_key_bytes)
        print_and_log(logger, f"Public key hash: {public_key_hash}")
        request_auth_dict = authorization_policy_manager.get_policy_dict(public_key_hash)
        print("Request auth dict:", request_auth_dict)
        authorization_policy = AzureAuthorizationPolicy(policy_dict=request_auth_dict)
        authorization_request, success = authorization_policy.check_request(request)
        if success:
            managed_identity_id = (
                authorization_policy_manager.create_managed_identity_with_roles(
                    authorization_request
                )
            )
            capability_dict = authorization_policy_manager.generate_capability(
                managed_identity_id
            )
            return Response(json.dumps(capability_dict), 200)
        return Response("Unauthorized", 401)
    except Exception as e:
        print_and_log(logger, f"Error in create_authorization_route: {e}")
        return Response("Error", 500)