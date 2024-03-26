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

from skydentity.policies.checker.azure_authorization_policy import AzureAuthorizationPolicy
from skydentity.utils.hash_util import hash_public_key

from .credentials import (
    get_managed_identity_auth_token,
)
from .logging import get_logger, print_and_log
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
    public_key_bytes = base64.b64decode(request.headers["X-PublicKey"], validate=True)
    authorized, managed_identity_id = check_request_from_policy(public_key_bytes, request)
    if not authorized:
        print_and_log(logger, "Request is unauthorized")
        return Response("Unauthorized", 401)
    
    # TODO: Delete this print statement
    try:
        print(request.json)
    except:
        pass

    # Get new endpoint and new headers
    new_url = get_new_url(request)
    new_headers = get_headers_with_auth(request)

    # Only modify the JSON if a valid service account capability was provided
    new_json = None
    if len(request.get_data()) > 0:
        new_json = request.json
        if managed_identity_id:
            new_json = get_json_with_managed_identity(request, managed_identity_id)
            print_and_log(logger, f"Json with service account: {new_json}")

    azure_response = send_azure_request(request, new_headers, new_url, new_json=new_json)
    return Response(azure_response.content, azure_response.status_code, headers=new_headers, content_type=azure_response.headers["Content-Type"])


def build_generic_forward(path: str, fields: list[str]):
    """
    Return the appropriate generic forward view function for the fields provided.

    The path is only used to create a unique and readable name for the anonymous function.
    """
    func = None
    if fields == ["cloud"]:
        func = lambda cloud: generic_forward_request(request, {"cloud": cloud})
    elif fields == ["subscriptionId"]:
        func = lambda subscriptionId: generic_forward_request(request, {"subscriptionId": subscriptionId})
    elif fields == ["subscriptionId", "resourceGroupName"]:
        func = lambda subscriptionId, resourceGroupName: generic_forward_request(
            request, {"subscriptionId": subscriptionId, "resourceGroupName": resourceGroupName}
        )
    elif fields == ["subscriptionId", "resourceGroupName", "nicName"]:
        func = lambda subscriptionId, resourceGroupName, nicName: generic_forward_request(
            request, {"subscriptionId": subscriptionId, "resourceGroupName": resourceGroupName, "nicName": nicName}
        )
    elif fields == ["subscriptionId", "resourceGroupName", "ipName"]:
        func = lambda subscriptionId, resourceGroupName, ipName: generic_forward_request(
            request, {"subscriptionId": subscriptionId, "resourceGroupName": resourceGroupName, "ipName": ipName}
        )
    elif fields == ["subscriptionId", "region", "operationId"]:
        func = lambda subscriptionId, region, operationId: generic_forward_request(
            request, {"subscriptionId": subscriptionId, "region": region, "operationId": operationId}
        )
    elif fields == ["subscriptionId", "resourceGroupName", "virtualNetworkName"]:
        func = lambda subscriptionId, resourceGroupName, virtualNetworkName: generic_forward_request(
            request, {"subscriptionId": subscriptionId, "resourceGroupName": resourceGroupName, "virtualNetworkName": virtualNetworkName}
        )
    elif fields == ["subscriptionId", "resourceGroupName", "virtualNetworkName", "subnetName"]:
        func = lambda subscriptionId, resourceGroupName, virtualNetworkName, subnetName: generic_forward_request(
            request, {"subscriptionId": subscriptionId, "resourceGroupName": resourceGroupName, "virtualNetworkName": virtualNetworkName, "subnetName": subnetName}
        )
    elif fields == ["subscriptionId", "resourceGroupName", "vmName"]:
        func = lambda subscriptionId, resourceGroupName, vmName: generic_forward_request(
            request, {"subscriptionId": subscriptionId, "resourceGroupName": resourceGroupName, "vmName": vmName}
        )
    elif fields == ["subscriptionId", "resourceGroupName", "nsgName"]:
        func = lambda subscriptionId, resourceGroupName, nsgName: generic_forward_request(
            request, {"subscriptionId": subscriptionId, "resourceGroupName": resourceGroupName, "nsgName": nsgName}
        )
    elif fields == ["subscriptionId", "resourceGroupName", "deploymentName"]:
        func = lambda subscriptionId, resourceGroupName, deploymentName: generic_forward_request(
            request, {"subscriptionId": subscriptionId, "resourceGroupName": resourceGroupName, "deploymentName": deploymentName}
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
    if "deployments" in request.url:
        vm_resource = {}
        resources = new_dict["properties"]["template"]["resources"]
        for resource in resources:
            if resource["type"] == "Microsoft.Compute/virtualMachines":
                vm_resource = resource
                break
        vm_resource["identity"] = managed_identity_dict
        import pdb; pdb.set_trace()
    else:
        new_dict["identity"] = managed_identity_dict
    del new_dict["managedIdentities"]
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
    logger = get_logger()
    print_and_log(logger, f"\tNew URL: {new_url}")
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
    logger = get_logger()
    authorization_policy_manager = get_authorization_policy_manager()
    print_and_log(logger, f"Creating authorization (json: {request.json})")

    public_key_bytes = base64.b64decode(request.headers["X-PublicKey"], validate=True)
    # Compute hash of public key
    public_key_hash = hash_public_key(public_key_bytes)
    print("Attempting to get public key hash:", public_key_hash)
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
