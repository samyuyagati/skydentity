"""
Forwarding for SkyPilot requests.
"""
import base64
import datetime
import json
import os
import time
from collections import namedtuple
import random
import requests
import logging as py_logging
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from flask import Flask, Response, request
from flask import stream_with_context
from typing import Dict, Optional, Tuple
from functools import cache
from .logging import build_time_logging_string

LOGGER = py_logging.getLogger(__name__)
py_logging.basicConfig(filename='redirector.log',
                    filemode='a',
                    format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                    datefmt='%H:%M:%S',
                    level=py_logging.INFO)

# reuse the request session across multiple forwarding calls
# otherwise, there are some issues with connectivity latency
REQUEST_SESSION = requests.Session()
adapter = requests.adapters.HTTPAdapter(pool_connections=20, pool_maxsize=20)
REQUEST_SESSION.mount('http://', adapter)
REQUEST_SESSION.mount('https://', adapter)

# global constants
STORAGE_ENDPOINT = os.environ.get(
    "STORAGE_ENDPOINT", "https://skydentity.blob.core.windows.net"
)

PRIVATE_KEY_PATH = os.environ.get(
    "PRIVATE_KEY_PATH", "proxy_util/private_key.pem" 
)
with open(PRIVATE_KEY_PATH, "rb") as key_file:
    PRIVATE_KEY = RSA.import_key(key_file.read())

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
    SkypilotRoute(
        methods=["GET", "PUT"],
        path="/<container>/<blob>",
        fields=["container", "blob"],
        view_func=lambda container, blob: handle_blob_request(request, container, blob),
    ),
    # skydentity internal route
    SkypilotRoute(
        methods=["POST"],
        path="/skydentity/cloud/<cloud>/create-authorization",
        fields=["cloud"]
    ),
]

def get_headers_with_signature(request):
    new_headers = {k: v for k, v in request.headers}

    private_key = PRIVATE_KEY
           
    # assume set, predetermined/agreed upon tolerance on client proxy/receiving end
    # use utc for consistency if server runs in cloud in different region
    timestamp = datetime.datetime.now(datetime.timezone.utc).timestamp()
    public_key_string = private_key.public_key().export_key()

    message = f"{str(request.method)}-{timestamp}-{public_key_string}"    
    message_bytes = message.encode("utf-8")

    h = SHA256.new(message_bytes)
    # TODO should we be using PSS?
    signature = pkcs1_15.new(private_key).sign(h)

    # base64 encode the signature and public key
    encoded_signature = base64.b64encode(signature)
    encoded_public_key_string = base64.b64encode(public_key_string)

    new_headers["X-Signature"] = encoded_signature
    new_headers["X-Timestamp"] = str(timestamp)
    new_headers["X-PublicKey"] = encoded_public_key_string

    if "Host" in new_headers:
        del new_headers["Host"]

    return new_headers


def generic_forward_request(request, log_dict=None):
    """
    [SkyPilot Integration]
    Forward a generic request to google APIs.
    """
    generic_forward_start = time.perf_counter()

    # logger = get_logger()
    # print(log_dict, flush=True)
    # if log_dict is not None:
    #     log_str = f"PATH: {request.full_path}\n"
    #     for key, val in log_dict.items():
    #         log_str += f"\t{key}: {val}\n"
    #     print(log_str, flush=True)
    #     print_and_log(logger, log_str.strip())

    new_url = get_new_url(request)
    new_headers = get_headers_with_signature(request)

    # Only modifies the body to attach the service account capability 
    new_json = None
    if len(request.get_data()) > 0:
        old_json = request.json
        # print("Old JSON:", old_json, flush=True)
        if "identity" not in old_json and "deployments" not in request.url:
        # if "identity" not in old_json and "deployments" not in request.url and "resourcegroups" not in request.url:
            new_json = request.json
        else:
            new_json = old_json
            # Check for existence of virtual machine identity field in the template and delete managed identity creation
            contains_identity_field = False
            if "deployments" in request.url:
                if "properties" in new_json:
                    if "template" in new_json["properties"]:
                        if "resources" in new_json["properties"]["template"]:
                            # Make sure to remove all managed identities
                            managed_identity_ids = []
                            for i, resource in enumerate(new_json["properties"]["template"]["resources"]):
                                if "type" in resource:
                                    if resource["type"] == "Microsoft.Compute/virtualMachines":
                                        if "identity" in resource:
                                            # print("Found identity field in the template", flush=True)
                                            contains_identity_field = True
                                    elif resource["type"] == "Microsoft.ManagedIdentity/userAssignedIdentities":
                                        managed_identity_ids.append(i)
                                    elif resource["type"] == "Microsoft.Authorization/roleAssignments":
                                        managed_identity_ids.append(i)
                            
                            for i in range(len(managed_identity_ids) - 1, -1, -1):
                                new_json["properties"]["template"]["resources"].pop(managed_identity_ids[i])

            # if "resourcegroups" in request.url:
            #     contains_identity_field = True

            if not ("deployments" in request.url and not contains_identity_field):
                # TODO don't hardcode the path to the capability
                parent_dir = os.path.dirname(os.getcwd())
                capability_dir = "tokens"
                capability_file = "capability.json"
                capability_path = os.path.join(parent_dir, capability_dir, capability_file)
                with open(capability_path, "r") as f:
                    new_json["managedIdentities"] = [json.load(f)]

            # print("JSON with service acct capability:", new_json, flush=True)

    forward_start = time.perf_counter()
    azure_response = forward_to_client(
        request, new_url, new_headers=new_headers, new_json=new_json
    )
    LOGGER.info(build_time_logging_string(
            request.full_path,
            "skypilot_forward:generic_forward_request",
            "forward_request",
            forward_start,
            time.perf_counter(),
        )
    )

    LOGGER.info(build_time_logging_string(
        request.full_path,
        "skypilot_forward:generic_forward_request",
        "generic_forward_request",
        generic_forward_start,
        time.perf_counter(),
        )
    )

    return Response(azure_response.content, azure_response.status_code, content_type=azure_response.headers["Content-Type"])


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
        
    # set up default route
    default_view = lambda path: generic_forward_request(request, {"path": path})
    default_view.__name__ = "default_view"
    app.add_url_rule("/", view_func=default_view, defaults={"path": ""})
    app.add_url_rule("/<path:path>", view_func=default_view)


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
    # logger = get_logger()
    # print_and_log(logger, f"\tOld URL: {request.host_url} (Redirect endpoint: {redirect_endpoint})")
    new_url = request.url.replace(request.host_url, redirect_endpoint)
    
    # print_and_log(logger, f"\tNew URL: {new_url}")
    return new_url


def forward_to_client(request, new_url: str, new_headers=None, new_json=None, new_data=None, stream=None, use_prepared_request=False):
    """
    Forward the request to the client proxy, with new headers, URL, and request body.
    """
    if new_headers is None:
        # default to the current headers
        new_headers = request.headers

    if use_prepared_request:
        prepared_request = requests.Request(
            method=request.method,
            url=new_url,
            headers=new_headers,
            cookies=request.cookies,
            data=new_data,
            json=new_json,
        ).prepare()
        if "Transfer-Encoding" in prepared_request.headers:
            del prepared_request.headers["Transfer-Encoding"]

        return REQUEST_SESSION.send(prepared_request,
                                    allow_redirects=False,
                                    stream=stream)

    # If no JSON body, don't include a json body in proxied request
    if len(request.get_data()) == 0:
        return REQUEST_SESSION.request(
            method=request.method,
            url=new_url,
            headers=new_headers,
            cookies=request.cookies,
            allow_redirects=False,
            data=new_data,
            stream=stream
        )
    return REQUEST_SESSION.request(
        method=request.method,
        url=new_url,
        headers=new_headers,
        json=new_json,
        cookies=request.cookies,
        allow_redirects=False,
        data=new_data,
        stream=stream
    )

# cache for access tokens
ACCESS_TOKEN_CACHE: Dict[Tuple[str, str], Tuple[str, str]] = {}

def request_storage_token(
    container: str, action: str
) -> Tuple[Optional[str], Optional[str], int]:
    """
    Requests an access token for the given container and actions.

    Returns a tuple containing:
    - access token (or None if error)
    - expiration timestamp (or None if error)
    - response status code (for error handling)
    """
    # return token from cache if it exists
    if (container, action) in ACCESS_TOKEN_CACHE:
        access_token, expiration_timestamp = ACCESS_TOKEN_CACHE[(container, action)]
        if datetime.datetime.now(datetime.timezone.utc) < datetime.datetime.fromisoformat(
            expiration_timestamp
        ).astimezone(datetime.timezone.utc):
            # still valid, return it
            return access_token, expiration_timestamp, 200
        # expired; delete from cache
        del ACCESS_TOKEN_CACHE[(container, action)]

    client_url = get_client_proxy_endpoint(request).strip("/") + "/"
    headers = get_headers_with_signature(requests.Request(method="POST"))
    response = REQUEST_SESSION.post(
        client_url + f"skydentity/cloud/azure/create-storage-authorization",
        json={
            "cloud_provider": "azure",
            "container": container,
            "action": action,
        },
        headers=headers,
    )

    if not response.ok:
        return None, None, response.status_code

    response_json = response.json()
    access_token = response_json["access_token"]
    expiration_timestamp = response_json["expires"]
    LOGGER.debug(f"Access token: {access_token}")

    if access_token:
        # cache the token
        ACCESS_TOKEN_CACHE[(container, action)] = (access_token, expiration_timestamp)
        return access_token, expiration_timestamp, response.status_code

    # no access token; server error
    return None, None, 500

def handle_blob_request(request, container, blob):
    if request.method == "PUT":
        return upload_blob(request, container, blob)
    elif request.method == "GET":
        return download_blob(request, container, blob)

def invalidate_cache(container: str, action: str):
    """
    Invalidate the cache for the given bucket/action.
    """
    ACCESS_TOKEN_CACHE.pop((container, action), None)

def upload_blob(request, container, blob):
    """
    POST /<container>/<blob> - Upload a blob to the specified container.
    """
    request_name = request.method.upper() + str(random.randint(0, 1000)) + request.path
    upload_start = time.perf_counter()

    token_start = time.perf_counter()
    access_token, expiration_timestamp, req_status = request_storage_token(
        container, "OVERWRITE_FALLBACK_UPLOAD"
    )
    LOGGER.info(build_time_logging_string(
            request_name,
            "skypilot_forward:upload_blob",
            "request_storage_token",
            token_start,
            time.perf_counter(),
        )
    )

    if access_token is None or expiration_timestamp is None:
        if 400 <= req_status < 500:
            # auth error
            return Response("Unauthorized", 401)
        return Response("Error creating authorization", 500)

    # check expiration timestamp
    expiration_datetime = datetime.datetime.fromisoformat(expiration_timestamp)
    if datetime.datetime.now(datetime.timezone.utc) > expiration_datetime:
        return Response("Expired credentials", 401)

    # attach access token
    new_headers = {k: v for k, v in request.headers}
    if "Host" in new_headers:
        del new_headers["Host"]

    # get new url directly to the storage endpoint
    storage_url = request.url.replace(
        # normalize to include one slash
        request.host_url.strip("/") + "/",
        STORAGE_ENDPOINT.strip("/") + "/",
    )
    access_token = access_token.replace("%3A", ":")
    if "?" in storage_url:
        storage_url += f"&{access_token}"
    else:
        storage_url += f"?{access_token}"
    LOGGER.debug("Sending to storage URL:", storage_url)
    # forward directly to the Azure endpoint; no need to go through client proxy
    forward_start = time.perf_counter()
    azure_response = forward_to_client(request, storage_url, new_headers=new_headers, new_data=request.stream, use_prepared_request=True)
    LOGGER.info(build_time_logging_string(
            request_name,
            "skypilot_forward:upload_blob",
            "forward_request",
            forward_start,
            time.perf_counter(),
        )
    )
    if azure_response.status_code in (401, 403):
        invalidate_cache(container, "READ")

    LOGGER.info(build_time_logging_string(
        request_name,
        "skypilot_forward:upload_blob",
        "upload_blob",
        upload_start,
        time.perf_counter(),
        )
    )
    return Response(azure_response.content, azure_response.status_code)

def download_blob(request, container, blob):
    """
    GET /<container>/<blob> - Upload a blob to the specified container.
    """
    request_name = request.method.upper() + str(random.randint(0, 1000)) + request.path
    download_start = time.perf_counter()

    token_start = time.perf_counter()
    access_token, expiration_timestamp, req_status = request_storage_token(container, "READ")
    LOGGER.info(build_time_logging_string(
            request_name,
            "skypilot_forward:download_blob",
            "request_storage_token",
            token_start,
            time.perf_counter(),
        )
    )
    if access_token is None or expiration_timestamp is None:
        if 400 <= req_status < 500:
            # auth error
            return Response("Unauthorized", 401)
        return Response("Error creating authorization", 500)

    # check expiration timestamp
    expiration_datetime = datetime.datetime.fromisoformat(expiration_timestamp)
    if datetime.datetime.now(datetime.timezone.utc) > expiration_datetime:
        return Response("Expired credentials", 401)

    # attach access token
    new_headers = {k: v for k, v in request.headers}
    if "Host" in new_headers:
        del new_headers["Host"]

    # get new url directly to the storage endpoint
    storage_url = request.url.replace(
        # normalize to include one slash
        request.host_url.strip("/") + "/",
        STORAGE_ENDPOINT.strip("/") + "/",
    )
    access_token = access_token.replace("%3A", ":")
    storage_url += f"?{access_token}"

    # forward directly to the Azure endpoint; no need to go through client proxy
    forward_start = time.perf_counter()
    azure_response = forward_to_client(request, storage_url, new_headers=new_headers, stream=True)
    LOGGER.info(build_time_logging_string(
            request_name,
            "skypilot_forward:download_blob",
            "forward_request",
            forward_start,
            time.perf_counter(),
        )
    )    
    if azure_response.status_code in (401, 403):
        invalidate_cache(container, "READ")

    LOGGER.info(build_time_logging_string(
        request_name,
        "skypilot_forward:download_blob",
        "download_blob",
        download_start,
        time.perf_counter(),
        )
    )
    return Response(stream_with_context(azure_response.iter_content(chunk_size=None)), azure_response.status_code, headers=dict(azure_response.headers))