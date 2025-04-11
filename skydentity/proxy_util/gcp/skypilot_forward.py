"""
Forwarding for requests to the client proxy.
"""

import base64
import json
import logging as py_logging
import os
import random
import time
from collections import namedtuple
from datetime import datetime
from urllib.parse import urlparse

from flask import Flask, Response, request

from skydentity.policies.checker.crosscloud_resources.crosscloud_resource_policy import (
    CrossCloudPolicy,
)
from skydentity.policies.checker.gcp_storage_policy import (
    GCPStoragePolicy,
)
from skydentity.proxy_util.crosscloud_resources.signature import (
    SignatureContent,
    validate_signature,
)

from ...policies.checker.gcp_authorization_policy import GCPAuthorizationPolicy
from ...utils.hash_util import hash_public_key
from ...utils.log_util import build_time_logging_string
from ...utils.signature import strip_signature_headers, verify_request_signature
from .credentials import (
    activate_service_account,
    get_crosscloud_policy_manager,
    get_crosscloud_service_account_manager,
    get_global_state_manager,
    get_service_account_auth_token,
    get_service_account_path,
)
from .policy_check import (
    check_request_from_policy,
    get_authorization_policy_manager,
    get_storage_policy_manager,
)
from .session import get_session

LOGGER = py_logging.getLogger(__name__)

# global constants
COMPUTE_API_ENDPOINT = os.environ.get(
    "COMPUTE_API_ENDPOINT", "https://compute.googleapis.com/"
)

Route = namedtuple(
    "Route",
    [
        "methods",  # HTTP methods for the route
        "path",  # Flask rule for the route path
        "fields",  # fields in the routing rule
        "view_func",  # explicit view function to use; optional
    ],
    defaults=[None, None],  # defaults for "fields" and "view_func"
)


# list of all routes required for the client proxy;
# all other routes will be denied.
ROUTES: list[Route] = [
    # VM creation routes
    Route(
        methods=["GET"],
        path="/compute/v1/projects/<project>/global/images/family/<family>",
        fields=["project", "family"],
    ),
    Route(
        methods=["GET"],
        path="/compute/v1/projects/<project>/global/images/<image>",
        fields=["project", "image"],
    ),
    Route(
        methods=["GET"],
        path="/compute/v1/projects/<project>/aggregated/instances",
        fields=["project"],
    ),
    Route(
        methods=["POST", "GET"],
        path="/compute/v1/projects/<project>/zones/<region>/instances",
        fields=["project", "region"],
    ),
    Route(
        methods=["GET"],
        path="/compute/v1/projects/<project>/regions/<region>",
        fields=["project", "region"],
    ),
    Route(
        methods=["GET"],
        path="/compute/v1/projects/<project>/aggregated/reservations",
        fields=["project"],
    ),
    Route(
        methods=["GET"],
        path="/compute/v1/projects/<project>",
        fields=["project"],
    ),
    Route(
        methods=["GET", "POST"],
        path="/compute/v1/projects/<project>/global/networks",
        fields=["project"],
    ),
    Route(
        methods=["GET", "POST"],
        path="/compute/v1/projects/<project>/global/firewalls",
        fields=["project"],
    ),
    Route(
        methods=["GET"],
        path="/compute/v1/projects/<project>/global/networks/<network>",
        fields=["project", "network"],
    ),
    Route(
        methods=["GET"],
        path="/compute/v1/projects/<project>/global/networks/<network>/getEffectiveFirewalls",
        fields=["project", "network"],
    ),
    Route(
        methods=["GET"],
        path="/compute/v1/projects/<project>/zones/<region>",
        fields=["project", "region"],
    ),
    Route(
        methods=["GET"],
        path="/compute/v1/projects/<project>/regions/<region>/subnetworks",
        fields=["project", "region"],
    ),
    Route(
        methods=["GET"],
        path="/compute/v1/projects/<project>/global/operations/<operation>",
        fields=["project", "operation"],
    ),
    Route(
        methods=["GET"],
        path="/compute/v1/projects/<project>/zones/<region>/operations/<operation>",
        fields=["project", "region", "operation"],
    ),
    Route(
        methods=["GET"],
        path="/compute/v1/projects/<project>/zones/<region>/disks/<instance>",
        fields=["project", "region", "instance"],
    ),
    Route(
        methods=["POST"],
        path="/compute/v1/projects/<project>/zones/<region>/instances/<instance>/setLabels",
        fields=["project", "region", "instance"],
    ),
    Route(
        methods=["POST"],
        path="/compute/v1/projects/<project>/zones/<region>/instances/<instance>/stop",
        fields=["project", "region", "instance"],
    ),
    Route(
        methods=["GET", "DELETE"],
        path="/compute/v1/projects/<project>/zones/<region>/instances/<instance>",
        fields=["project", "region", "instance"],
    ),
    Route(
        methods=["POST"],
        path="/compute/v1/projects/<project>/zones/<region>/instances/<instance>/start",
        fields=["project", "region", "instance"],
    ),
    # storage routes
    Route(
        methods=["POST"],
        path="/upload/storage/v1/b/<bucket>/o",
        fields=["bucket"],
    ),
    Route(
        methods=["GET"],
        path="/download/storage/v1/b/<bucket>/o/<path:file>",
        fields=["bucket", "file"],
    ),
    Route(
        methods=["GET"],
        path="/storage/v1/b/<bucket>/o",
        fields=["bucket"],
    ),
    # skydentity internal routes
    Route(
        methods=["POST"],
        path="/skydentity/cloud/<cloud>/create-authorization",
        fields=["cloud"],
        # wrapper to allow for the function to be defined later
        view_func=lambda cloud: create_authorization_route(cloud),
    ),
    Route(
        methods=["POST"],
        path="/skydentity/cloud/<cloud>/create-storage-authorization",
        fields=["cloud"],
        view_func=lambda cloud: create_storage_authorization_route(cloud),
    ),
    Route(
        methods=["POST"],
        path="/skydentity/cloud/<cloud>/init-storage-authorization",
        fields=["cloud"],
        view_func=lambda cloud: init_storage_authorization_route(cloud),
    ),
    Route(
        methods=["POST"],
        path="/skydentity/cross-cloud/credentials",
        view_func=lambda: generate_crosscloud_credentials_route(),
    ),
]


def generic_forward_request(request, log_dict=None, **kwargs):
    """
    Forward a generic request to google APIs.
    """
    LOGGER.debug("forwarding request %s", request)
    start = time.time()

    request_name = (
        request.method.upper() + str(random.randint(0, 1000)) + " " + request.path
    )
    caller = "skypilot_forward:generic_forward_request"

    if log_dict is not None:
        log_str = f"PATH: {request.full_path}\n"
        for key, val in log_dict.items():
            log_str += f"\t{key}: {val}\n"
        LOGGER.debug(log_str.strip())

    LOGGER.info(
        build_time_logging_string(
            request_name, caller, "setup_logs", start, time.time()
        ),
    )

    # Verify the request signature
    start_verify_request_signature = time.time()
    if not verify_request_signature(request, request_name, caller):
        LOGGER.debug("Request is unauthorized (signature verification failed)")
        LOGGER.info(
            build_time_logging_string(
                request_name,
                caller,
                "total (signature verif. failed)",
                start,
                time.time(),
            ),
        )
        return Response("Unauthorized", 401)
    LOGGER.info(
        build_time_logging_string(
            request_name,
            caller,
            "verify_request_signature",
            start_verify_request_signature,
            time.time(),
        ),
    )

    # Check the request against the policy for this workload orchestrator
    start_check_request_from_policy = time.time()
    public_key_bytes = base64.b64decode(request.headers["X-PublicKey"], validate=True)
    authorized, service_account_id = check_request_from_policy(
        public_key_bytes, request, request_id=request_name, caller_name=caller
    )
    LOGGER.info(
        build_time_logging_string(
            request_name,
            caller,
            "check_request_from_policy",
            start_check_request_from_policy,
            time.time(),
        ),
    )
    if not authorized:
        LOGGER.debug("Request is unauthorized (policy check failed)")
        LOGGER.info(
            build_time_logging_string(
                request_name, caller, "total (policy check failed)", start, time.time()
            ),
        )
        return Response("Unauthorized", 401)

    # Get new endpoint and new headers
    start_get_new_url = time.time()
    new_url = get_new_url(request)
    LOGGER.info(
        build_time_logging_string(
            request_name, caller, "get_new_url", start_get_new_url, time.time()
        ),
    )
    start_get_new_headers = time.time()
    new_headers = get_headers_with_auth(request)
    LOGGER.info(
        build_time_logging_string(
            request_name,
            caller,
            "get_headers_with_auth",
            start_get_new_headers,
            time.time(),
        ),
    )

    # If a valid service account was provided, attach it to the request
    new_json = None
    if len(request.get_data()) > 0:
        start_get_json_with_sa = time.time()
        new_json = request.json
        if service_account_id:
            new_json = get_json_with_service_account(request, service_account_id)
            LOGGER.debug(f"Json with service account: {new_json}")
        LOGGER.info(
            build_time_logging_string(
                request_name,
                caller,
                "get_json_with_service_account",
                start_get_json_with_sa,
                time.time(),
            ),
        )

    # Send the request to the GCP endpoint
    start_send_gcp_request = time.time()
    gcp_response = send_gcp_request(request, new_headers, new_url, new_json=new_json)
    LOGGER.info(
        build_time_logging_string(
            request_name,
            caller,
            "send_gcp_request",
            start_send_gcp_request,
            time.time(),
        ),
    )
    LOGGER.info(
        build_time_logging_string(request_name, caller, "total", start, time.time()),
    )
    return Response(gcp_response.content, gcp_response.status_code, new_headers)


def build_generic_forward(path: str, fields: list[str]):
    """
    Return a generic forward view function.

    The path is only used to create a unique and readable name for the anonymous function.
    """
    func = lambda **kwargs: generic_forward_request(request, **kwargs)

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
    LOGGER.debug(f"UNKNOWN ROUTE: /{path}")
    return Response("Unknown route; permission denied", 401)


def forward_request_unchecked(request, path=None):
    """
    Default forward to google APIs, with no request or policy checking.

    Attaches credentials for the service account; this function should be used with caution,
    since credentials will be passed along to unchecked requests.
    """
    LOGGER.debug(f"UNCHECKED FORWARD: /{path}")

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
    LOGGER.debug(f"\tNew URL: {new_url}")
    return new_url


def send_gcp_request(request, new_headers, new_url, new_json=None):
    """
    Send a request to the GCP endpoint, with new headers, URL, and request body.
    """
    # If no JSON body, don't include a json body in proxied request
    if len(request.get_data()) == 0:
        return get_session().request(
            method=request.method,
            url=new_url,
            headers=new_headers,
            cookies=request.cookies,
            allow_redirects=False,
        )
    return get_session().request(
        method=request.method,
        url=new_url,
        headers=new_headers,
        json=new_json,
        cookies=request.cookies,
        allow_redirects=False,
    )


def create_authorization_route(cloud):
    LOGGER.debug("Create authorization handler")
    authorization_policy_manager = get_authorization_policy_manager()
    LOGGER.debug(f"Creating authorization (json: {request.json})")

    # Get hash of public key
    public_key_bytes = base64.b64decode(request.headers["X-PublicKey"], validate=True)
    # Compute hash of public key
    public_key_hash = hash_public_key(public_key_bytes)
    LOGGER.debug(f"Public key hash: {public_key_hash}")

    # Retrieve authorization policy from firestore with public key hash
    request_auth_dict = authorization_policy_manager.get_policy_dict(public_key_hash)
    LOGGER.debug(f"Request auth dict: {request_auth_dict}")

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


def create_storage_authorization_route(cloud):
    LOGGER.debug("Create storage authorization handler")

    storage_policy_manager = get_storage_policy_manager()
    LOGGER.debug(f"Creating authorization (json: {request.json})")

    # Get hash of public key
    public_key_bytes = base64.b64decode(request.headers["X-PublicKey"], validate=True)
    # Compute hash of public key
    public_key_hash = hash_public_key(public_key_bytes)
    LOGGER.debug(f"Public key hash: {public_key_hash}")

    # Retrieve authorization policy from firestore with public key hash
    storage_policy_dict = storage_policy_manager.get_policy_dict(public_key_hash)
    LOGGER.debug(f"Storage policy dict: {storage_policy_dict}")

    # Check request against authorization policy
    storage_policy = GCPStoragePolicy(policy_dict=storage_policy_dict)
    request_auth, success = storage_policy.check_request(request)

    if success and request_auth is not None:
        access_token, expiration_timestamp = (
            storage_policy_manager.create_timed_service_account(
                request_auth.bucket, request_auth.action
            )
        )
        LOGGER.debug(
            f"Returning access token {access_token}, expires {expiration_timestamp}"
        )
        return Response(
            json.dumps({"access_token": access_token, "expires": expiration_timestamp}),
            200,
        )
    return Response("Unauthorized", 401)


def init_storage_authorization_route(cloud):
    """
    Initialize the initial cached service accounts.
    """
    LOGGER.debug("Init storage authorization handler")

    storage_policy_manager = get_storage_policy_manager()
    LOGGER.debug("Initializing authorization")

    # Get hash of public key
    public_key_bytes = base64.b64decode(request.headers["X-PublicKey"], validate=True)
    # Compute hash of public key
    public_key_hash = hash_public_key(public_key_bytes)
    LOGGER.debug(f"Public key hash: {public_key_hash}")

    # Retrieve authorization policy from firestore with public key hash
    storage_policy_dict = storage_policy_manager.get_policy_dict(public_key_hash)
    LOGGER.debug(f"Storage policy dict: {storage_policy_dict}")

    # storage authorization policy
    storage_policy = GCPStoragePolicy(policy_dict=storage_policy_dict)
    allowed_actions = storage_policy._policy.actions
    allowed_buckets = storage_policy._policy.buckets

    storage_policy_manager.init_service_accounts(allowed_buckets, allowed_actions)

    return Response(status=204)


def generate_crosscloud_credentials_route():
    """
    Verifies request signature, and then generate credentials for the given VM.

    Expects a request body of the form
    {
        "vm_id": <vm ID>
        "source_cloud": <source cloud name>
        "dest_cloud": "gcp",
        "timestamp": <timestamp of request>
        "signature": <b64-encoded signature on all of the above fields>
    }
    """

    LOGGER.debug("generate crosscloud credentials handler")

    request_body = request.json
    assert request_body is not None

    vm_id = request_body["vm_id"]
    source_cloud = request_body["source_cloud"]
    dest_cloud = request_body["dest_cloud"]
    timestamp = request_body["timestamp"]
    base64_signature = request_body["signature"]

    # use the source cloud and VM ID to fetch the public key; error if not found
    global_state_manager = get_global_state_manager()
    global_state = global_state_manager.fetch_state(source_cloud, vm_id)

    signature_content = SignatureContent(
        vm_id=vm_id,
        source_cloud=source_cloud,
        dest_cloud=dest_cloud,
        timestamp=timestamp,
    )

    valid_signature = validate_signature(
        base64_signature, signature_content, global_state.vm_public_key.encode("utf-8")
    )

    if not valid_signature:
        LOGGER.debug("Invalid signature!")
        return Response("Unauthorized", 401)
    if dest_cloud != "gcp":
        LOGGER.debug("Invalid dest cloud (expected 'gcp', got %s)", dest_cloud)
        return Response("Unauthorized", 401)

    # check timestamp
    try:
        request_time = int(timestamp)
    except ValueError:
        return Response("Bad request: invalid timestamp", 400)

    cur_time = datetime.now().timestamp()

    # timestamps can have deviation of at most 60 seconds
    # (to account for delays and desyncs)
    if abs(cur_time - request_time) > 60:
        LOGGER.debug(
            "Timestamp discrepancy too high; given %d, current time %d",
            request_time,
            cur_time,
        )
        return Response("Unauthorized", 401)

    # fetch the cross-cloud policy
    crosscloud_policy_manager = get_crosscloud_policy_manager()
    crosscloud_policy_dict = crosscloud_policy_manager.get_policy_dict(
        global_state.orchestrator_key_hash
    )
    crosscloud_policy = CrossCloudPolicy(policy_dict=crosscloud_policy_dict)

    # get the access identity in GCP
    service_account_email = crosscloud_policy.get_access_identity(
        global_state.vm_role, cloud="gcp"
    )
    if service_account_email is None:
        return Response("Bad request: VM role no longer found in policy", 400)

    # request valid; generate credentials for the role and return it
    service_account_manager = get_crosscloud_service_account_manager()
    access_token = service_account_manager.generate_credentials(service_account_email)

    return Response(json.dumps({"access_token": access_token}), 200)
