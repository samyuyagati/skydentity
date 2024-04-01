"""
Forwarding for SkyPilot requests.
"""

import json
import logging as py_logging
import os
from collections import namedtuple
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

import requests
from flask import Flask, Response, request

from .logging import get_logger, print_and_log
from .signature import get_headers_with_signature

py_logging.basicConfig(
    filename="redirector_skypilot_forward.log", level=py_logging.INFO
)
pylogger = py_logging.getLogger(__name__)

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


# list of all routes that require special handling;
# all other routes are forwarded directly to the client proxy.
ROUTES: list[SkypilotRoute] = [
    SkypilotRoute(
        methods=["POST"],
        path="/upload/storage/v1/b/<bucket>/o",
        fields=["bucket"],
        # route to specific upload function
        view_func=lambda bucket: upload_blob(request, bucket),
    ),
    SkypilotRoute(
        methods=["GET"],
        path="/download/storage/v1/b/<bucket>/o/<path:file>",
        fields=["bucket", "file"],
        # route to specific download function
        view_func=lambda bucket, file: download_blob(request, bucket, file),
    ),
]

STORAGE_ENDPOINT = "https://storage.googleapis.com"


def generic_forward_request(request, log_dict=None):
    """
    [SkyPilot Integration]
    Forward a generic request to google APIs.
    """
    logger = get_logger()
    pylogger.debug(f"{log_dict}")
    if log_dict is not None:
        log_str = f"PATH: {request.full_path}\n"
        for key, val in log_dict.items():
            log_str += f"\t{key}: {val}\n"
        pylogger.debug(f"{log_str}")
        print_and_log(logger, log_str.strip())

    new_url = get_new_url(request)
    new_headers = get_headers_with_signature(request)
    # pylogger.debug(f"{new_headers}")

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

            pylogger.debug(f"JSON with service acct capability: {new_json}")

    print("Forwarding to client...", flush=True)

    gcp_response = forward_to_client(
        request, new_url, new_headers=new_headers, new_json=new_json
    )

    print(f"Received response from client...\n {gcp_response}", flush=True)
    return Response(gcp_response.content, gcp_response.status_code)


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
    default_view = lambda path: generic_forward_request(request, {"path": path})
    default_view.__name__ = "default_view"

    all_methods = [
        "GET",
        "HEAD",
        "POST",
        "PUT",
        "DELETE",
        "CONNECT",
        "OPTIONS",
        "TRACE",
        "PATCH",
    ]
    app.add_url_rule(
        "/", view_func=default_view, defaults={"path": ""}, methods=all_methods
    )
    app.add_url_rule("/<path:path>", view_func=default_view, methods=all_methods)


def get_client_proxy_endpoint(request):
    """
    Retrieve the correct client proxy endpoint from the client identifier.
    """
    # user_agent = request.headers.get("User-Agent")
    # logger.debug(f"USER AGENT: {user_agent}")

    # TODO: replace with actual fetch
    return os.environ.get("SKYID_CLIENT_ADDRESS", "https://127.0.0.1:5001/")


def get_new_url(request):
    """
    Redirect the URL (originally to the proxy) to the correct client proxy.
    """
    redirect_endpoint = get_client_proxy_endpoint(request)
    logger = get_logger()
    print_and_log(
        logger,
        f"\tOld URL: {request.host_url} (Redirect endpoint: {redirect_endpoint})",
    )
    new_url = request.url.replace(
        # normalize to include one slash
        request.host_url.strip("/") + "/",
        redirect_endpoint.strip("/") + "/",
    )

    print_and_log(logger, f"\tNew URL: {new_url}")
    return new_url


def forward_to_client(
    request, new_url: str, new_headers=None, new_json=None, new_data=None
):
    """
    Forward the request to the client proxy, with new headers, URL, and request body.

    `new_json` specifies the new JSON body, `new_data` specifies the new arbitrary request body
    (not necessarily JSON).
    `new_data` is given precedent if both are specified.
    """
    if new_headers is None:
        # default to the current headers
        new_headers = request.headers

    print(
        f"url {repr(request.url)}\n"
        f"headers {repr(request.headers)}\n"
        f"data {repr(request.get_data())}\n"
    )
    print("NEW\n" f"url {new_url}\n" f"headers {new_headers}\n")

    # If no JSON body, don't include a json body in proxied request
    if len(request.get_data()) == 0:
        return requests.request(
            method=request.method,
            url=new_url,
            headers=new_headers,
            cookies=request.cookies,
            allow_redirects=False,
        )

    if new_data is not None:
        return requests.request(
            method=request.method,
            url=new_url,
            headers=new_headers,
            cookies=request.cookies,
            allow_redirects=False,
            data=new_data,
        )
    elif new_json is not None:
        return requests.request(
            method=request.method,
            url=new_url,
            headers=new_headers,
            json=new_json,
            cookies=request.cookies,
            allow_redirects=False,
        )
    else:
        # keep original body
        return requests.request(
            method=request.method,
            url=new_url,
            headers=new_headers,
            cookies=request.cookies,
            allow_redirects=False,
            data=request.get_data(),
        )


# cache for access tokens
ACCESS_TOKEN_CACHE: Dict[Tuple[str, str], Tuple[str, str]] = {}


def request_storage_access_token(
    bucket: str, action: str
) -> Tuple[Optional[str], Optional[str], int]:
    """
    Requests an access token for a service account for the given bucket and action.

    Returns a tuple containing:
    - access token (or None if error)
    - expiration timestamp in ISO format (or None if error)
    - response status code (for error handling)
    """
    # return token from cache if it exists
    if (bucket, action) in ACCESS_TOKEN_CACHE:
        access_token, expiration_timestamp = ACCESS_TOKEN_CACHE[(bucket, action)]
        if datetime.now(timezone.utc) < datetime.fromisoformat(
            expiration_timestamp
        ).astimezone(timezone.utc):
            # still valid, return it
            return access_token, expiration_timestamp, 200
        # expired; delete from cache
        del ACCESS_TOKEN_CACHE[(bucket, action)]

    client_url = get_client_proxy_endpoint(request).strip("/") + "/"
    headers = get_headers_with_signature(requests.Request(method="POST"))
    response = requests.post(
        client_url + f"skydentity/cloud/gcp/create-storage-authorization",
        json={
            "cloud_provider": "GCP",
            "bucket": bucket,
            "action": action,
        },
        headers=headers,
    )

    if not response.ok:
        return None, None, response.status_code

    response_json = response.json()
    access_token = response_json["access_token"]
    expiration_timestamp = response_json["expires"]
    print("access token", access_token)

    if access_token:
        ACCESS_TOKEN_CACHE[(bucket, action)] = (access_token, expiration_timestamp)
        return access_token, expiration_timestamp, response.status_code

    # no access token; server error
    return None, None, 500


def upload_blob(request, bucket: str):
    """
    POST /upload/storage/v1/b/<bucket>/o
    """
    access_token, expiration_timestamp, req_status = request_storage_access_token(
        bucket, "OVERWRITE_FALLBACK_UPLOAD"
    )
    if access_token is None or expiration_timestamp is None:
        if 400 <= req_status < 500:
            # auth error
            return Response("Unauthorized", 401)
        return Response("Error creating authorization", 500)

    # check expiration timestamp
    expiration_datetime = datetime.fromisoformat(expiration_timestamp).astimezone(
        timezone.utc
    )
    if datetime.now(timezone.utc) > expiration_datetime:
        return Response("Expired credentials", 401)

    # attach access token
    new_headers = {k: v for k, v in request.headers}
    new_headers["Authorization"] = f"Bearer {access_token}"
    del new_headers["Host"]

    # get new url directly to the storage endpoint
    storage_url = request.url.replace(
        # normalize to include one slash
        request.host_url.strip("/") + "/",
        STORAGE_ENDPOINT.strip("/") + "/",
    )

    # forward directly to the GCP endpoint; no need to go through client proxy
    gcp_response = forward_to_client(request, storage_url, new_headers=new_headers)
    print(gcp_response.content)
    return Response(gcp_response.content, gcp_response.status_code)


def download_blob(request, bucket: str, file: str):
    """
    GET /download/storage/v1/b/<bucket>/o/<file:path>
    """
    access_token, expiration_timestamp, req_status = request_storage_access_token(
        bucket, "READ"
    )
    if access_token is None or expiration_timestamp is None:
        if 400 <= req_status < 500:
            # auth error
            return Response("Unauthorized", 401)
        return Response("Error creating authorization", 500)

    # check expiration timestamp
    expiration_datetime = datetime.fromisoformat(expiration_timestamp).astimezone(
        timezone.utc
    )
    if datetime.now(timezone.utc) > expiration_datetime:
        return Response("Expired credentials", 401)

    # attach access token
    new_headers = {k: v for k, v in request.headers}
    new_headers["Authorization"] = f"Bearer {access_token}"
    del new_headers["Host"]

    # get new url directly to the storage endpoint
    storage_url = request.url.replace(
        # normalize to include one slash
        request.host_url.strip("/") + "/",
        STORAGE_ENDPOINT.strip("/") + "/",
    )

    # forward directly to the GCP endpoint; no need to go through client proxy
    gcp_response = forward_to_client(request, storage_url, new_headers=new_headers)
    print(gcp_response.content)
    return Response(gcp_response.content, gcp_response.status_code)
