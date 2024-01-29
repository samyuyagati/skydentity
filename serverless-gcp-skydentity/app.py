from flask import Flask
from flask import request, Response
from google.cloud import logging
from markupsafe import escape
from os import listdir
from os.path import isfile, join

import json
import os
import requests
import subprocess
from urllib.parse import urlparse
from skydentity.policies.managers.gcp_policy_manager import GCPPolicyManager
from skydentity.policies.checker.gcp_authorization_policy import GCPAuthorizationPolicy
from skydentity.policies.managers.gcp_authorization_policy_manager import GCPAuthorizationPolicyManager

import pdb

app = Flask(__name__)

#CREDS_DIR = "/Users/samyu/.cloud_creds/gcp/proxy"
CREDS_DIR = "/cloud_creds/gcp/"
ENC_DIR = "/cloud_creds/enc/"
COMPUTE_API_ENDPOINT = "https://compute.googleapis.com/"
CREDS_FILE = "proxy_service_account_key.json"

# Utilities
def get_logger():
    logging_client = logging.Client()
    return logging_client.logger("app_proxy")

def print_and_log(logger, text, severity="WARNING"):
    print(text)
    logger.log_text(text, severity=severity)

def get_gcp_creds():
    # Local testing
    if (not CREDS_DIR.startswith("/cloud_creds")):
        cred_files = [f for f in listdir(CREDS_DIR) if isfile(join(CREDS_DIR, f))]
        assert(len(cred_files) == 1)
        return os.path.join(CREDS_DIR, cred_files[0])
    
    # Serverless
    return os.path.join(CREDS_DIR, CREDS_FILE)

def get_enc_key():
    # Local testing
    if (not CREDS_DIR.startswith("/cloud_creds")):
        return os.path.join("/Users/samyu/.cloud_creds/gcp/proxy-enc/", "capability_enc.key")
    
    # Serverless
    return os.path.join(ENC_DIR, "capability_enc.key")

def check_request_from_policy(public_key, request, authorization_policy_manager) -> (bool, str):
    logger = get_logger()
    print_and_log(logger, f"Check request public key: {public_key} (request: {request})")
    policy = gcp_policy_manager.get_policy(public_key, None)
    policy.set_authorization_manager(authorization_policy_manager)
    print("Got policy", policy)
    print("Request", request)
#    print("Request json:", request.json)
#    breakpoint()
    valid = policy.check_request(request)
    if not valid:
        return (False, None)
    # Check if a service account should be attached to the VM
    if policy.valid_authorization:
        return (True, policy.valid_authorization)
    # If no service account should be attached, return True
    print(">>> CHECK REQUEST: No service account should be attached")
    return (True, None)

def get_json_with_service_account(request, service_account_email):
    json_dict = request.json
    service_account_dict = {'email': f"{service_account_email}",
            'scopes': [f"https://www.googleapis.com/auth/cloud-platform"]}
    new_dict = json_dict.copy()
    new_dict['serviceAccounts'] = [service_account_dict] 
    return new_dict

def get_headers_with_auth(request):
    logger = get_logger()
    print_and_log(logger, "Entered get_headers_with_auth")
    ## Get authorization token and add to headers
    new_headers = {k:v for k,v in request.headers} # if k.lower() == 'host'}

    print_and_log(logger, f"ORIGINAL HEADERS: {new_headers}")
    parsed_compute_api_endpoint = urlparse(f"{COMPUTE_API_ENDPOINT}")
    hostname = parsed_compute_api_endpoint.netloc
    new_headers["Host"] = f'{hostname}'
 
    # Activate service account and get auth token
    service_acct_creds = get_gcp_creds()
    print_and_log(logger, f"SERVICE ACCT CRED PATH: {service_acct_creds}")
    with open(service_acct_creds, 'r') as file:
        json_contents = json.load(file)
        print_and_log(logger, f"SERVICE ACCT CRED CONTENTS: {json_contents}") 

    auth_command = f"gcloud auth activate-service-account --key-file={service_acct_creds}"
    auth_process = subprocess.Popen(auth_command.split())
    auth_process.wait()

    auth_token_command = f"gcloud auth print-access-token"
    auth_token_process = subprocess.Popen(auth_token_command.split(), stdout=subprocess.PIPE)
    auth_token_process_out_bytes, _ = auth_token_process.communicate() 
    auth_token = auth_token_process_out_bytes.strip().decode('utf-8')
    print_and_log(logger, f"AUTH TOKEN: {auth_token}")
    new_headers["Authorization"] = f"Bearer {auth_token}"
    return new_headers

def get_new_url(request):
    new_url = request.url.replace(request.host_url, f'{COMPUTE_API_ENDPOINT}')
    logger = get_logger()
    print_and_log(logger, f"{new_url}")
    return new_url

def send_gcp_request(request, new_headers, new_url, new_json=None):
    # If no JSON body, don't include a json body in proxied request
    if (len(request.get_data()) == 0):
        return requests.request(
                  method = request.method,
                  url = new_url,
                  headers = new_headers,
                  cookies = request.cookies,
                  allow_redirects = False,
               )
    return requests.request(  
        method          = request.method,
        url             = new_url,
        headers         = new_headers,
        json            = new_json,
        cookies         = request.cookies,
        allow_redirects = False,
    )

# Define policy manager object
gcp_policy_manager = GCPPolicyManager(get_gcp_creds())
authorization_policy_manager = GCPAuthorizationPolicyManager(get_gcp_creds(), 
                                                             get_enc_key())
# Handlers

@app.route("/hello", methods=["GET"])
def handle_hello():
    logger = get_logger()
    print_and_log(logger, "Hello!")
    return "Hello"

@app.route("/skydentity/cloud/<cloud>/create-authorization", methods=["POST"])
def create_authorization(cloud):
    logger = get_logger()
    print_and_log(logger, f"Creating authorization (json: {request.json})")
    request_auth_dict = authorization_policy_manager.get_policy_dict("skypilot_eval")
    print("Request auth dict:", request_auth_dict)
    authorization_policy = GCPAuthorizationPolicy(policy_dict=request_auth_dict)
    authorization_request, success = authorization_policy.check_request(request)
    if success:
        service_account_id = authorization_policy_manager.create_service_account_with_roles(authorization_request)
        capability_dict = authorization_policy_manager.generate_capability(service_account_id)
        return Response(json.dumps(capability_dict), 200)
    return Response("Unauthorized", 401)

@app.route("/compute/v1/projects/<project>/global/images/family/<family>", methods=["GET"])
def get_image(project, family):
    logger = get_logger()
    print_and_log(logger, "Incoming GET IMAGE request information----------------------------------")
    print_and_log(logger, f"{project}")
    print_and_log(logger, f"{family}")

    # TODO: Take out the public key from the request
    print("Checking request")
    authorized, _ = check_request_from_policy("skypilot_eval", request, authorization_policy_manager) # Can't attach service acct to image read request
    print("Checked request")
    if not authorized:
        print_and_log(logger, "Request is unauthorized")
        return Response("Unauthorized", 401)

    print("Request is authorized")

    request_length = len(request.get_data())
    print_and_log(logger, "REQUEST LEN: request_length")
    print_and_log(logger, "Setting new headers")
    new_headers = get_headers_with_auth(request)
    print_and_log(logger, f"NEW HEADERS: {new_headers}")
    print_and_log(logger, "Creating proxy request")
    new_url = get_new_url(request)

    # Send request with new url and headers
    gcp_response = send_gcp_request(request, new_headers, new_url)

    print_and_log(logger, f"Proxied request: {gcp_response}")
    return Response(gcp_response.content, gcp_response.status_code, new_headers)

@app.route("/compute/v1/projects/<project>/zones/<region>/instances", methods=["POST"])
def create_vm(project, region):
    logger = get_logger()
    print_and_log(logger, "Incoming POST INSTANCES request information----------------------------------")
    print_and_log(logger, f"{project}")
    print_and_log(logger, f"{region}")

    # TODO: Take out the public key from the request
    authorized, service_account_id = check_request_from_policy("skypilot_eval", request, authorization_policy_manager)
    if not authorized:
        print_and_log(logger, "Request is unauthorized")
        return Response("Unauthorized", 401)

#    print_and_log(logger, f"DATA {request.data}")
#    print_and_log(logger, f"JSON {request.json}")
    data = request.get_data()
    print_and_log(logger, f"DATA {data}")
    print(type(data))
    print(type(request.json))
    print("JSON ", request.json)

    ## Attach service account to VM if present
    new_json = request.json
    if service_account_id:
        new_json = get_json_with_service_account(request, service_account_id)
        print_and_log(logger, f"NEW JSON: {new_json}")

    ## Get authorization token and add to headers
    new_headers = get_headers_with_auth(request) 
    
    ## Redirect request to GCP endpoint
    new_url = get_new_url(request) 

    # Send request
    gcp_response = send_gcp_request(request, new_headers, new_url, new_json=new_json) 

    ## TODO: Spawn a new request for firewall rule creation (for http/s traffic allowed)
    return Response(gcp_response.content, gcp_response.status_code, new_headers)

#@app.after_request
#def after(response):
#    print_and_log(logger, "Response information------------------------------------")
#    print_and_log(logger, response.status)
#    print_and_log(logger, response.headers)
#    print_and_log(logger, response.get_data())
#    return response

def create_app():
    logger = get_logger()
    print_and_log(logger, "Starting up server")
    app = Flask(__name__)
    return app

if __name__ == "__main__":
    app.run('0.0.0.0', debug=False, port=int(os.environ.get("PORT", 8080)), 
            ssl_context=(os.path.join(CERT_DIR, 'domain.crt'), 
            os.path.join("certs/", 'domain.key')))
