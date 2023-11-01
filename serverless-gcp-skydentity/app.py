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

app = Flask(__name__)

CERT_DIR = "/certs/"
CREDS_PATH = "/cloud_creds/gcp"
COMPUTE_API_ENDPOINT = "https://compute.googleapis.com/"

def get_logger():
    logging_client = logging.Client()
    return logging_client.logger("app_proxy")

def print_and_log(logger, text, severity="WARNING"):
    print(text)
    logger.log_text(text, severity=severity)

def get_gcp_creds():
    cred_files = [f for f in listdir(CREDS_PATH) if isfile(join(CREDS_PATH, f))]
    return os.path.join(CREDS_PATH, cred_files[0])

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


@app.route("/hello", methods=["GET"])
def handle_hello():
    logger = get_logger()
    print_and_log(logger, "Hello!")
    return "Hello"

@app.route("/compute/v1/projects/<project>/global/images/family/<family>", methods=["GET"])
def get_image(project, family):
    logger = get_logger()
    print_and_log(logger, "Incoming GET IMAGE request information----------------------------------")
    print_and_log(logger, f"{project}")
    print_and_log(logger, f"{family}")

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
#    print_and_log(logger, f"DATA {request.data}")
#    print_and_log(logger, f"JSON {request.json}")
    data = request.get_data()
    print_and_log(logger, f"DATA {data}")
    print(type(data))
    print(type(request.json))
    print("JSON ", request.json)
    new_json = get_json_with_service_account(request, "terraform@sky-identity.iam.gserviceaccount.com")
    print("NEW JSON", new_json)
    print_and_log(logger, f"NEW JSON: {new_json}") 
    ## Get authorization token and add to headers
    new_headers = get_headers_with_auth(request) 
    
    ## Redirect request to GCP endpoint
    new_url = get_new_url(request) 

    ## Attach service account to VM
    new_json = get_json_with_service_account(request, "terraform@sky-identity.iam.gserviceaccount.com")

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
