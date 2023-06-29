from flask import Flask
from flask import request, Response
from markupsafe import escape
from os import listdir
from os.path import isfile, join

import os
import requests
from urllib.parse import urlparse

app = Flask(__name__)

CREDS_PATH = "/Users/samyu/.cloud_creds/gcp"
COMPUTE_API_ENDPOINT = "https://compute.googleapis.com/"
#SERVICE_ACCT_EMAIL = "terraform@sky-identity.iam.gserviceaccount.com"
CERT_DIR = "/Users/samyu/skydentity/certs"

def get_gcp_creds():
    cred_files = [f for f in listdir(CREDS_PATH) if isfile(join(CREDS_PATH, f))]
    return os.path.join(CREDS_PATH, cred_files[0])

def get_headers_with_auth(request):
    ## Get authorization token and add to headers
    new_headers = {k:v for k,v in request.headers} # if k.lower() == 'host'}

    print("ORIGINAL HEADERS:", new_headers)
    parsed_compute_api_endpoint = urlparse(f"{COMPUTE_API_ENDPOINT}")
    hostname = parsed_compute_api_endpoint.netloc
    new_headers["Host"] = f'{hostname}'
 
    # Activate service account and get auth token
    service_acct_creds = get_gcp_creds()
    os.popen(f"gcloud auth activate-service-account --key-file={service_acct_creds}")
    
    auth_token_stream = os.popen(f"gcloud auth print-access-token")
    auth_token = auth_token_stream.read().strip()
 
    new_headers["Authorization"] = f"Bearer {auth_token}"
    return new_headers

def get_new_url(request, new_headers):
    new_url = request.url.replace(request.host_url, f'{COMPUTE_API_ENDPOINT}')
    print(new_url)
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
        json            = request.json,
        cookies         = request.cookies,
        allow_redirects = False,
    )

#@app.before_request
#def before_request():
#    os.environ["REQUESTS_CA_BUNDLE"] = os.path.join(CERT_DIR, "server.crt")
 
@app.route("/compute/v1/projects/<project>/global/images/family/<family>", methods=["GET"])
def get_image(project, family):
    print("Incoming GET IMAGE request information----------------------------------")
    print(project)
    print(family)
#    print(request.data)
    print("\nJSON:", request.is_json, "\n")
    print("REQUEST LEN:", len(request.get_data()))
    print("Setting new headers")
    new_headers = get_headers_with_auth(request)
    print("NEW HEADERS:", new_headers)
    print("Creating proxy request")
    proxy_req = get_new_url(request, new_headers)

    print("Proxied request:", proxy_req)
    return Response(proxy_req.content, proxy_req.status_code, new_headers)

@app.route("/compute/v1/projects/<project>/zones/<region>/instances", methods=["POST"])
def create_vm(project, region):
    print("Incoming POST INSTANCES request information----------------------------------")
    print(project)
    print(region)
    print(request.data)
    print(request.json)
#    os.environ["REQUEST_CA_BUNDLE"] = os.path.join(CERT_DIR, "server.crt")
#    print("REQUESTS_CA_BUNDLE:", os.environ["REQUESTS_CA_BUNDLE"])
    print(request.get_data())
 
    ## Get authorization token and add to headers
    new_headers = get_headers_with_auth(request) 
    
    ## Redirect request to GCP endpoint
    proxy_req = get_new_url(request, new_headers) 

    ## TODO: Spawn a new request for firewall rule creation (for http/s traffic allowed)

    return Response(proxy_req.content, proxy_req.status_code, new_headers)

# TODO handler for firewall rule creation

@app.after_request
def after(response):
    print("Response information------------------------------------")
    print(response.status)
    print(response.headers)
    print(response.get_data())
    return response

if __name__ == "__main__":
    app.run('127.0.0.1', debug=False, port=5000, ssl_context=(os.path.join(CERT_DIR, 'server.crt'), 
            os.path.join(CERT_DIR, 'server.key')))
