from flask import Flask
from flask import request, Response

import os
import requests
import subprocess
from urllib.parse import urlparse

from proxy_server import ProxyServer

class AzureProxyServer(ProxyServer):
    COMPUTE_API_ENDPOINT = "https://management.azure.com/"
    CRED_PATH = "/cloud_creds/azure"
    SERVICE_PRINCIPAL_SECRET = os.path.join(CRED_PATH, "service-principal-secret")

    ROUTES_MAP = {
        "/subscriptions/<subscriptionId>/providers/Microsoft.Compute/virtualMachines": ["GET"],
        "/subscriptions/<subscriptionId>/resourcegroups/<resourceGroupName>": ["PUT"],
        "/subscriptions/<subscriptionId>/resourceGroups/<resourceGroupName>/providers/Microsoft.Network/networkInterfaces/<nicName>": ["GET"],
        "/subscriptions/<subscriptionId>/resourceGroups/<resourceGroupName>/providers/Microsoft.Network/publicIpAddresses/<ipName>": ["GET", "PUT"],
        "/subscriptions/<subscriptionId>/providers/Microsoft.Compute/locations/<region>/operations/<operationId>": ["GET"],
        "/subscriptions/<subscriptionId>/resourceGroups/<resourceGroupName>/providers/Microsoft.Compute/virtualMachines/<vmName>": ["PUT", "GET"],
        "/subscriptions/<subscriptionId>/resourceGroups/<resourceGroupName>/providers/Microsoft.Network/virtualNetworks/<virtualNetworkName>": ["PUT", "GET"],
        "/subscriptions/<subscriptionId>/resourceGroups/<resourceGroupName>/providers/Microsoft.Network/virtualNetworks/<virtualNetworkName>/subnets/<subnetName>": ["PUT", "GET"]
    }

    def __init__(self, flask_server: Flask):
        super().__init__(flask_server)
        self.azure_creds = None

    def setup_routes(self):
        for route, method in AzureProxyServer.ROUTES_MAP.items():
            self.flask_server.route(route, methods=method)(self.process_request)
        self.flask_server.after_request(self.after)

    def get_access_token(self):
        auth_token_stream = os.popen('az account get-access-token --query "accessToken" --output tsv')
        auth_token = auth_token_stream.read().strip()
        return auth_token
    
    def get_azure_creds(self):
        if not self.azure_creds:
            with open(AzureProxyServer.SERVICE_PRINCIPAL_SECRET, "r") as f:
                self.azure_creds = f.read().strip()
        return self.azure_creds

    def get_headers_with_auth(self, request):
        ## Get authorization token and add to headers
        new_headers = {k:v for k,v in request.headers} # if k.lower() == 'host'}

        print("ORIGINAL HEADERS:", new_headers)
        parsed_compute_api_endpoint = urlparse(f"{AzureProxyServer.COMPUTE_API_ENDPOINT}")
        hostname = parsed_compute_api_endpoint.netloc
        new_headers["Host"] = f'{hostname}'

        azure_cred_path = self.get_azure_creds()
        # The app_id and tenant environment variables are something that we have to set based upon what / how the service principal gets created

        # TODO: Watch out for if things get flushed here...
        auth_command = f"az login --service-principal -u {os.environ['APP_ID']} -p {azure_cred_path} --tenant {os.environ['TENANT']}"
        auth_process = subprocess.Popen(auth_command.split())
        auth_process.wait()

        auth_token = self.get_access_token()
        new_headers["Authorization"] = f"Bearer {auth_token}"
        return new_headers

    def get_new_url(self, request, new_headers):
        new_url = request.url.replace(request.host_url, f'{AzureProxyServer.COMPUTE_API_ENDPOINT}')
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
    
    def process_request(self, **kwargs):
        print(f"Incoming {request.method} request information----------------------------------")
        print(*kwargs)
        print("\nJSON:", request.is_json, "\n")
        print("REQUEST LEN:", len(request.get_data()))
        print("Setting new headers")
        new_headers = self.get_headers_with_auth(request)
        print("NEW HEADERS:", new_headers)
        print("Creating proxy request")
        proxy_req = self.get_new_url(request, new_headers)

        print("Proxied request:", proxy_req)
        return Response(proxy_req.content, proxy_req.status_code, new_headers)

    def after(self, response):
        print("Response information------------------------------------")
        print(response.status)
        print(response.headers)
        print(response.get_data())
        return response
    
app = Flask(__name__)
az_server = AzureProxyServer(app)
az_server.setup_routes()

if __name__ == "__main__":
    app.run('0.0.0.0', debug=True, port=int(5000), 
        ssl_context=('../serverless-gcp-skydentity/certs/domain_dir/domain.crt', '../serverless-gcp-skydentity/certs/domain_dir/domain.key'))