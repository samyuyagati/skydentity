from flask import Flask

class ProxyServer:
    """
    Abstraction for a Skydentity server which:
    1) Receives incoming requests for various Cloud-specific endpoints
    2) Authenticates the request with the desired user credentials
    3) Proxies the request to cloud provider 
    """

    def __init__(self, flask_server: Flask):
        self.flask_server = flask_server

    def setup_routes(self):
        pass