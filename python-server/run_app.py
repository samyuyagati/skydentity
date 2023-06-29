from flask import Flask

import os

app = Flask(__name__)

cert_dir = "/Users/samyu/.cloud_creds/skydentity_cert/"

if __name__ == "__main__":
    app.run('127.0.0.1', debug=False, port=5000, ssl_context=(os.path.join(cert_dir, 'server.crt'), 
            os.path.join(cert_dir, 'server.key')))
