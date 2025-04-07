import logging as py_logging
import os
import subprocess

from flask import Flask
from proxy_util.credentials import get_app_id, get_app_secret, get_tenant_id
from proxy_util.logging import get_logger, print_and_log
from proxy_util.skypilot_forward import setup_routes

from skydentity.utils.log_util import build_file_handler

app = Flask(__name__)

# add file handler for local logging
LOGGER = py_logging.getLogger()
LOGGER.setLevel(py_logging.DEBUG)
LOGGER.addHandler(build_file_handler("authorizer.log"))


@app.route("/hello", methods=["GET"])
def handle_hello():
    """
    Debugging route.
    """
    logger = get_logger()
    print_and_log(logger, "Hello!")
    return "Hello"


def setup_app():
    """
    Set up the Flask app.

    Sets required routes for forwarding requests.
    """
    logger = get_logger()
    print_and_log(logger, "Starting up server")

    managed_identity_id = os.environ.get("MANAGED_IDENTITY_ID", None)
    use_system_identity = os.environ.get("SYSTEM_ID", None)
    if managed_identity_id is not None:
        print_and_log(logger, "Setting up managed identity")
        # Setting APPSETTING_WEBSITE_SITE_NAME is for forcing azure to go to the correct MSI endpoint
        subprocess.Popen(
            ["az", "login", "--identity", "--username", managed_identity_id],
            env={"APPSETTING_WEBSITE_SITE_NAME": "DUMMY"},
            stdout=subprocess.PIPE,
        ).communicate()
    if use_system_identity is not None:
        print_and_log(logger, "Setting up system identity with dummy")
        # Setting APPSETTING_WEBSITE_SITE_NAME is for forcing azure to go to the correct MSI endpoint
        subprocess.Popen(
            ["az", "login", "--identity"],
            env={"APPSETTING_WEBSITE_SITE_NAME": "DUMMY"},
            stdout=subprocess.PIPE,
        ).communicate()
    tenant_id = get_tenant_id()
    app_id = get_app_id()
    app_secret = get_app_secret()
    if tenant_id is not None and app_id is not None and app_secret is not None:
        print_and_log(logger, "Setting up Azure AD")
        subprocess.Popen(
            [
                "az",
                "login",
                "--service-principal",
                "--tenant",
                tenant_id,
                "-u",
                app_id,
                "-p",
                app_secret,
            ],
            stdout=subprocess.PIPE,
        ).communicate()

    # set up skypilot forwarding routes
    setup_routes(app)


# set up the application
setup_app()

if __name__ == "__main__":
    # get certificate information
    cert_file = os.environ.get("CERT_FILE", None)
    cert_key = os.environ.get("CERT_KEY", None)
    assert cert_file is not None and os.path.isfile(cert_file)
    assert cert_key is not None and os.path.isfile(cert_key)

    # start the application if not started through Flask
    app.run(
        "0.0.0.0",
        debug=False,
        port=int(os.environ.get("PORT", 5001)),
        ssl_context=(cert_file, cert_key),
    )
