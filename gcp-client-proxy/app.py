import logging as py_logging
import os

from flask import Flask
from google.cloud import logging as gcp_logging

from skydentity.proxy_util.gcp.logging import get_logger, print_and_log
from skydentity.proxy_util.gcp.skypilot_forward import setup_routes
from skydentity.utils.log_util import build_file_handler

app = Flask(__name__)

# set gcp logging for root logger; also sets default log level
GCP_LOGGING_CLIENT = gcp_logging.Client()
GCP_LOGGING_CLIENT.setup_logging(log_level=py_logging.DEBUG)

# add file handler for local logging
LOGGER = py_logging.getLogger()
LOGGER.addHandler(build_file_handler("authorizer.log"))


@app.route("/hello", methods=["GET"])
def handle_hello():
    """
    Debugging route.
    """
    LOGGER.debug("Hello!")
    return "Hello"


def setup_app():
    """
    Set up the Flask app.

    Sets required routes for forwarding requests.
    """
    LOGGER.debug("Starting up server")

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
