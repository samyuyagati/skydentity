import logging as py_logging
import os

from flask import Flask
from proxy_util.logging import get_logger, print_and_log
from proxy_util.skypilot_forward import setup_routes

from skydentity.utils.log_util import build_file_handler

app = Flask(__name__)

# add file handler for local logging
LOGGER = py_logging.getLogger()
LOGGER.setLevel(py_logging.INFO)
LOGGER.addHandler(build_file_handler("redirector.log"))


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
        port=int(os.environ.get("PORT", 5000)),
        ssl_context=(cert_file, cert_key),
    )
