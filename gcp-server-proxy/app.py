import logging as py_logging
import os

from flask import Flask
from google.cloud import logging as gcp_logging
from proxy_util.logging import get_logger, print_and_log
from proxy_util.skypilot_forward import setup_routes

# check whether gcp logging should be enabled (default yes)
# useful to disable if the active GCP account does not have permissions
ENABLE_GCP_LOGGING = bool(int(os.environ.get("ENABLE_GCP_LOGGING", 1)))

app = Flask(__name__)

if ENABLE_GCP_LOGGING:
    # set gcp logging for root logger; also sets default log level
    GCP_LOGGING_CLIENT = gcp_logging.Client()
    GCP_LOGGING_CLIENT.setup_logging(log_level=py_logging.DEBUG)
else:
    # set default log level
    py_logging.getLogger().setLevel(py_logging.DEBUG)

# add file handler for local logging
LOGGER = py_logging.getLogger()
DEFAULT_FILE_HANDLER = py_logging.FileHandler("redirector.log")
DEFAULT_FORMATTER = py_logging.Formatter(
    fmt="%(asctime)s %(levelname)s %(filename)s:%(lineno)d - %(message)s"
)
DEFAULT_FILE_HANDLER.setFormatter(DEFAULT_FORMATTER)
LOGGER.addHandler(DEFAULT_FILE_HANDLER)


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
