import os

from flask import Flask
from skydentity.proxy_util.gcp.skypilot_forward import setup_routes
from skydentity.proxy_util.gcp.logging import get_logger, print_and_log

app = Flask(__name__)


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
        port=int(os.environ.get("PORT", 5001)),
        ssl_context=(cert_file, cert_key),
    )
