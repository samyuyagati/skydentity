import os

from flask import Flask
from proxy_util.constants import CERT_DIR
from proxy_util.logging import get_logger, print_and_log
from proxy_util.skypilot_forward import setup_routes

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
    # start the application if not started through Flask
    app.run(
        "0.0.0.0",
        debug=False,
        port=int(os.environ.get("PORT", 5000)),
        ssl_context=(
            os.path.join(CERT_DIR, "domain.crt"),
            os.path.join("certs/", "domain.key"),
        ),
    )
