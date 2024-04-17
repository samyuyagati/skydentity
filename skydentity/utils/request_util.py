import backoff
import google_auth_httplib2
import googleapiclient.http
import httplib2
from googleapiclient.discovery import service_account

DEFAULT_BACKOFF_STRATEGY = backoff.fibo
DEFAULT_MAX_BACKOFF_TRIES = 15


def request_builder_factory(credentials: service_account.Credentials):
    """
    Returns a builder that creates a new Http object for every request,
    along with the initial AuthorizedHttp object for service creation.

    Http objects are not thread-safe, so this is necessary to ensure that
    concurrent requests work.
    """

    def build_request(http, *args, **kwargs):
        new_http = google_auth_httplib2.AuthorizedHttp(
            credentials, http=httplib2.Http(timeout=300)
        )
        return googleapiclient.http.HttpRequest(new_http, *args, **kwargs)

    authorized_http = google_auth_httplib2.AuthorizedHttp(
        credentials, http=httplib2.Http(timeout=300)
    )

    return build_request, authorized_http
