import base64
import json
import logging
from dataclasses import dataclass
from typing import Optional

from Crypto.PublicKey import RSA
from ruamel.yaml import YAML

from skydentity.proxy_util.crosscloud_resources.signature import export_key

LOGGER = logging.getLogger(__name__)

# TODO: fill in the deployed proxy URL
#  (this must be the deployed proxy, since it's run on the newly created VM, and must be publicly accessible)
GCP_URL = "https://skyidproxy-storage-service-488643085394.us-west1.run.app"


@dataclass
class SkydentityConfig:
    """Config for skydentity from cloudinit"""

    # private key in PEM format
    # TODO: swap over to secrets
    private_key: str

    # mapping from cloud to authorizer rURL
    urls: dict[str, str]

    def to_dict(self):
        return {"private_key": self.private_key, "urls": self.urls}


def prepare_cloudinit(request_body: dict, vm_private_key: RSA.RsaKey) -> dict:
    """
    Update the request body with an updated cloud-init file,
    containing information about the skydentity configuration.
    """
    private_key_export = export_key(vm_private_key)

    urls = {"gcp": GCP_URL}

    config = SkydentityConfig(private_key=private_key_export, urls=urls)
    config_serialized = json.dumps(config.to_dict()).strip()
    LOGGER.debug("Serialized config: %s", config_serialized)

    request_properties = request_body.get("properties", {})
    request_userdata_b64: Optional[str] = request_properties.get("userData", None)

    if not request_userdata_b64:
        request_userdata = "#cloud-config"
        LOGGER.debug("No existing userdata")
    else:
        # deserialize the userdata from base64
        request_userdata = base64.b64decode(request_userdata_b64).decode("utf-8")

        # make sure that the userdata is actually a cloud-config file;
        # i.e. the first line contains "cloud-config"
        assert (
            "cloud-config" in request_userdata.strip().splitlines()[0]
        ), "cloud-config directive not in the first line of the existing request userdata"

    # use safe YAML loader
    yaml = YAML(typ=["rt", "string"])
    yaml.width = 1000000  # set super high width to avoid wrapping
    parsed_userdata = yaml.load(request_userdata)

    try:
        existing_write_files = parsed_userdata.get("write_files", [])
    except AttributeError:
        # not a map
        existing_write_files = []

    existing_write_files.append(
        {
            "path": "/run/skydentity/config.json",
            "encoding": "text/plain",
            "content": config_serialized,
        }
    )

    # replace with the new userdata
    request_userdata = yaml.dumps(parsed_userdata)

    LOGGER.debug("New cloud-init userdata: %s\n", request_userdata)

    # re-encode the userdata in base64
    request_userdata_b64 = base64.b64encode(request_userdata.encode("utf-8")).decode(
        "utf-8"
    )

    LOGGER.debug("New cloud-init userdata b64 length: %d", len(request_userdata_b64))

    # clone request body with updated userdata
    updated_body = {
        **request_body,
        "properties": {**request_properties, "userData": request_userdata_b64},
    }
    return updated_body
