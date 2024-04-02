import hashlib
import logging as py_logging
import re
import sys
from typing import Dict, List, Optional, Tuple, TypedDict, Union

from flask import Request

from skydentity.policies.checker.policy_actions import PolicyAction
from skydentity.policies.checker.resource_policy import (
    CloudPolicy,
    PolicyContentException,
    ResourcePolicy,
    UnrecognizedResourcePolicy,
    VMPolicy,
)
from skydentity.policies.managers.gcp_authorization_policy_manager import (
    GCPAuthorizationPolicyManager,
)

class GCPVMPolicy(VMPolicy):
    """
    Defines methods for GCP VM policies.
    """

    REGION_AND_INSTANCE_TYPE_REGEX = re.compile(
        r"zones/(?P<region>[a-z0-9-]+)/machineTypes/(?P<instance_type>[a-z0-9-]+)"
    )
    DISK_TYPE_REGEX = re.compile(r"zones/(?P<zone>[^/]+)/diskTypes/pd-balanced")
    IMAGE_REGEX = re.compile(r".*/(?P<image>[a-z0-9-]+)$")
    SUBNETWORK_REGEX = re.compile(
        r"https://www\.googleapis\.com/compute/v1/projects/(?P<project>[^/]+)/regions/(?P<region>[^/]+)/subnetworks/(?P<subnetwork>[^/]+)"
    )

    VM_URL_REGEX = {
        "create": re.compile(
            r"compute/v1/projects/(?P<project>[^/]+)/zones/<region>/instances"
        ),
        "set_labels": re.compile(
            r"compute/v1/projects/(?P<project>[^/]+)/zones/(?P<zone>[^/]+)/instances/(?P<instance>[^/]+)/setLabels"
        ),
    }

    def __init__(self, policy: Dict):
        """
        :param policy: The dict of the policy to enforce.
        """
        self._policy = policy
        py_logging.basicConfig(filename='gcp_resource_policy.log', level=py_logging.INFO)
        self._pylogger = py_logging.getLogger("GCPResourcePolicy")

    def check_request(self, request: Request) -> bool:
        super_valid = super().check_request(request)
        if not super_valid:
            return False

        standardized_vm_policy = self.get_policy_standard_form()

        # also check hard-coded values in the request

        request_contents = request.get_json(cache=True)

        # check disks
        if "disks" in request_contents:
            disks = request_contents["disks"]
            for disk in disks:
                if (
                    disk.get("autoDelete", None) != True
                    or disk.get("boot", None) != True
                    or disk.get("type", None) != "PERSISTENT"
                ):
                    self._pylogger.debug(f"disk denied (plain) {disk}")
                    return False

                initialize_params = disk.get("initializeParams", None)
                if initialize_params is not None:
                    disk_size = initialize_params.get("diskSizeGb", None)
                    if disk_size is None or disk_size > 256:
                        self._pylogger.debug(f"disk denied (disk size) {disk}")
                        return False
                    disk_type = initialize_params.get("diskType", None)
                    if disk_type is None:
                        self._pylogger.debug(f"disk denied (disk type) {disk}")
                        return False

                    disk_match = re.search(GCPVMPolicy.DISK_TYPE_REGEX, disk_type)
                    if (
                        disk_match is None
                        or disk_match.group("zone")
                        not in standardized_vm_policy["regions"]
                    ):
                        self._pylogger.debug(f"disk denied (disk type) {disk}")
                        return False

                    source_image = initialize_params.get("sourceImage", None)
                    if source_image is None:
                        self._pylogger.debug(f"disk denied (source_image) {disk}")
                        return False

                    source_image_match = re.search(
                        GCPVMPolicy.IMAGE_REGEX, source_image
                    )
                    if (
                        source_image_match is None
                        or source_image_match.group("image")
                        not in standardized_vm_policy["allowed_images"]
                    ):
                        self._pylogger.debug("disk denied (source_image)")
                        return False

        # TODO: check metadata; currently will break skypilot

        # check network interfaces
        if "networkInterfaces" in request_contents:
            interfaces = request_contents["networkInterfaces"]
            for interface in interfaces:
                access_configs = interface.get("accessConfigs", None)
                if access_configs is None:
                    self._pylogger.debug(f"network interface denied (access_configs) {interface}")
                    return False

                for access_config in access_configs:
                    access_config_name = access_config.get("name", None)
                    access_config_type = access_config.get("type", None)

                    if (
                        access_config_name is None
                        or access_config_type is None
                        or access_config_name != "External NAT"
                        or access_config_type != "ONE_TO_ONE_NAT"
                    ):
                        self._pylogger.debug(f"network interface denied (access_configs) {access_config}")
                        return False

                subnetwork = interface.get("subnetwork")
                if subnetwork is None:
                    self._pylogger.debug(f"network interface denied (subnetwork) {interface}")
                    return False

                subnetwork_match = re.search(GCPVMPolicy.SUBNETWORK_REGEX, subnetwork)

                # TODO: check project
                if (
                    subnetwork_match is None
                    or (
                        subnetwork_match.group("region")
                        not in standardized_vm_policy["regions"]
                    )
                    or subnetwork_match.group("subnetwork") != "skypilot-vpc"
                ):
                    self._pylogger.debug(f"network interface denied (subnetwork) {interface}")
                    return False

        if "scheduling" in request_contents:
            if request_contents["scheduling"] != None:
                self._pylogger.debug(f"scheduling denied {request_contents['scheduling']}")
                return False

        return True

    def get_policy_standard_form(self) -> Dict:
        """
        Gets the policy in a standard form.
        :return: The policy in a standard form.
        """
        return self._policy

    def get_standard_request_form(self, request: Request) -> Dict:
        """
        Extracts the important values from the request to check in a standardized form.
        The standard form is:
        {
            "actions": <action>,
            "regions": <regions>,
            "instance_type": <instance_type>,
            "allowed_images": [list of allowed images],
            "startup_script": <startup script hash>,
        }
        """
        out_dict = {
            "actions": None,
            "regions": [],
            "instance_type": [],
            "allowed_images": [],
            "startup_script": None,
        }
        if request.method == "POST":
            if re.search(GCPVMPolicy.VM_URL_REGEX["create"], request.path) is not None:
                out_dict["actions"] = PolicyAction.CREATE
            else:
                out_dict["actions"] = PolicyAction.WRITE
        elif request.method == "GET":
            out_dict["actions"] = PolicyAction.READ

        request_contents = request.get_json(cache=True)
        if "machineType" in request_contents:
            full_machine_type = request_contents["machineType"]

            # Extract the region from the machine type
            extracted_region_and_machine_type = (
                GCPVMPolicy.REGION_AND_INSTANCE_TYPE_REGEX.match(full_machine_type)
            )

            out_dict["instance_type"].append(
                extracted_region_and_machine_type.group("instance_type")
            )
            out_dict["regions"].append(
                extracted_region_and_machine_type.group("region")
            )

        # Now look up for the image
        if "disks" in request_contents:
            for disk in request_contents["disks"]:
                if "initializeParams" in disk:
                    if "sourceImage" in disk["initializeParams"]:
                        extracted_image = GCPVMPolicy.IMAGE_REGEX.match(
                            disk["initializeParams"]["sourceImage"]
                        )
                        out_dict["allowed_images"].append(
                            extracted_image.group("image")
                        )

        # Parse the setup script, if it exists
        if "metadata" in request_contents:
            if "items" in request_contents["metadata"]:
                for item in request_contents["metadata"]["items"]:
                    if item["key"] == "startup-script":
                        out_dict["startup_script"] = hashlib.sha256(
                            item["value"].encode()
                        ).hexdigest()

        return out_dict

    def to_dict(self) -> Dict:
        """
        Converts the policy to a dictionary so that it can be stored.
        :return: The dictionary representation of the policy.
        """
        out_dict = {
            "actions": self._policy["actions"].value,
            "cloud_provider": [GCPPolicy.GCP_CLOUD_NAME],
            "regions": {GCPPolicy.GCP_CLOUD_NAME: self._policy["regions"]},
            "instance_type": {GCPPolicy.GCP_CLOUD_NAME: self._policy["instance_type"]},
            "allowed_images": {
                GCPPolicy.GCP_CLOUD_NAME: self._policy["allowed_images"]
            } 
        }
        if "startup_scripts" in self._policy:
            out_dict["startup_scripts"] = { GCPPolicy.GCP_CLOUD_NAME: self._policy["startup_scripts"] }
        return out_dict

    @staticmethod
    def from_dict(policy_dict_cloud_level: Dict, logger=None):
        """
        Distills a general multi-cloud policy into a cloud specific policy.
        :param policy_dict_cloud_level: The dictionary representation of the policy in terms of all clouds.
        :param logger: optional. google.cloud logger object
        :throws: Error if the policy is not valid.
        :return: The policy representation of the dict.
        """
        if logger:
            logger.log_text(str(policy_dict_cloud_level))

        cloud_specific_policy = {}
        cloud_specific_policy["can_cloud_run"] = (
            GCPPolicy.GCP_CLOUD_NAME in policy_dict_cloud_level["cloud_provider"]
        )
        if not cloud_specific_policy["can_cloud_run"]:
            raise PolicyContentException("Policy does not accept GCP")

        try:
            # TODO(kdharmarajan): Generalize this policy actioni
            # TODO what happens if multiple actions are permitted?
            #self._pylogger.debug(f"{policy_dict_cloud_level["actions"]}")
            if isinstance(policy_dict_cloud_level["actions"], list):
                action = PolicyAction[policy_dict_cloud_level["actions"][0]]
            else:
                action = PolicyAction[policy_dict_cloud_level["actions"]]
            cloud_specific_policy["actions"] = action
        except KeyError:
            raise PolicyContentException("Policy action is not valid")

        gcp_cloud_regions = []
        for region_group in policy_dict_cloud_level["regions"]:
            #print("REGION GROUP", region_group)
            if GCPPolicy.GCP_CLOUD_NAME in region_group:
                if isinstance(policy_dict_cloud_level["regions"], list):
                    gcp_cloud_regions = region_group[GCPPolicy.GCP_CLOUD_NAME]
                else:
                    gcp_cloud_regions = policy_dict_cloud_level["regions"][region_group]
                break

        # TODO(kdharmarajan): Check that the regions are valid later (not essential)
        cloud_specific_policy["regions"] = gcp_cloud_regions

        gcp_instance_types = []
        for instance_type_group in policy_dict_cloud_level["instance_type"]:
            if GCPPolicy.GCP_CLOUD_NAME in instance_type_group:
                if isinstance(policy_dict_cloud_level["instance_type"], list):
                    gcp_instance_types = instance_type_group[GCPPolicy.GCP_CLOUD_NAME]
                else:
                    gcp_instance_types = policy_dict_cloud_level["instance_type"][
                        GCPPolicy.GCP_CLOUD_NAME
                    ]
        cloud_specific_policy["instance_type"] = gcp_instance_types

        gcp_allowed_images = []
        for allowed_images_group in policy_dict_cloud_level["allowed_images"]:
            if GCPPolicy.GCP_CLOUD_NAME in allowed_images_group:
                if isinstance(policy_dict_cloud_level["allowed_images"], list):
                    gcp_allowed_images = allowed_images_group[GCPPolicy.GCP_CLOUD_NAME]
                else:
                    gcp_allowed_images = policy_dict_cloud_level["allowed_images"][
                        GCPPolicy.GCP_CLOUD_NAME
                    ]

        cloud_specific_policy["allowed_images"] = gcp_allowed_images

        # Handle startup scripts
        gcp_startup_scripts = []
        if ("startup_scripts" in policy_dict_cloud_level):
            for startup_scripts_group in policy_dict_cloud_level["startup_scripts"]:
                if GCPPolicy.GCP_CLOUD_NAME in startup_scripts_group:
                    if isinstance(policy_dict_cloud_level["startup_scripts"], list):
                        gcp_startup_scripts = startup_scripts_group[GCPPolicy.GCP_CLOUD_NAME]
                    else:
                        gcp_startup_scripts = policy_dict_cloud_level["startup_scripts"][GCPPolicy.GCP_CLOUD_NAME]
            cloud_specific_policy["startup_scripts"] = gcp_startup_scripts
        return GCPVMPolicy(cloud_specific_policy)


class GCPAttachedAuthorizationPolicy(ResourcePolicy):
    """
    Defines methods for GCP Attached Authorization Policies (what GCP policies can be attached to a VM)
    """

    def __init__(self, policy: Dict):
        """
        :param policy: The dict of the policy to enforce.
        """
        self._policy = policy
        py_logging.basicConfig(filename='gcp_resource_policy.log', level=py_logging.INFO)
        self._pylogger = py_logging.getLogger("GCPResourcePolicy")

    def check_request(
        self,
        request: Request,
        auth_policy_manager: GCPAuthorizationPolicyManager,
        logger=None,
    ) -> Tuple[Union[str, None], bool]:
        """
        Enforces the policy on a request.
        :param request: The request to enforce the policy on.
        :return: True if the request is allowed, False otherwise.
        """
        self._pylogger.debug("check_request")
        sys.stdout.flush()

        request_contents = request.get_json(cache=True)
        self._pylogger.debug(f">>>request: {request_contents}")

        # Handle attached service account capability
        if "serviceAccounts" not in request_contents:
            return (None, True)

        # Expect a single attached service account
        if len(request_contents["serviceAccounts"]) != 1:
            if logger:
                logger.log_text(
                    "Only one service account may be attached"
                )
            else:
                self._pylogger.debug("Only one service account may be attached")
            return (None, False)

        # Expect a capability of the form:
        #   { 'nonce': XX, 'header': XX, 'ciphertext': XX, 'tag': XX }
        service_account_capability = request_contents["serviceAccounts"][0]
        self._pylogger.debug(f">>>service_account_capability: {service_account_capability}")
        if (
            service_account_capability["nonce"] is None
            or service_account_capability["header"] is None
            or service_account_capability["ciphertext"] is None
            or service_account_capability["tag"] is None
        ):
            if logger:
                logger.log_text("Invalid capability format")
            else:
                self._pylogger.debug("Invalid capability format")
            return (None, False)

        service_account_id, success = auth_policy_manager.check_capability(
            service_account_capability
        )
        if not success:
            self._pylogger.debug("Unsuccessful in checking capability")
            return (None, False)

        # Double-check that the service account is allowed (e.g., if policy changed since
        # the capability was issued)
        self._pylogger.debug(f"{self._policy[GCPPolicy.GCP_CLOUD_NAME][0]['authorization']}")
        if (
            service_account_id
            not in self._policy[GCPPolicy.GCP_CLOUD_NAME][0]["authorization"]
        ):
            self._pylogger.debug(
                f"Service account id {service_account_id} not in {self._policy[GCPPolicy.GCP_CLOUD_NAME]}"
            )
            return (None, False)

        # If permitted, add the service account to the request
        return (service_account_id, True)

    def to_dict(self) -> Dict:
        """
        Converts the policy to a dictionary so that it can be stored.
        :return: The dictionary representation of the policy.
        """
        out_dict = {}
        self._pylogger.debug(f"{self._policy}")
        if GCPPolicy.GCP_CLOUD_NAME in self._policy:
            out_dict[GCPPolicy.GCP_CLOUD_NAME] = self._policy[GCPPolicy.GCP_CLOUD_NAME]
        return out_dict

    @staticmethod
    def from_dict(
        policy_dict_cloud_level: Dict, logger=None
    ) -> "GCPAttachedAuthorizationPolicy":
        """
        Converts a dictionary to a policy.
        :param policy_dict: The dictionary representation of the policy.
        :param logger: optional. google.cloud logger object.
        :return: The policy representation of the dict.
        """
        if logger:
            logger.log_text("GCPAttachedAuthorization")
        #else:
        #    print("GCPAttachedAuthorization")
        cloud_specific_policy = {}
        can_cloud_run = False
        #print("Policy dict:", policy_dict_cloud_level)
        if isinstance(policy_dict_cloud_level, list):
            for cloud_auth in policy_dict_cloud_level:
                if GCPPolicy.GCP_CLOUD_NAME in cloud_auth:
                    can_cloud_run = True
                    service_accounts = cloud_auth[GCPPolicy.GCP_CLOUD_NAME]
                    cloud_specific_policy[GCPPolicy.GCP_CLOUD_NAME] = service_accounts
                    break
        else:
            for cloud_name in policy_dict_cloud_level:
                if not (cloud_name == GCPPolicy.GCP_CLOUD_NAME):
                    continue
                can_cloud_run = True
                service_accounts = policy_dict_cloud_level[cloud_name]
                cloud_specific_policy[GCPPolicy.GCP_CLOUD_NAME] = service_accounts
                break
        cloud_specific_policy["can_cloud_run"] = can_cloud_run
        #self._pylogger.debug(f"Cloud-specific attached authorization policy: {cloud_specific_policy}")
        return GCPAttachedAuthorizationPolicy(cloud_specific_policy)


class GCPImageLookupPolicy(ResourcePolicy):
    """
    Defines methods for GCP Image Lookup policies.
    """

    PUBLIC_PROJECTS = set(
        [
            "debian-cloud",
            "centos-cloud",
            "ubuntu-os-cloud",
            "windows-cloud",
            "cos-cloud",
            "rhel-cloud",
            "rhel-sap-cloud",
            "rocky-linux-cloud",
            "opensuse-cloud",
            "suse-sap-cloud",
            "suse-cloud",
            "windows-sql-cloud",
            "fedora-cloud",
            "fedora-coreos-cloud",
            "ubuntu-os-pro-cloud",
        ]
    )

    def __init__(self):
        """
        :param policy: The dict of the policy to enforce.
        """
        self._image_regex_extractor = re.compile(
            r"compute/v1/projects/(?P<project>)/global/images/family/(?P<family>)$"
        )

    def check_request(self, request: Request) -> bool:
        """
        Enforces the policy on a request.
        :param request: The request to enforce the policy on.
        :return: True if the request is allowed, False otherwise.
        """
        if request.method == "GET":
            image_info = self._image_regex_extractor.match(request.path)
            if image_info:
                project = image_info.group("project")
                if project not in GCPImageLookupPolicy.PUBLIC_PROJECTS:
                    return False
        return True


class GCPReadPolicy(ResourcePolicy):
    """Defines methods for GCP read request policies."""

    # TODO: instead of using regex, get information from routing done by the proxy
    READ_TYPE_URL_PATTERNS: Dict[str, re.Pattern] = {
        "project": re.compile(r"compute/v1/projects/(?P<project>[^/]+)"),
        "regions": re.compile(
            r"compute/v1/projects/(?P<project>[^/]+)/regions/(?P<region>[^/]+)"
        ),
        "zones": re.compile(
            r"compute/v1/projects/(?P<project>[^/]+)/zones/(?P<zone>[^/]+)"
        ),
        "reservations": re.compile(
            r"compute/v1/projects/(?P<project>[^/]+)/aggregated/reservations"
        ),
        "firewalls": re.compile(
            r"compute/v1/projects/(?P<project>[^/]+)/global/"
            r"(firewalls"
            "|"
            r"networks/(?P<network>[^/]+)/getEffectiveFirewalls)"
        ),
        "subnetworks": re.compile(
            r"compute/v1/projects/(?P<project>[^/]+)/regions/(?P<region>[^/]+)/subnetworks"
        ),
        "operations": re.compile(
            r"compute/v1/projects/(?P<project>[^/]+)/"
            r"(global|zones/(?P<zone>[^/]+))"
            r"/operations/(?P<operation>[^/]+)"
        ),
    }

    class _PolicyDict(TypedDict):
        project: Union[str, None]
        regions: Union[List[str], None]
        zones: Union[List[str], None]
        reservations: bool
        firewalls: bool
        subnetworks: bool
        operations: bool

    def __init__(self, policy: _PolicyDict, policy_override: Union[bool, None] = None):
        """
        Create a new GCPReadPolicy instance.

        `policy_override` is used to specify DENY_ALL or ALLOW_ALL policies;
        if not None, then `policy` is ignored and a blanket ALLOW (if True) or DENY (if False) is used.
        """
        self._policy = policy
        self._policy_override = policy_override

    def check_request(self, request: Request) -> bool:
        raise NotImplemented("Use `check_read_request` instead.")

    def check_read_request(self, request: Request, *aux_info: str) -> bool:
        # TODO: allow any non-GET request through?
        if request.method != "GET":
            return True

        # check for blanket ALLOW/DENY policy
        if self._policy_override is not None:
            return self._policy_override

        assert len(aux_info) > 0 and aux_info[0] in GCPReadPolicy.READ_TYPE_URL_PATTERNS
        read_type = aux_info[0]

        request_info = self._get_request_info(request, read_type)

        if read_type == "project":
            if self._policy["project"] is None:
                # default allow if not specified
                return True

            # check project with policy
            request_project = request_info["project"]
            if request_project in GCPImageLookupPolicy.PUBLIC_PROJECTS:
                # allow if public project
                return True

            return request_project == self._policy["project"]
        elif read_type == "regions":
            if self._policy["regions"] is None:
                # default allow if not specified
                return True

            # check region with policy
            request_region = request_info["region"]
            return request_region in self._policy["regions"]
        elif read_type == "zones":
            if self._policy["zones"] is None:
                return True

            # check zone with policy
            request_zone = request_info["zone"]
            return request_zone in self._policy["zones"]
        elif read_type == "reservations":
            return self._policy["reservations"]
        elif read_type == "firewalls":
            return self._policy["firewalls"]
        elif read_type == "subnetworks":
            return self._policy["subnetworks"]
        elif read_type == "operations":
            return self._policy["operations"]

        # TODO: allow request if unrecognized?
        return True

    def _get_request_info(self, request: Request, read_type: str):
        """Parse path to get the appropriate request information"""

        url_pattern = GCPReadPolicy.READ_TYPE_URL_PATTERNS[read_type]
        match = url_pattern.search(request.path)

        assert match, "URL does not match read type pattern"

        if read_type == "project":
            return {"project": match.group("project")}
        elif read_type == "regions":
            return {"region": match.group("region")}
        elif read_type == "zones":
            return {"zone": match.group("zone")}

        # all other read types do not use any auxiliary information from the path
        return {}

    @staticmethod
    def _get_default_policy_dict() -> _PolicyDict:
        """
        Get default policy dictionary, which allows all requests.
        """
        return {
            "project": None,
            "regions": None,
            "zones": None,
            "reservations": True,
            "firewalls": True,
            "subnetworks": True,
            "operations": True,
        }

    @staticmethod
    def get_default_deny_policy():
        """
        Get default policy object, which denies all requests.
        """
        return GCPReadPolicy(
            GCPReadPolicy._get_default_policy_dict(), policy_override=False
        )

    @staticmethod
    def get_default_allow_policy():
        """
        Get default policy object, which allows all requests.
        """
        return GCPReadPolicy(
            GCPReadPolicy._get_default_policy_dict(), policy_override=True
        )

    @staticmethod
    def from_dict(policy_dict: Dict, logger=None) -> "GCPReadPolicy":
        """
        Parse dictionary to get relevant info.

        Expects a dictionary with the top level key as the cloud name ("gcp").
        """
        if GCPPolicy.GCP_CLOUD_NAME not in policy_dict or not isinstance(
            policy_dict[GCPPolicy.GCP_CLOUD_NAME], dict
        ):
            # no valid section found
            return GCPReadPolicy.get_default_deny_policy()

        gcp_policy = policy_dict[GCPPolicy.GCP_CLOUD_NAME]

        # allow if not specified
        out_dict = GCPReadPolicy._get_default_policy_dict()
        if "project" in gcp_policy:
            out_dict["project"] = gcp_policy["project"]
        if "regions" in gcp_policy:
            out_dict["regions"] = gcp_policy["regions"]
        if "zones" in gcp_policy:
            out_dict["zones"] = gcp_policy["zones"]
        if "reservations" in gcp_policy:
            out_dict["reservations"] = gcp_policy["reservations"]
        if "firewalls" in gcp_policy:
            out_dict["firewalls"] = gcp_policy["firewalls"]
        if "subnetworks" in gcp_policy:
            out_dict["subnetworks"] = gcp_policy["subnetworks"]
        if "operations" in gcp_policy:
            out_dict["operations"] = gcp_policy["operations"]

        return GCPReadPolicy(out_dict)

    def to_dict(self):
        return {
            GCPPolicy.GCP_CLOUD_NAME: {
                # filter out None items
                k: v
                for k, v in self._policy.items()
                if v is not None
            }
        }


class GCPPolicy(CloudPolicy):
    """
    Defines methods for GCP policies.
    """

    GCP_CLOUD_NAME = "gcp"
    VM_REQUEST_KEYS = set(
        [
            "name",  # TODO should name really indicate VM?
            "networkInterfaces",
            "disks",
            "machineType",
            "metadata",
            "labels",
            "scheduling",
            "serviceAccounts",
            "tags",
        ]
    )
    ATTACHED_AUTHORIZATION_KEYS = set(["serviceAccounts"])

    def __init__(
        self,
        vm_policy: GCPVMPolicy,
        attached_authorization_policy: GCPAttachedAuthorizationPolicy,
        read_policy: GCPReadPolicy,
    ):
        """
        :param vm_policy: The GCP VM Policy to enforce.
        :param attached_policy_policy: The Attached Policy Policy to enforce.
        """
        self._resource_policies = {
            "virtual_machine": vm_policy,
            "attached_authorizations": attached_authorization_policy,
            "image_lookup": GCPImageLookupPolicy(),
            "read": read_policy,
            "unrecognized": UnrecognizedResourcePolicy(),
        }
        py_logging.basicConfig(filename='gcp_resource_policy.log', level=py_logging.INFO)
        self._pylogger = py_logging.getLogger("GCPResourcePolicy")
        self.valid_authorization: Union[str, None] = None
        self._pylogger.debug(
            "GCPAuthorizationPolicy init:",
            self._resource_policies["attached_authorizations"]._policy,
        )

    def set_authorization_manager(self, manager: GCPAuthorizationPolicyManager):
        self._authorization_manager = manager

    def get_request_resource_types(self, request: Request) -> List[Tuple[str]]:
        """
        Gets the resource types that the request is trying to access / create / delete.
        :param request: The request to get the resource types from.
        :return: The resource types that the request is trying to access as a list of tuples
            to identify the resource type.
        """
        resource_types = set([])

        # Handle GET request
        if request.method == "GET":
            self._pylogger.debug("NOT JSON")
            if "images" in request.path:
                resource_types.add(("image_lookup",))
            else:
                # check all read request paths
                has_match = False
                for (
                    read_type,
                    read_path_regex,
                ) in GCPReadPolicy.READ_TYPE_URL_PATTERNS.items():
                    match = read_path_regex.search(request.path)
                    if match:
                        has_match = True
                        resource_types.add(("read", read_type))

                if not has_match:
                    # if no matches, then add unrecognized
                    resource_types.add(("unrecognized",))
        elif request.method == "POST":
            # Handle POST request
            self._pylogger.debug(f"{request.get_json(cache=True)}")
            if (
                re.search(GCPVMPolicy.VM_URL_REGEX["set_labels"], request.path)
                is not None
            ):
                resource_types.add(("virtual_machine",))
            else:
                for key in request.get_json(cache=True).keys():
                    self._pylogger.debug(f"{key}")
                    if key in GCPPolicy.VM_REQUEST_KEYS:
                        resource_types.add(("virtual_machine",))
                    elif key in GCPPolicy.ATTACHED_AUTHORIZATION_KEYS:
                        resource_types.add(("attached_authorizations",))
                    else:
                        # disallow any unrecognized keys
                        resource_types.add(("unrecognized", key))

                # only add unrecognized if nothing yet
                # if len(resource_types) == 0:
                #     resource_types.add(("unrecognized",))
                #     print(">>>>> ALL UNRECOGNIZED RESOURCE TYPES <<<<<")
        else:
            # unrecognized request method
            resource_types.add(("unrecognized,"))
            self._pylogger.debug(f"UNRECOGNIZED REQUEST METHOD: {request.method}")
        self._pylogger.debug(f"All resource types: {list(resource_types)}")
        return list(resource_types)

    def check_resource_type(self, resource_type: Tuple[str], request: Request) -> bool:
        """
        Enforces the policy on a resource type.
        :param resource_type: The resource type to enforce the policy on.
        :param request: The request to enforce the policy on.
        :return: True if the request is allowed, False otherwise.
        """
        resource_type_key, *resource_type_aux = resource_type
        assert resource_type_key in self._resource_policies
        self._pylogger.debug(f"GCPPolicy check_resource_type: {resource_type}")

        if resource_type_key == "attached_authorizations":
            # Authorization policies
            result = self._resource_policies[resource_type_key].check_request(
                request, self._authorization_manager
            )
            self.valid_authorization = result[0]
            return result[1]
        elif resource_type_key == "read":
            # read policies
            result = self._resource_policies[resource_type_key].check_read_request(
                request, *resource_type_aux
            )
            return result
        else:
            # VM policies
            result = self._resource_policies[resource_type_key].check_request(request)
            return result

    def to_dict(self) -> Dict:
        """
        Converts the policy to a dictionary so that it can be stored.
        :return: The dictionary representation of the policy.
        """
        out_dict = {}
        for resource_type, policy in self._resource_policies.items():
            self._pylogger.debug(f"GCPPolicy resource type: {resource_type}")
            self._pylogger.debug(f"GCPPolicy policy: {policy}")
            if resource_type == "unrecognized" or resource_type == "image_lookup":
                continue
            out_dict[resource_type] = policy.to_dict()
        self._pylogger.debug(f"out_dict: {out_dict}")
        return out_dict

    @staticmethod
    def from_dict(policy_dict: Dict, logger=None) -> "GCPPolicy":
        """
        Converts a dictionary to a policy.
        :param policy_dict: The dictionary representation of the policy.
        :param logger: optional. google.cloud logger object.
        :return: The policy representation of the dict.
        """
        vm_dict = {}
        if "virtual_machine" in policy_dict:
            vm_dict = policy_dict["virtual_machine"]
            #print("VM_DICT in GCPPolicy:from_dict", vm_dict)
        vm_policy = GCPVMPolicy.from_dict(vm_dict, logger)

        attached_authorization_dict = {}
        if "attached_authorizations" in policy_dict:
            attached_authorization_dict = policy_dict["attached_authorizations"]
        #print("GCPPolicy attached authorizations dict:", attached_authorization_dict)
        attached_authorization_policy = GCPAttachedAuthorizationPolicy.from_dict(
            attached_authorization_dict, logger
        )

        if PolicyAction.READ.is_allowed_be_performed(
            vm_policy.get_policy_standard_form()["actions"]
        ):
            if "reads" in policy_dict:
                read_dict = policy_dict["reads"]
                #print("READS_DICT in GCPPolicy:from_dict", read_dict)
                read_policy = GCPReadPolicy.from_dict(read_dict, logger)
            else:
                # if reads are allowed, and there is no granular specification, then allow all
                read_policy = GCPReadPolicy.get_default_allow_policy()
        else:
            # if cannot read, then deny all reads
            read_policy = GCPReadPolicy.get_default_deny_policy()

        return GCPPolicy(vm_policy, attached_authorization_policy, read_policy)
