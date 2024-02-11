from typing import Dict, List, Tuple, TypedDict, Union
from flask import Request
import re
import sys

from skydentity.policies.checker.resource_policy import (
    CloudPolicy, 
    ResourcePolicy, 
    VMPolicy,
    UnrecognizedResourcePolicy,
    PolicyContentException
)
from skydentity.policies.checker.policy_actions import PolicyAction
from skydentity.policies.managers.gcp_authorization_policy_manager import GCPAuthorizationPolicyManager

class GCPVMPolicy(VMPolicy):
    """
    Defines methods for GCP VM policies.
    """

    def __init__(self, policy: Dict):
        """
        :param policy: The dict of the policy to enforce.
        """
        self._policy = policy
        self._region_and_instance_type_regex = re.compile(r'zones/(?P<region>[a-z0-9-]+)/machineTypes/(?P<instance_type>[a-z0-9-]+)')
        self._image_regex = re.compile(r'.*/(?P<image>[a-z0-9-]+)$')
    
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
        }
        """
        out_dict = {
            "actions": None,
            "regions": [],
            "instance_type": [],
            "allowed_images": [],
        }
        if request.method == 'POST':
            out_dict["actions"] = PolicyAction.CREATE
        elif request.method == 'GET':
            out_dict["actions"] = PolicyAction.READ

        request_contents = request.get_json(cache=True)
        if "machineType" in request_contents:
            full_machine_type = request_contents["machineType"]

            # Extract the region from the machine type
            extracted_region_and_machine_type = self._region_and_instance_type_regex.match(full_machine_type)

            out_dict["instance_type"].append(extracted_region_and_machine_type.group("instance_type"))
            out_dict["regions"].append(extracted_region_and_machine_type.group("region"))

        # Now look up for the image
        if "disks" in request_contents:
            for disk in request_contents["disks"]:
                if "initializeParams" in disk:
                    if "sourceImage" in disk["initializeParams"]:
                        extracted_image = self._image_regex.match(disk["initializeParams"]["sourceImage"])
                        out_dict["allowed_images"].append(extracted_image.group("image"))

        return out_dict

    def to_dict(self) -> Dict:
        """
        Converts the policy to a dictionary so that it can be stored.
        :return: The dictionary representation of the policy.
        """
        out_dict = {
            "actions": self._policy["actions"].value,
            "cloud_provider": [
                GCPPolicy.GCP_CLOUD_NAME
            ],
            "regions": {
                GCPPolicy.GCP_CLOUD_NAME: self._policy["regions"]
            },
            "instance_type": {
                GCPPolicy.GCP_CLOUD_NAME: self._policy["instance_type"]
            },
            "allowed_images": {
                GCPPolicy.GCP_CLOUD_NAME: self._policy["allowed_images"]
            },
        }
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
          logger.log_text(str(policy_dict_cloud_level), severity="WARNING")
        else:
          print(str(policy_dict_cloud_level))
        cloud_specific_policy = {}
        cloud_specific_policy["can_cloud_run"] = GCPPolicy.GCP_CLOUD_NAME \
                            in policy_dict_cloud_level["cloud_provider"]
        if not cloud_specific_policy["can_cloud_run"]:
            raise PolicyContentException("Policy does not accept GCP")

        try:
            # TODO(kdharmarajan): Generalize this policy actioni
            # TODO what happens if multiple actions are permitted?
            print(policy_dict_cloud_level["actions"])
            if isinstance(policy_dict_cloud_level["actions"], list):
              action = PolicyAction[policy_dict_cloud_level["actions"][0]]
            else:
              action = PolicyAction[policy_dict_cloud_level["actions"]]
            cloud_specific_policy["actions"] = action
        except KeyError:
            raise PolicyContentException("Policy action is not valid")

        gcp_cloud_regions = []
        for region_group in policy_dict_cloud_level["regions"]:
            print("REGION GROUP", region_group)
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
                  gcp_instance_types = policy_dict_cloud_level["instance_type"][GCPPolicy.GCP_CLOUD_NAME]
        cloud_specific_policy["instance_type"] = gcp_instance_types

        gcp_allowed_images = []
        for allowed_images_group in policy_dict_cloud_level["allowed_images"]:
            if GCPPolicy.GCP_CLOUD_NAME in allowed_images_group:
                if isinstance(policy_dict_cloud_level["allowed_images"], list):
                  gcp_allowed_images = allowed_images_group[GCPPolicy.GCP_CLOUD_NAME]
                else:
                  gcp_allowed_images = policy_dict_cloud_level["allowed_images"][GCPPolicy.GCP_CLOUD_NAME]

        cloud_specific_policy["allowed_images"] = gcp_allowed_images

        # TODO(kdharmarajan): Add allowed_setup script inclusion here
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
    
    def check_request(self, request: Request, auth_policy_manager: GCPAuthorizationPolicyManager, logger=None) -> (str, bool):
        """
        Enforces the policy on a request.
        :param request: The request to enforce the policy on.
        :return: True if the request is allowed, False otherwise.
        """
        print("check_request", flush=True)
        sys.stdout.flush()
        
        request_contents = request.get_json(cache=True)
        print(">>>request:", request_contents)

        # Handle attached service account capability
        if "serviceAccounts" not in request_contents:
            return (None, True)
        
        # Expect a single attached service account
        if len(request_contents["serviceAccounts"]) != 1:
            if logger:
                logger.log_text("Only one service account may be attached", severity="WARNING")
            else:
                print("Only one service account may be attached")
            return (None, False)

        # Expect a capability of the form:
        #   { 'nonce': XX, 'header': XX, 'ciphertext': XX, 'tag': XX }
        service_account_capability = request_contents["serviceAccounts"][0]
        print(">>>service_account_capability:", service_account_capability)
        if (service_account_capability["nonce"] is None or \
            service_account_capability["header"] is None or \
            service_account_capability["ciphertext"] is None or \
            service_account_capability["tag"] is None):
            if logger:
                logger.log_text("Invalid capability format", severity="WARNING")
            else:
                print("Invalid capability format")
            return (None, False)
        
        service_account_id, success = auth_policy_manager.check_capability(service_account_capability)
        if not success:
            print("Unsuccessful in checking capability")
            return (None, False)

        # Double-check that the service account is allowed (e.g., if policy changed since
        # the capability was issued)
        print(self._policy[GCPPolicy.GCP_CLOUD_NAME][0]["authorization"])
        if service_account_id not in self._policy[GCPPolicy.GCP_CLOUD_NAME][0]["authorization"]:
            print("Service account id", service_account_id, "not in", self._policy[GCPPolicy.GCP_CLOUD_NAME])
            return (None, False)
        
        # If permitted, add the service account to the request
        return (service_account_id, True)

    def to_dict(self) -> Dict:
        """
        Converts the policy to a dictionary so that it can be stored.
        :return: The dictionary representation of the policy.
        """
        out_dict = {}
        print(self._policy)
        if GCPPolicy.GCP_CLOUD_NAME in self._policy:
            out_dict[GCPPolicy.GCP_CLOUD_NAME] = self._policy[GCPPolicy.GCP_CLOUD_NAME]
        return out_dict

    @staticmethod
    def from_dict(policy_dict_cloud_level: Dict, logger=None) -> 'GCPAttachedAuthorizationPolicy':
        """
        Converts a dictionary to a policy.
        :param policy_dict: The dictionary representation of the policy.
        :param logger: optional. google.cloud logger object.
        :return: The policy representation of the dict.
        """
        if logger:
          logger.log_text("GCPAttachedAuthorization", severity="WARNING")
        else:
          print("GCPAttachedAuthorization")
        cloud_specific_policy = {}
        can_cloud_run = False
        print("Policy dict:", policy_dict_cloud_level)
        if isinstance(policy_dict_cloud_level, list):
          for cloud_auth in policy_dict_cloud_level:
              if GCPPolicy.GCP_CLOUD_NAME \
                              in cloud_auth:
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
        cloud_specific_policy['can_cloud_run'] = can_cloud_run
        print("Cloud-specific attached authorization policy:", cloud_specific_policy)
        return GCPAttachedAuthorizationPolicy(cloud_specific_policy)
    
class GCPImageLookupPolicy(ResourcePolicy):
    """
    Defines methods for GCP Image Lookup policies.
    """

    PUBLIC_PROJECTS = set([
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
        "ubuntu-os-pro-cloud"])

    def __init__(self):
        """
        :param policy: The dict of the policy to enforce.
        """
        self._image_regex_extractor = re.compile(r'compute/v1/projects/(?P<project>)/global/images/family/(?P<family>)$')
    
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
        "regions": re.compile(r"compute/v1/projects/(?P<project>[^/]+)/regions/(?P<region>[^/]+)"),
        "zones": re.compile(r"compute/v1/projects/(?P<project>[^/]+)/zones/(?P<zone>[^/]+)"),
        "reservations": re.compile(r"compute/v1/projects/(?P<project>[^/]+)/aggregated/reservations"),
        "firewalls": re.compile(
            r"compute/v1/projects/(?P<project>[^/]+)/global/"
            r"(firewalls"
            "|"
            r"networks/(?P<network>[^/]+)/getEffectiveFirewalls)"
        ),
        "subnetworks": re.compile(r"compute/v1/projects/(?P<project>[^/]+)/regions/(?P<region>[^/]+)/subnetworks"),
        "operations": re.compile(
            r"compute/v1/projects/(?P<project>[^/]+)/"
            r"(global|zones/(?P<zone>[^/]+))"
            r"/operations/(?P<operation>[^/]+)"
        )
    }

    class _PolicyDict(TypedDict):
        project: Union[str, None]
        regions: Union[List[str], None]
        zones: Union[List[str], None]
        reservations: bool
        firewalls: bool
        subnetworks: bool
        operations: bool

    def __init__(self, policy: _PolicyDict, policy_override: Union[bool, None]=None):
        """
        Create a new GCPReadPolicy instance.

        `policy_override` is used to specify DENY_ALL or ALLOW_ALL policies;
        if not None, then `policy` is ignored and a blanket ALLOW (if True) or DENY (if False) is used.
        """
        self._policy = policy
        self._policy_override = policy_override

    def check_request(self, request: Request) ->  bool:
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
            return {
                "project": match.group("project")
            }
        elif read_type == "regions":
            return {
                "region": match.group("region")
            }
        elif read_type == "zones":
            return {
                "zone": match.group("zone")
            }

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
        return GCPReadPolicy(GCPReadPolicy._get_default_policy_dict(), policy_override=False)

    @staticmethod
    def get_default_allow_policy():
        """
        Get default policy object, which allows all requests.
        """
        return GCPReadPolicy(GCPReadPolicy._get_default_policy_dict(), policy_override=True)

    @staticmethod
    def from_dict(policy_dict: Dict, logger=None) -> "GCPReadPolicy":
        """
        Parse dictionary to get relevant info.

        Expects a dictionary with the top level key as the cloud name ("gcp").
        """
        if GCPPolicy.GCP_CLOUD_NAME not in policy_dict or not isinstance(policy_dict[GCPPolicy.GCP_CLOUD_NAME], dict):
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


class GCPPolicy(CloudPolicy):
    """
    Defines methods for GCP policies.
    """

    GCP_CLOUD_NAME = "gcp"
    VM_REQUEST_KEYS = set([
        "name", # TODO should name really indicate VM?
        "networkInterfaces",
        "disks",
        "machineType"
    ])
    ATTACHED_AUTHORIZATION_KEYS = set([
        "serviceAccounts"
    ])

    def __init__(self, vm_policy: GCPVMPolicy, attached_authorization_policy: GCPAttachedAuthorizationPolicy, read_policy: GCPReadPolicy):
        """
        :param vm_policy: The GCP VM Policy to enforce.
        :param attached_policy_policy: The Attached Policy Policy to enforce.
        """
        self._resource_policies = {
            "virtual_machine": vm_policy,
            "attached_authorizations": attached_authorization_policy,
            "image_lookup": GCPImageLookupPolicy(),
            "read": read_policy,
            "unrecognized": UnrecognizedResourcePolicy()
        }
        self.valid_authorization = None
        print("GCPAuthorizationPolicy init:", self._resource_policies["attached_authorizations"]._policy)

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
            print("NOT JSON")
            if "images" in request.path:
                resource_types.add(("image_lookup",))
            else:
                # check all read request paths
                has_match = False
                for read_type, read_path_regex in GCPReadPolicy.READ_TYPE_URL_PATTERNS.items():
                    match = read_path_regex.search(request.path)
                    if match:
                        has_match = True
                        resource_types.add(("read", read_type))
                
                if not has_match:
                    # if no matches, then add unrecognized
                    resource_types.add(("unrecognized",))
        else:
            # Handle POST request
            print(request.get_json(cache=True))
            for key in request.get_json(cache=True).keys():
                print(key)
                if key in GCPPolicy.VM_REQUEST_KEYS:
                    resource_types.add(("virtual_machine",))
                elif key in GCPPolicy.ATTACHED_AUTHORIZATION_KEYS:
                    resource_types.add(("attached_authorizations",))
                else:
                    resource_types.add(("unrecognized",))
                    print(">>>>> UNRECOGNIZED RESOURCE TYPE <<<<<")
        print("All resource types:", list(resource_types))
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
        print("GCPPolicy check_resource_type:", resource_type)

        if resource_type_key == "attached_authorizations":
            # Authorization policies
            result = self._resource_policies[resource_type_key].check_request(request, self._authorization_manager)
            self.valid_authorization = result[0]
            return result[1]
        elif resource_type_key == "read":
            # read policies
            result = self._resource_policies[resource_type_key].check_read_request(request, *resource_type_aux)
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
            print("GCPPolicy resource type:", resource_type)
            print("GCPPolicy policy:", policy)
            if resource_type == "unrecognized" or resource_type == "image_lookup":
                continue
            out_dict[resource_type] = policy.to_dict()
        print(out_dict)
        return out_dict

    @staticmethod
    def from_dict(policy_dict: Dict, logger=None) -> 'GCPPolicy':
        """
        Converts a dictionary to a policy.
        :param policy_dict: The dictionary representation of the policy.
        :param logger: optional. google.cloud logger object.
        :return: The policy representation of the dict.
        """
        vm_dict = {}
        if "virtual_machine" in policy_dict:
            vm_dict = policy_dict["virtual_machine"]
            print("VM_DICT in GCPPolicy:from_dict", vm_dict)
        vm_policy = GCPVMPolicy.from_dict(vm_dict, logger)

        attached_authorization_dict = {}
        if "attached_authorizations" in policy_dict:
            attached_authorization_dict = policy_dict["attached_authorizations"]
        print("GCPPolicy attached authorizations dict:", attached_authorization_dict)
        attached_authorization_policy = GCPAttachedAuthorizationPolicy.from_dict(attached_authorization_dict, logger)

        if PolicyAction.READ.is_allowed_be_performed(vm_policy.get_policy_standard_form()["actions"]):
            if "reads" in policy_dict:
                read_dict = policy_dict["reads"]
                print("READS_DICT in GCPPolicy:from_dict", read_dict)
                read_policy = GCPReadPolicy.from_dict(read_dict, logger)
            else:
                # if reads are allowed, and there is no granular specification, then allow all
                read_policy = GCPReadPolicy.get_default_allow_policy()
        else:
            # if cannot read, then deny all reads
            read_policy = GCPReadPolicy.get_default_deny_policy()

        return GCPPolicy(vm_policy, attached_authorization_policy, read_policy)
