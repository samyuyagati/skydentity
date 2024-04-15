from typing import Dict, List, Tuple, TypedDict, Union
from flask import Request
import sys
import re
import hashlib
import base64
import logging as py_logging

from skydentity.policies.checker.resource_policy import (
    CloudPolicy, 
    ResourcePolicy, 
    VMPolicy, 
    UnrecognizedResourcePolicy,
    PolicyContentException
)
from skydentity.policies.checker.policy_actions import PolicyAction
from skydentity.policies.managers.azure_authorization_policy_manager import AzureAuthorizationPolicyManager

class AzureVMPolicy(VMPolicy):
    """
    Defines methods for Azure VM policies.
    """

    VM_PROPERTIES_ALLOWED_KEYS = set(["hardwareProfile", "storageProfile", "networkProfile", "osProfile", "priority", "billingProfile"])
    STORAGE_PROFILE_ALLOWED_KEYS = set(["osDisk", "imageReference"])
    OS_DISK_ALLOWED_KEYS = set(["createOption", "managedDisk", "diskSizeGB"])
    NETWORK_PROFILE_ALLOWED_KEYS = set(["networkInterfaces"])
    OS_PROFILE_ALLOWED_KEYS = set(["computerName", "adminUsername", "adminPassword", "linuxConfiguration", "customData"])

    DEFAULT_VM_GB = 256

    def __init__(self, policy: Dict):
        """
        :param policy: The dict of the policy to enforce.
        """
        self._policy = policy
        py_logging.basicConfig(filename='azure_resource_policy.log', level=py_logging.INFO)
        self._pylogger = py_logging.getLogger("AzureResourcePolicy")

    def check_request(self, request: Request) -> bool:
        """
        Checks the requests with defaultdeny

        Default properties set by SkyPilot (and consequently are checked here):
        storageProfile.osDisk.createOption = "fromImage"
        storageProfile.osDisk.managedDisk.storageAccountType = "Premium_LRS"
        storageProfile.osDisk.diskSizeGB = 256
        osProfile.linuxConfiguration.disablePasswordAuthentication = True
        """
        generic_vm_policy_check = super().check_request(request)
        if not generic_vm_policy_check:
            return False

        request_contents = request.get_json(cache=True)
        if "properties" in request_contents:
            # Default deny on VM properties
            for key in request_contents["properties"]:
                if key not in AzureVMPolicy.VM_PROPERTIES_ALLOWED_KEYS:
                    return False

            # Default deny on storage properties in VM
            if "storageProfile" in request_contents["properties"]:
                for key in request_contents["properties"]["storageProfile"]:
                    if key not in AzureVMPolicy.STORAGE_PROFILE_ALLOWED_KEYS:
                        return False

                # Check OS Disk
                if "osDisk" in request_contents["properties"]["storageProfile"]:
                    os_disk = request_contents["properties"]["storageProfile"]["osDisk"]
                    for key in os_disk:
                        if key not in AzureVMPolicy.OS_DISK_ALLOWED_KEYS:
                            return False
                    
                    # Check for certain values for certain osDisk entries
                    if "createOption" in os_disk and os_disk["createOption"] != "fromImage":
                        return False
                    
                    if "managedDisk" in os_disk and os_disk["managedDisk"]["storageAccountType"] != "Premium_LRS":
                        return False
                    
                    if "diskSizeGB" in os_disk and os_disk["diskSizeGB"] != AzureVMPolicy.DEFAULT_VM_GB:
                        self._pylogger.debug("Disk size is not default")
                        return False

            self._pylogger.debug("VM Past networkProfile")
            # Default deny on network properties in VM
            if "networkProfile" in request_contents["properties"]:
                for key in request_contents["properties"]["networkProfile"]:
                    if key not in AzureVMPolicy.NETWORK_PROFILE_ALLOWED_KEYS:
                        return False

            self._pylogger.debug("VM Past networkProfile")
            # Default deny on OS Profile
            if "osProfile" in request_contents["properties"]:
                for key in request_contents["properties"]["osProfile"]:
                    if key not in AzureVMPolicy.OS_PROFILE_ALLOWED_KEYS:
                        return False
                    
                # Ensure that if linux configuration is used, password authentication is disabled
                if "linuxConfiguration" in request_contents["properties"]["osProfile"]:
                    if "disablePasswordAuthentication" not in request_contents["properties"]["osProfile"]["linuxConfiguration"]:
                        return False

                    if not request_contents["properties"]["osProfile"]["linuxConfiguration"]["disablePasswordAuthentication"]:
                        return False

                    # Check for the existence of a given public key attached, even though this will be overriden later
                    if not "ssh" in request_contents["properties"]["osProfile"]["linuxConfiguration"] or \
                        not "publicKeys" in request_contents["properties"]["osProfile"]["linuxConfiguration"]["ssh"] or \
                        len(request_contents["properties"]["osProfile"]["linuxConfiguration"]["ssh"]["publicKeys"]) == 0:
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
            "startup_script": <startup script hash>
        }
        """
        out_dict = {
            "actions": None,
            "regions": [],
            "instance_type": [],
            "allowed_images": [],
            "startup_script": None
        }
        if request.method == 'POST' or request.method == 'PUT' or request.method == 'PATCH':
            out_dict["actions"] = PolicyAction.CREATE
        elif request.method == 'GET':
            out_dict["actions"] = PolicyAction.READ

        request_contents = request.get_json(cache=True)
        if "location" in request_contents:
            out_dict["regions"].append(request_contents["location"])

        if "properties" in request_contents:
            if "hardwareProfile" in request_contents["properties"]:
                out_dict["instance_type"].append(request_contents["properties"]["hardwareProfile"]["vmSize"])

        # Now get the image
        if "properties" in request_contents:
            if "storageProfile" in request_contents["properties"]:
                if "imageReference" in request_contents["properties"]["storageProfile"]:
                    image_reference = request_contents["properties"]["storageProfile"]["imageReference"]
                    if "offer" in image_reference and "sku" in image_reference:
                        image = f"{image_reference['offer']}:{image_reference['sku']}"
                        out_dict["allowed_images"].append(image)

        # Parse the setup script, if it exists
        if "properties" in request_contents:
            if "osProfile" in request_contents["properties"]:
                if "customData" in request_contents["properties"]["osProfile"]:
                        # The cloud-init script in Azure is base64 encoded, so decode before hashing
                        decoded_script = base64.b64decode(request_contents["properties"]["osProfile"]["customData"])
                        out_dict["startup_script"] = hashlib.sha256(decoded_script).hexdigest()

        return out_dict

    def to_dict(self) -> Dict:
        """
        Converts the policy to a dictionary so that it can be stored.
        :return: The dictionary representation of the policy.
        """
        out_dict = {
            "actions": [self._policy["actions"].value],
            "cloud_provider": [
                AzurePolicy.Azure_CLOUD_NAME
            ],
            "regions": {
                AzurePolicy.Azure_CLOUD_NAME: self._policy["regions"]
            },
            "instance_type": {
                AzurePolicy.Azure_CLOUD_NAME: self._policy["instance_type"]
            },
            "allowed_images": {
                AzurePolicy.Azure_CLOUD_NAME: self._policy["allowed_images"]
            },
            "startup_scripts": {
                AzurePolicy.Azure_CLOUD_NAME: self._policy["startup_scripts"]
            }
        }
        return out_dict
    
    @staticmethod
    def from_dict(policy_dict_cloud_level: Dict):
        """
        Distills a general multi-cloud policy into a cloud specific policy.
        :param policy_dict_cloud_level: The dictionary representation of the policy in terms of all clouds.
        :throws: Error if the policy is not valid.
        :return: The policy representation of the dict.
        """
        # self._pylogger.debug(str(policy_dict_cloud_level))

        cloud_specific_policy = {}
        cloud_specific_policy["can_cloud_run"] = AzurePolicy.Azure_CLOUD_NAME \
                            in policy_dict_cloud_level["cloud_provider"]
        if not cloud_specific_policy["can_cloud_run"]:
            raise PolicyContentException("Policy does not accept Azure")

        try:
            # self._pylogger.debug(policy_dict_cloud_level["actions"])
            action = PolicyAction[policy_dict_cloud_level["actions"][0]]
            cloud_specific_policy["actions"] = action
        except KeyError:
            raise PolicyContentException("Policy action is not valid")

        Azure_cloud_regions = []
        for region_group in policy_dict_cloud_level["regions"]:
            # self._pylogger.debug("REGION GROUP", region_group)
            if AzurePolicy.Azure_CLOUD_NAME in region_group:
                if isinstance(policy_dict_cloud_level["regions"], list):
                  Azure_cloud_regions = region_group[AzurePolicy.Azure_CLOUD_NAME] 
                else: 
                  Azure_cloud_regions = policy_dict_cloud_level["regions"][region_group] 
                break

        # TODO(kdharmarajan): Check that the regions are valid later (not essential)
        cloud_specific_policy["regions"] = Azure_cloud_regions

        Azure_instance_types = []
        for instance_type_group in policy_dict_cloud_level["instance_type"]:
            if AzurePolicy.Azure_CLOUD_NAME in instance_type_group:
                if isinstance(policy_dict_cloud_level["instance_type"], list):
                  Azure_instance_types = instance_type_group[AzurePolicy.Azure_CLOUD_NAME]
                else:
                  Azure_instance_types = policy_dict_cloud_level["instance_type"][AzurePolicy.Azure_CLOUD_NAME]
        cloud_specific_policy["instance_type"] = Azure_instance_types

        Azure_allowed_images = []
        for allowed_images_group in policy_dict_cloud_level["allowed_images"]:
            if isinstance(policy_dict_cloud_level["allowed_images"], list):
                Azure_allowed_images = allowed_images_group[AzurePolicy.Azure_CLOUD_NAME]
            else:
                Azure_allowed_images = policy_dict_cloud_level["allowed_images"][AzurePolicy.Azure_CLOUD_NAME]

        cloud_specific_policy["allowed_images"] = Azure_allowed_images

        # Handle startup scripts
        azure_startup_scripts = []
        for startup_script_group in policy_dict_cloud_level["startup_scripts"]:
            if AzurePolicy.Azure_CLOUD_NAME in startup_script_group:
                if isinstance(policy_dict_cloud_level["startup_scripts"], list):
                    azure_startup_scripts = startup_script_group[AzurePolicy.Azure_CLOUD_NAME]
                else:
                    azure_startup_scripts = policy_dict_cloud_level["startup_scripts"][AzurePolicy.Azure_CLOUD_NAME]
        cloud_specific_policy["startup_scripts"] = azure_startup_scripts
        return AzureVMPolicy(cloud_specific_policy)
    
class AzureAttachedAuthorizationPolicy(ResourcePolicy):
    """
    Defines methods for Azure Attached Policies (what Azure policies can be attached to a VM)
    """

    def __init__(self, policy: Dict):
        """
        :param policy: The dict of the policy to enforce.
        """
        self._policy = policy
        py_logging.basicConfig(filename='azure_resource_policy.log', level=py_logging.INFO)
        self._pylogger = py_logging.getLogger("AzureResourcePolicy")
        self._resource_group_extractor = re.compile(r"/resource[gG]roups/(?P<resourceGroupName>[^/]+)")

    def check_request(self, request: Request, auth_policy_manager: AzureAuthorizationPolicyManager, logger=None) -> Tuple[Union[str, None], bool]:
        """
        Enforces the policy on a request.
        :param request: The request to enforce the policy on.
        :return: True if the request is allowed, False otherwise.
        """
        self._pylogger.debug("check_request", flush=True)
        sys.stdout.flush()
        
        request_contents = request.get_json(cache=True)
        self._pylogger.debug(">>>request:", request_contents)

        # Handle attached managed identity capability
        if "managedIdentities" not in request_contents:
            return (None, True)
        
        # Expect a single attached managed identity
        if len(request_contents["managedIdentities"]) != 1:
            if logger:
                logger.log_text("Only one managed identity may be attached")
            else:
                self._pylogger.debug("Only one managed identity may be attached")
            return (None, False)

        # Expect a capability of the form:
        #   { 'nonce': XX, 'header': XX, 'ciphertext': XX, 'tag': XX }
        managed_identity_capability = request_contents["managedIdentities"][0]
        self._pylogger.debug(">>>managed_identity_capability:", managed_identity_capability)
        if (managed_identity_capability["nonce"] is None or \
            managed_identity_capability["header"] is None or \
            managed_identity_capability["ciphertext"] is None or \
            managed_identity_capability["tag"] is None):
            if logger:
                logger.log_text("Invalid capability format")
            else:
                self._pylogger.debug("Invalid capability format")
            return (None, False)
        
        managed_identity_id, success = auth_policy_manager.check_capability(managed_identity_capability)
        if not success:
            self._pylogger.debug("Unsuccessful in checking capability")
            return (None, False)

        # Double-check that the managed identity is allowed (e.g., if policy changed since
        # the capability was issued)
        self._pylogger.debug(self._policy[AzurePolicy.Azure_CLOUD_NAME][0]["authorization"])
        if managed_identity_id not in self._policy[AzurePolicy.Azure_CLOUD_NAME][0]["authorization"]:
            self._pylogger.debug("managed identity id", managed_identity_id, "not in", self._policy[AzurePolicy.Azure_CLOUD_NAME])
            return (None, False)
        
        # Now, change the resource group of the managed_identity_id to be the one in the new resource group
        # If the resource groups are the same
        request_resource_group_match = self._resource_group_extractor.search(request.path)
        if request_resource_group_match:
            request_resource_group = request_resource_group_match.group("resourceGroupName")
            source_managed_identity_resource_group = self._resource_group_extractor.search(managed_identity_id).group("resourceGroupName")

            if request_resource_group != source_managed_identity_resource_group:
                auth_policy_manager.duplicate_managed_identity(managed_identity_id, request_resource_group)

            managed_identity_id = managed_identity_id.replace(source_managed_identity_resource_group, request_resource_group)
        

        # If permitted, add the managed identity to the request
        return (managed_identity_id, True)

    def to_dict(self) -> Dict:
        """
        Converts the policy to a dictionary so that it can be stored.
        :return: The dictionary representation of the policy.
        """
        out_dict = {}
        self._pylogger.debug(self._policy)
        if AzurePolicy.Azure_CLOUD_NAME in self._policy:
            out_dict[AzurePolicy.Azure_CLOUD_NAME] = self._policy[AzurePolicy.Azure_CLOUD_NAME]
        return out_dict

    @staticmethod
    def from_dict(policy_dict_cloud_level: Dict, logger=None) -> 'AzureAttachedAuthorizationPolicy':
        """
        Converts a dictionary to a policy.
        :param policy_dict: The dictionary representation of the policy.
        :param logger: optional. azure.cloud logger object.
        :return: The policy representation of the dict.
        """
        if logger:
            logger.log_text("AzureAttachedAuthorization", severity="WARNING")
        # else:
        #     print("AzureAttachedAuthorization")
        cloud_specific_policy = {}
        can_cloud_run = False
        # print("Policy dict:", policy_dict_cloud_level)
        if isinstance(policy_dict_cloud_level, list):
            for cloud_auth in policy_dict_cloud_level:
                if AzurePolicy.Azure_CLOUD_NAME \
                              in cloud_auth:
                    can_cloud_run = True
                    managed_identities = cloud_auth[AzurePolicy.Azure_CLOUD_NAME]
                    cloud_specific_policy[AzurePolicy.Azure_CLOUD_NAME] = managed_identities
                    break
        else:
            for cloud_name in policy_dict_cloud_level:
                if not (cloud_name == AzurePolicy.Azure_CLOUD_NAME):
                    continue
                can_cloud_run = True
                managed_identities = policy_dict_cloud_level[cloud_name]
                cloud_specific_policy[AzurePolicy.Azure_CLOUD_NAME] = managed_identities
                break
        cloud_specific_policy['can_cloud_run'] = can_cloud_run
        # print("Cloud-specific attached authorization policy:", cloud_specific_policy)
        return AzureAttachedAuthorizationPolicy(cloud_specific_policy)

class AzureReadPolicy(ResourcePolicy):
    """Defines methods for Azure read request policies."""

    # TODO: instead of using regex, get information from routing done by the proxy
    READ_TYPE_URL_PATTERNS: Dict[str, re.Pattern] = {
        "virtualMachinesGeneral": re.compile(r"subscriptions/(?P<subscriptionId>[^/]+)/providers/Microsoft.Compute/virtualMachines"),
        "virtualMachines": re.compile(r"subscriptions/(?P<subscriptionId>[^/]+)/resourceGroups/(?P<resourceGroupName>[^/]+)/providers/Microsoft.Compute/virtualMachines"),
        "virtualMachineInstanceView": re.compile(r"subscriptions/(?P<subscriptionId>[^/]+)/resourceGroups/(?P<resourceGroupName>[^/]+)/providers/Microsoft.Compute/virtualMachines/(?P<vmName>[^/]+)/instanceView"),
        "networkInterfaces": re.compile(r"subscriptions/(?P<subscriptionId>[^/]+)/resourceGroups/(?P<resourceGroupName>[^/]+)/providers/Microsoft.Network/networkInterfaces/(?P<nicName>[^/]+)"),
        "ipAddresses": re.compile(r"subscriptions/(?P<subscriptionId>[^/]+)/resourceGroups/(?P<resourceGroupName>[^/]+)/providers/Microsoft.Network/publicIPAddresses/(?P<ipName>[^/]+)"),
        "operations": re.compile(r"subscriptions/(?P<subscriptionId>[^/]+)/providers/Microsoft.Compute/locations/(?P<region>[^/]+)/operations/(?P<operationId>[^/]+)"),
        "virtualNetworks": re.compile(r"subscriptions/(?P<subscriptionId>[^/]+)/resourceGroups/(?P<resourceGroupName>[^/]+)/providers/Microsoft.Network/virtualNetworks/(?P<virtualNetworkName>[^/]+)"),
        "subnets": re.compile(r"subscriptions/(?P<subscriptionId>[^/]+)/resourceGroups/(?P<resourceGroupName>[^/]+)/providers/Microsoft.Network/virtualNetworks/(?P<virtualNetworkName>[^/]+)/subnets/(?P<subnetName>[^/]+)"),
        "networkSecurityGroups": re.compile(r"subscriptions/(?P<subscriptionId>[^/]+)/resourceGroups/(?P<resourceGroupName>[^/]+)/providers/Microsoft.Network/networkSecurityGroups/(?P<nsgName>[^/]+)"),
        "deployments": re.compile(r"subscriptions/(?P<subscriptionId>[^/]+)/resourcegroups/(?P<resourceGroupName>[^/]+)/providers/Microsoft.Resources/deployments/(?P<deploymentName>[^/]+)"),
    }

    class _PolicyDict(TypedDict):
        resource_group: Union[List[str], None]
        regions: Union[List[str], None]
        virtualMachines: bool
        virtualMachineInstanceView: bool
        networkInterfaces: bool
        ipAddresses: bool
        operations: bool
        virtualNetworks: bool
        subnets: bool
        networkSecurityGroups: bool
        deployments: bool

    def __init__(self, policy: _PolicyDict, policy_override: Union[bool, None]=None):
        """
        Create a new AzureReadPolicy instance.

        `policy_override` is used to specify DENY_ALL or ALLOW_ALL policies;
        if not None, then `policy` is ignored and a blanket ALLOW (if True) or DENY (if False) is used.
        """
        self.policy = policy
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

        assert len(aux_info) > 0 and aux_info[0] in AzureReadPolicy.READ_TYPE_URL_PATTERNS
        read_type = aux_info[0]

        request_info = self._get_request_info(request, read_type)

        if read_type == "virtualMachinesGeneral":
            return self.policy["virtualMachines"]
        elif read_type == "operations":
            return self.policy["operations"] and request_info["region"] in self.policy["regions"]
        # The rest of the read types should include a resource group
        # TODO: Optionally specify resource group constraint on the GET requests
        return self.policy[read_type]

    def _get_request_info(self, request: Request, read_type: str):
        """Parse path to get the appropriate request information"""

        url_pattern = AzureReadPolicy.READ_TYPE_URL_PATTERNS[read_type]
        match = url_pattern.search(request.path)

        assert match, "URL does not match read type pattern"

        possible_resource_group = match.group("resourceGroupName")
        # Only need to check the resource group also
        if possible_resource_group:
            return {
                "resource_group": possible_resource_group,
            }
        elif read_type == "operations":
            return {
                "region": match.group("region")
            }

        # all other read types do not use any auxiliary information from the path
        return {}

    @staticmethod
    def _get_default_policy_dict() -> _PolicyDict:
        """
        Get default policy dictionary, which allows all requests.
        """
        return {
            "resource_group": None,
            "regions": None,
            "virtualMachines": True,
            "virtualMachineInstanceView": True,
            "networkInterfaces": True,
            "ipAddresses": True,
            "operations": True,
            "virtualNetworks": True,
            "subnets": True,
            "networkSecurityGroups": True,
            "deployments": True
        }

    @staticmethod
    def get_default_deny_policy():
        """
        Get default policy object, which denies all requests.
        """
        return AzureReadPolicy(AzureReadPolicy._get_default_policy_dict(), policy_override=False)

    @staticmethod
    def get_default_allow_policy():
        """
        Get default policy object, which allows all requests.
        """
        return AzureReadPolicy(AzureReadPolicy._get_default_policy_dict(), policy_override=True)

    @staticmethod
    def from_dict(policy_dict: Dict, logger=None) -> "AzureReadPolicy":
        """
        Parse dictionary to get relevant info.

        Expects a dictionary with the top level key as the cloud name ("azure").
        """
        if AzurePolicy.Azure_CLOUD_NAME not in policy_dict or not isinstance(policy_dict[AzurePolicy.Azure_CLOUD_NAME], dict):
            # no valid section found
            return AzureReadPolicy.get_default_deny_policy()

        azure_policy = policy_dict[AzurePolicy.Azure_CLOUD_NAME]

        # allow if not specified
        out_dict = AzureReadPolicy._get_default_policy_dict()
        for key in out_dict:
            if key in azure_policy:
                out_dict[key] = azure_policy[key]

        return AzureReadPolicy(out_dict)

    def to_dict(self):
        return {
            AzurePolicy.Azure_CLOUD_NAME: {
                # filter out None items
                k: v for k, v in self.policy.items() if v is not None
            }
        }

class AzureDefaultDenyPolicy(CloudPolicy):
    """
    For certain recognized request types, provides default deny
    """

    DEFAULT_DENY_PATTERNS: Dict[str, re.Pattern] = {
        "resourceGroup": re.compile(r"subscriptions/(?P<subscriptionId>[^/]+)/resourcegroups/(?P<resourceGroupName>[^/]+)"),
        "virtualNetworks": re.compile(r"subscriptions/(?P<subscriptionId>[^/]+)/resourceGroups/(?P<resourceGroupName>[^/]+)/providers/Microsoft.Network/virtualNetworks/(?P<virtualNetworkName>[^/]+)"),
        "networkSecurityGroups": re.compile(r"subscriptions/(?P<subscriptionId>[^/]+)/resourceGroups/(?P<resourceGroupName>[^/]+)/providers/Microsoft.Network/networkSecurityGroups/(?P<nsgName>[^/]+)"),
        "publicIPAddresses": re.compile(r"subscriptions/(?P<subscriptionId>[^/]+)/resourceGroups/(?P<resourceGroupName>[^/]+)/providers/Microsoft.Network/publicIPAddresses/(?P<ipName>[^/]+)"),
        "networkInterfaces": re.compile(r"subscriptions/(?P<subscriptionId>[^/]+)/resourceGroups/(?P<resourceGroupName>[^/]+)/providers/Microsoft.Network/networkInterfaces/(?P<nicName>[^/]+)")
    }

    def __init__(self, 
                 allowed_regions: List[str], 
                 allowed_resource_group_names: List[str]):
        """
        :param allowed_regions: The list of allowed regions.
        :param allowed_resource_group_names: The list of allowed resource group names.
        """
        self.allowed_regions = allowed_regions
        self.allowed_resource_group_names = allowed_resource_group_names
        self._resource_group_extractor = re.compile(r"/resourcegroups/(?P<resourceGroupName>[^/]+)")
        py_logging.basicConfig(filename='azure_resource_policy.log', level=py_logging.INFO)
        self._pylogger = py_logging.getLogger("AzureResourcePolicy")

    def check_request(self, request: Request) ->  bool:
        raise NotImplemented("Use `check_default_deny_request` instead.")
    
    def check_default_deny_request(self, request: Request, *aux_info: str) -> bool:
        self._pylogger.debug("Called check_default_deny_request with aux_info:", aux_info)
        default_deny_type = aux_info[0]
        request_contents = request.get_json(cache=True)
        if "location" in request_contents and request_contents["location"] not in self.allowed_regions:
            return False

        if default_deny_type == "resourceGroup":
            resource_group = self._resource_group_extractor.search(request.path).group("resourceGroupName")
            return resource_group is not None and resource_group in self.allowed_resource_group_names

        elif default_deny_type == "virtualNetworks":
            """
            Default virtual network requests of the form are:
            {
                'location': 'westus', 
                'properties': {
                    'addressSpace': {
                        'addressPrefixes': ['10.146.0.0/16']
                    },
                    'subnets': [
                        {
                            'properties': {
                                'addressPrefix': '10.146.0.0/16'
                            }
                        }
                    ]
                }
            }
            """
            if "properties" in request_contents:
                if "addressSpace" in request_contents["properties"]:
                    address_space = request_contents["properties"]["addressSpace"]
                    if "addressPrefixes" in address_space:
                        if len(address_space["addressPrefixes"]) != 1:
                            return False
                        if not re.search(r'^10\.\d+\.0\.0\/16$', address_space["addressPrefixes"][0]):
                            return False
                
                if "subnets" in request_contents["properties"]:
                    subnets = request_contents["properties"]["subnets"]
                    for subnet in subnets:
                        if "properties" in subnet and "addressPrefix" in subnet["properties"]:
                            if not re.search(r'^10\.\d+\.0\.0\/16$', subnet["properties"]["addressPrefix"]):
                                return False

        elif default_deny_type == "networkSecurityGroups":
            """
            Default network security group requests of the form are:
            {'location': 'westus', 'properties': 
                {'securityRules': [
                    {'name': 'ssh', 
                    'properties': {
                        'protocol': 'Tcp', 
                        'sourcePortRange': '*', 
                        'destinationPortRange': '22', 
                        'sourceAddressPrefix': '*', 
                        'destinationAddressPrefix': '*', 
                        'access': 'Allow', 
                        'priority': 100, 
                        'direction': 'Inbound'}}
                    ]
                }
            }
            """
            # Basically, check only for the existence of an inbound port 22 rule for Tcp            
            if "properties" in request_contents and "securityRules" in request_contents["properties"]:
                security_rules = request_contents["properties"]["securityRules"]
                if len(security_rules) != 1:
                    return False
                
                rule = security_rules[0]
                if "properties" in rule:
                    rule_properties = rule["properties"]
                    if ("direction" in rule_properties and rule_properties["direction"] == "Inbound") and \
                        ("protocol" in rule_properties and rule_properties["protocol"].lower() == "tcp") and \
                        ("destinationPortRange" in rule_properties and rule_properties["destinationPortRange"] == "22") and \
                        ("sourceAddressPrefix" in rule_properties and rule_properties["sourceAddressPrefix"] == "*") and \
                        ("destinationAddressPrefix" in rule_properties and rule_properties["destinationAddressPrefix"] == "*") and \
                        ("sourcePortRange" in rule_properties and rule_properties["sourcePortRange"] == "*"):
                            return True
                return False
        
        elif default_deny_type == "publicIPAddresses":
            """
            Default public IP address requests of the form are:
            {'location': 'westus', 'properties': {'publicIPAllocationMethod': 'Static'}}
            """            
            if "properties" in request_contents and "publicIPAllocationMethod" in request_contents["properties"]:
                if request_contents["properties"]["publicIPAllocationMethod"] != "Static":
                    return False

        elif default_deny_type == "networkInterfaces":
            """
            Default network interface requests of the form are:
            {'location': 'westus', 
            'properties': {
                'networkSecurityGroup': {
                    'id': '/subscriptions/x/resourceGroups/skydentity/providers/Microsoft.Network/networkSecurityGroups/skydentity-nsg'
                    }, 
                    'ipConfigurations': [
                        {'name': 'skydentity-ip-config', 
                        'properties': {
                            'subnet': {
                                'id': '/subscriptions/x/resourceGroups/skydentity/providers/Microsoft.Network/virtualNetworks/skydentity-vnet/subnets/skydentity-subnet'}, 
                                'publicIPAddress': {
                                    'id': '/subscriptions/x/resourceGroups/skydentity/providers/Microsoft.Network/publicIPAddresses/skydentity-ip'
                                    }
                                }
                            }
                        ]
                    }
                }
            """
            # Just check that it contains certain keys
            if not ("properties" in request_contents and "networkSecurityGroup" in request_contents["properties"] and \
                "ipConfigurations" in request_contents["properties"]):
                return False

        return True

class AzureDeploymentPolicy(ResourcePolicy):
    """
    Defines methods for Azure Deployment policies.
    """

    RESOURCE_NAME_TO_DEFAULT_DENY_KEY = {
        "Microsoft.Network/virtualNetworks": "virtualNetworks",
        "Microsoft.Network/networkSecurityGroups": "networkSecurityGroups",
        "Microsoft.Network/publicIpAddresses": "publicIPAddresses",
        "Microsoft.Network/networkInterfaces": "networkInterfaces"
    }

    class MockAzureRequest:
        """
        Internal class used to mock Azure requests on resource creation.
        """
        def __init__(self, json_contents: Dict, method: str, path: str = ''):
            self.json_contents = json_contents
            self.method = method
            self.path = path

        def get_json(self, cache=False):
            return self.json_contents

    def __init__(self, 
                 azure_vm_policy: AzureVMPolicy, 
                 attached_authorization_policy: AzureAttachedAuthorizationPolicy,
                 default_deny_policy: AzureDefaultDenyPolicy):
        """
        :param azure_vm_policy: The Azure VM Policy to enforce.
        :param attached_authorization_policy: The Attached Policy Policy to enforce.
        :param default_deny_policy: The default deny policy to enforce.
        :param auth_policy_manager: The authorization policy manager to use.
        """
        self._azure_vm_policy = azure_vm_policy
        self._attached_authorization_policy = attached_authorization_policy
        self._default_deny_policy = default_deny_policy

        self._param_extractor = re.compile(r"^\[parameters\('(?P<param_name>[^']+)'\)\]$")
        self._resource_group_extractor = re.compile(r"/resourcegroups/(?P<resourceGroupName>[^/]+)")
        py_logging.basicConfig(filename='azure_resource_policy.log', level=py_logging.INFO)
        self._pylogger = py_logging.getLogger("AzureResourcePolicy")

    def check_request(self, request: Request, auth_policy_manager: AzureAuthorizationPolicyManager) -> Tuple[Union[str, None], bool]:
        """
        Enforces the policy on a request.
        :param request: The request to enforce the policy on.
        :return: For the first parameter, return a managed identity id if the request is allowed, None otherwise.
        True if the request is allowed, False otherwise for the first parameter. 
        """
        request_contents = request.get_json(cache=True)
        # Check that the deployment's resource group is one of the valid resource groups specified in the policy
        # This implicitly checks that the deployment has a valid location as well assuming other checks pass
        resource_group = self._resource_group_extractor.search(request.path).group("resourceGroupName")
        if resource_group not in self._default_deny_policy.allowed_resource_group_names:
            return (None, False)
        
        returned_managed_identity = None
        if "properties" in request_contents:
            # Load up all of the parameters
            parameters = {}
            if "parameters" in request_contents["properties"]:
                for parameter in request_contents["properties"]["parameters"]:
                    parameters[parameter] = request_contents["properties"]["parameters"][parameter]["value"]

            if "template" in request_contents["properties"]:
                template = request_contents["properties"]["template"]

                # Check that the variable for location is the resource group's location
                if "variables" in template:
                    if "location" in template["variables"]:
                        if template["variables"]["location"] != f"[resourceGroup().location]":
                            return (None, False)

                if "resources" in template:
                    for resource in template["resources"]:
                        self._pylogger.debug("Resource: ", resource)
                        if "type" in resource:
                            resource_type = resource["type"]
                            if resource_type == "Microsoft.Compute/virtualMachines":
                                # Check the VM policy
                                vm_request = self.convert_vm_source_to_vm_request(resource, parameters, request.path)
                                if "location" in vm_request.get_json():
                                    if vm_request.get_json()["location"] != "[variables('location')]":
                                        return (None, False)
                                    del vm_request.get_json()["location"]

                                attached_auth_mock_request = AzureDeploymentPolicy.MockAzureRequest(request_contents, "PUT", request.path)
                                returned_managed_identity, should_succeed = \
                                    self._attached_authorization_policy.check_request(attached_auth_mock_request, auth_policy_manager)

                                if not should_succeed or not self._azure_vm_policy.check_request(vm_request):
                                    return (None, False)

                            else:
                                # Check the default deny policy
                                converted_request = self.convert_generic_source_to_mock_request(resource, parameters, request.path)
                                if resource_type not in AzureDeploymentPolicy.RESOURCE_NAME_TO_DEFAULT_DENY_KEY:
                                    self._pylogger.debug(f"Resource type {resource_type} not in allowed part of default deny policy")
                                    return (None, False)
                                
                                if "location" in converted_request.get_json():
                                    if converted_request.get_json()["location"] != "[variables('location')]":
                                        return (None, False)
                                    del converted_request.get_json()["location"]

                                default_deny_key = AzureDeploymentPolicy.RESOURCE_NAME_TO_DEFAULT_DENY_KEY[resource_type]
                                if not self._default_deny_policy.check_default_deny_request(converted_request, default_deny_key):
                                    self._pylogger.debug("Default deny policy failed check")
                                    return (None, False)
                                self._pylogger.debug("Passed defaultdeny on other objects")
        self._pylogger.debug("Successful request check")
        return returned_managed_identity, True
    
    def convert_vm_source_to_vm_request(self, vm_source_dict, parameters_dict, path) -> 'AzureDeploymentPolicy.MockAzureRequest':
        """
        Converts a the VM template resource into a mock request that can be checked by the vm policy.
        :param vm_source_dict: The VM template resource.
        :param parameters_dict: The parameters for the template.
        :param path: The path of the request.
        """
        request_body = {
            "properties": {
            }
        }
        if "properties" in vm_source_dict:
            if "hardwareProfile" in vm_source_dict["properties"]:
                hardware_profile = vm_source_dict["properties"]["hardwareProfile"]
                request_body["properties"]["hardwareProfile"] = self.recursively_resolve_parameters(hardware_profile, parameters_dict)

            if "storageProfile" in vm_source_dict["properties"]:
                storage_profile = vm_source_dict["properties"]["storageProfile"]
                request_body["properties"]["storageProfile"] = self.recursively_resolve_parameters(storage_profile, parameters_dict)

            if "osProfile" in vm_source_dict["properties"]:
                os_profile = vm_source_dict["properties"]["osProfile"]
                request_body["properties"]["osProfile"] = self.recursively_resolve_parameters(os_profile, parameters_dict)

            if "networkProfile" in vm_source_dict["properties"]:
                network_profile = vm_source_dict["properties"]["networkProfile"]
                request_body["properties"]["networkProfile"] = self.recursively_resolve_parameters(network_profile, parameters_dict)
        if "location" in vm_source_dict:
            request_body["location"] = vm_source_dict["location"]

        return AzureDeploymentPolicy.MockAzureRequest(request_body, "PUT", path)
    
    def convert_generic_source_to_mock_request(self, generic_source_dict, parameters_dict, path) -> 'AzureDeploymentPolicy.MockAzureRequest':
        """
        Converts a generic resource template into a mock request that can be checked by the default deny policy.
        :param generic_source_dict: The generic resource template.
        :param parameters_dict: The parameters for the template.
        :param path: The path of the request.
        """
        request_body = {}
        request_body["properties"] = self.recursively_resolve_parameters(generic_source_dict["properties"], parameters_dict)
        if "location" in generic_source_dict:
            request_body["location"] = generic_source_dict["location"]
        return AzureDeploymentPolicy.MockAzureRequest(request_body, "PUT", path)

    def recursively_resolve_parameters(self, template: Dict, parameters: Dict) -> Dict:
        """
        Recursively resolves the parameters in the template.
        :param template: The template to resolve the parameters in.
        :param parameters: The parameters to resolve.
        :return: The template with the parameters resolved.
        """
        out_template = {}
        for key in template:
            if isinstance(template[key], dict):
                out_template[key] = self.recursively_resolve_parameters(template[key], parameters)
            else:
                if isinstance(template[key], str):
                    match = self._param_extractor.match(template[key])
                    if match:
                        out_template[key] = parameters[match.group("param_name")]
                    else:
                        out_template[key] = template[key]
                else:
                    if isinstance(template[key], list):
                        out_template[key] = []
                        for item in template[key]:
                            if isinstance(item, dict):
                                out_template[key].append(self.recursively_resolve_parameters(item, parameters))
                            else:
                                new_item = item
                                # TODO(kdharmarajan): Nasty code reuse here
                                if isinstance(item, str):
                                    match = self._param_extractor.match(item)
                                    if match:
                                        new_item = parameters[match.group("param_name")]

                                out_template[key].append(new_item)
                    else:
                        out_template[key] = template[key]
        return out_template

class AzurePolicy(CloudPolicy):
    """
    Defines methods for Azure policies.
    """

    Azure_CLOUD_NAME = "azure"
    ATTACHED_AUTHORIZATION_KEYS = set([
        "managedIdentities"
    ])

    UPDATE_VM_PROPERTY_PATTERN = re.compile(r"subscriptions/(?P<subscriptionId>[^/]+)/resourceGroups/(?P<resourceGroupName>[^/]+)/providers/Microsoft.Compute/virtualMachines/(?P<vmName>[^/]+)")
    VM_CREATE_PATTERN = re.compile(r"subscriptions/(?P<subscriptionId>[^/]+)/resourceGroups/(?P<resourceGroupName>[^/]+)/providers/Microsoft.Compute/virtualMachines")

    def __init__(self, vm_policy: AzureVMPolicy, attached_authorization_policy: AzureAttachedAuthorizationPolicy, read_policy: AzureReadPolicy):
        """
        :param vm_policy: The Azure VM Policy to enforce.
        :param attached_authorization_policy: The Attached Policy Policy to enforce.
        """
        # Regions and resource group for default deny is specified here, but note that this may have to be refactored later
        default_deny_policy = AzureDefaultDenyPolicy(
            read_policy.policy["regions"], 
            read_policy.policy["resource_group"]
            )

        self._resource_policies = {
            "virtual_machine": vm_policy,
            "attached_authorizations": attached_authorization_policy,
            "reads": read_policy,
            "unrecognized": UnrecognizedResourcePolicy(),
            "default_deny": default_deny_policy,
            "deployments": AzureDeploymentPolicy(vm_policy, 
                                                 attached_authorization_policy, 
                                                 default_deny_policy),
        }
        self.valid_authorization: Union[str, None] = None
        py_logging.basicConfig(filename='azure_resource_policy.log', level=py_logging.INFO)
        self._pylogger = py_logging.getLogger("AzureResourcePolicy")

    def get_request_resource_types(self, request: Request) -> List[str]:
        """
        Gets the resource types that the request is trying to access / create / delete.
        :param request: The request to get the resource types from.
        :return: The resource types that the request is trying to access as a list of names.
        """
        resource_types = set([])
        # TODO(later): Refactoring the logic to reuse better
        if request.method == 'GET':
            self._pylogger.debug("NOT JSON")
            has_match = False
            for read_type, read_path_regex in AzureReadPolicy.READ_TYPE_URL_PATTERNS.items():
                match = read_path_regex.search(request.path)
                if match:
                    has_match = True
                    resource_types.add(("reads", read_type))
            
            if not has_match:
                # if no matches, then add unrecognized
                resource_types.add(("unrecognized",))
            return list(resource_types)
        
        else:
            
            if request.method == 'PATCH':
                match = AzurePolicy.UPDATE_VM_PROPERTY_PATTERN.search(request.path)
                if match:
                    resource_types.add(("virtual_machine",))
                    return list(resource_types)
            
            if "deployments" in request.url:
                resource_types.add(("deployments",))
                return list(resource_types)

            vm_match = AzurePolicy.VM_CREATE_PATTERN.search(request.path)
            if vm_match:
                resource_types.add(("virtual_machine",))

            for default_deny_type, default_deny_path_regex in AzureDefaultDenyPolicy.DEFAULT_DENY_PATTERNS.items():
                match = default_deny_path_regex.search(request.path)
                if match:
                    resource_types.add(("default_deny", default_deny_type))

            for key in request.get_json(cache=True).keys():
                self._pylogger.debug(key)
                if key in AzurePolicy.ATTACHED_AUTHORIZATION_KEYS:
                    resource_types.add(("attached_authorizations",))
        if len(resource_types) == 0:
            resource_types.add(("unrecognized",))
            self._pylogger.debug(">>>>> ALL UNRECOGNIZED RESOURCE TYPES <<<<<")
        self._pylogger.debug("All resource types:", list(resource_types))
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
        self._pylogger.debug("AzurePolicy check_resource_type:", resource_type_key)

        if resource_type_key == "attached_authorizations":
            # Authorization policies
            result = self._resource_policies[resource_type_key].check_request(request, self._authorization_manager)
            self.valid_authorization = result[0]
            return result[1]
        elif resource_type_key == "reads":
            # Read policies
            return self._resource_policies[resource_type_key].check_read_request(request, *resource_type_aux)
        elif resource_type_key == "default_deny":
            # Default deny policies
            return self._resource_policies[resource_type_key].check_default_deny_request(request, *resource_type_aux)
        elif resource_type_key == "deployments":
            # Deployment policies
            result = self._resource_policies[resource_type_key].check_request(request, self._authorization_manager)
            self.valid_authorization = result[0]
            return result[1]
        return self._resource_policies[resource_type_key].check_request(request)

    def set_authorization_manager(self, manager: AzureAuthorizationPolicyManager):
        self._authorization_manager = manager

    def to_dict(self) -> Dict:
        """
        Converts the policy to a dictionary so that it can be stored.
        :return: The dictionary representation of the policy.
        """
        out_dict = {}
        for resource_type, policy in self._resource_policies.items():
            self._pylogger.debug("AzurePolicy resource type:", resource_type)
            self._pylogger.debug("AzurePolicy policy:", policy)
            if resource_type == "unrecognized" or resource_type == "deployments" or resource_type == "default_deny":
                continue
            out_dict[resource_type] = policy.to_dict()
        self._pylogger.debug(out_dict)
        return out_dict

    @staticmethod
    def from_dict(policy_dict: Dict) -> 'AzurePolicy':
        """
        Converts a dictionary to a policy.
        :param policy_dict: The dictionary representation of the policy.
        :return: The policy representation of the dict.
        """
        vm_dict = {}
        if "virtual_machine" in policy_dict:
            vm_dict = policy_dict["virtual_machine"]
            # print("VM_DICT in AzurePolicy:from_dict", vm_dict)
        vm_policy = AzureVMPolicy.from_dict(vm_dict)

        attached_policy_dict = {}
        if "attached_authorizations" in policy_dict:
            attached_policy_dict = policy_dict["attached_authorizations"]
        if "attached_authorizations" in vm_dict:
            attached_policy_dict = vm_dict["attached_authorizations"]
        # print("AzurePolicy attached authorizations dict:", attached_policy_dict)
        attached_authorization_policy = AzureAttachedAuthorizationPolicy.from_dict(attached_policy_dict)
        if PolicyAction.READ.is_allowed_be_performed(vm_policy.get_policy_standard_form()["actions"]):
            if "reads" in policy_dict:
                read_dict = policy_dict["reads"]
                # print("READS_DICT in AzurePolicy:from_dict", read_dict)
                read_policy = AzureReadPolicy.from_dict(read_dict)
            else:
                # if reads are allowed, and there is no granular specification, then allow all
                read_policy = AzureReadPolicy.get_default_allow_policy()
        else:
            # if cannot read, then deny all reads
            read_policy = AzureReadPolicy.get_default_deny_policy()

        return AzurePolicy(vm_policy, attached_authorization_policy, read_policy)