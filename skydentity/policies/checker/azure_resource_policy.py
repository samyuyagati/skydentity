from typing import Dict, List, Tuple, TypedDict, Union, Optional
from flask import Request
import sys
import re
import hashlib
import base64

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

    VM_PROPERTIES_DENIED_KEYS = set(["additionalCapabilities", "applicationProfile", "availabilitySet",
                                      "capacityReservation", "diagnosticsProfile", "evictionPolicy", 
                                      "extensionsTimeBudget", "host", "hostGroup", 
                                      "instanceView", "licenseType", "platformFaultDomain",
                                      "provisioningState", "proximityPlacementGroup", "scheduledEventsProfile",
                                      "securityProfile", "timeCreated", "userData", 
                                      "virtualMachineScaleSet"])
    STORAGE_PROFILE_DENIED_KEYS = set(["dataDisks", "diskControllerType"])
    OS_DISK_DENIED_KEYS = set(["caching", "encryptionSettings", "managedDisk", "deleteOption", "vhd", "writeAccelerator"])
    NETWORK_PROFILE_DENIED_KEYS = set(["networkInterfaceConfigurations"])
    OS_PROFILE_DENIED_KEYS = set(["requireGuestProvisionSignal", "secrets", "allowExtensionOperations"])

    def __init__(self, policy: Dict):
        """
        :param policy: The dict of the policy to enforce.
        """
        self._policy = policy

    def check_request(self, request: Request) -> bool:
        """
        Checks the requests with defaultdeny
        """
        generic_vm_policy_check = super().check_request(request)
        if not generic_vm_policy_check:
            return False
        
        request_contents = request.get_json(cache=True)
        if "properties" in request_contents:
            # Default deny on VM properties
            for key in request_contents["properties"]:
                if key in AzureVMPolicy.VM_PROPERTIES_DENIED_KEYS:
                    return False
            
            # Default deny on storage properties in VM
            if "storageProfile" in request_contents["properties"]:
                for key in request_contents["properties"]["storageProfile"]:
                    if key in AzureVMPolicy.STORAGE_PROFILE_DENIED_KEYS:
                        return False

                # Check OS Disk
                if "osDisk" in request_contents["properties"]["storageProfile"]:
                    os_disk = request_contents["properties"]["storageProfile"]["osDisk"]
                    for key in os_disk:
                        if key in AzureVMPolicy.OS_DISK_DENIED_KEYS:
                            return False
                    
                    # Check for certain values for certain osDisk entries
                    if "createOption" in os_disk and os_disk["createOption"] != "FromImage":
                        return False
    
            # Default deny on network properties in VM
            if "networkProfile" in request_contents["properties"]:
                for key in request_contents["properties"]["networkProfile"]:
                    if key in AzureVMPolicy.NETWORK_PROFILE_DENIED_KEYS:
                        return False
            
            # Default deny on OS Profile
            if "osProfile" in request_contents["properties"]:
                for key in request_contents["properties"]["osProfile"]:
                    if key in AzureVMPolicy.OS_PROFILE_DENIED_KEYS:
                        return False
                    
                # Ensure that if linux configuration is used, password authentication is disabled
                if "linuxConfiguration" in request_contents["properties"]["osProfile"]:
                    if "disablePasswordAuthentication" not in request_contents["properties"]["osProfile"]["linuxConfiguration"] \
                        and not request_contents["properties"]["osProfile"]["linuxConfiguration"]["disablePasswordAuthentication"]:
                        return False

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
        cloud_specific_policy = {}
        cloud_specific_policy["can_cloud_run"] = AzurePolicy.Azure_CLOUD_NAME \
                            in policy_dict_cloud_level["cloud_provider"]
        if not cloud_specific_policy["can_cloud_run"]:
            raise PolicyContentException("Policy does not accept Azure")

        try:
            action = PolicyAction[policy_dict_cloud_level["actions"][0]]
            cloud_specific_policy["actions"] = action
        except KeyError:
            raise PolicyContentException("Policy action is not valid")

        Azure_cloud_regions = []
        for region_group in policy_dict_cloud_level["regions"]:
            print("REGION GROUP", region_group)
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
    
    def check_request(self, request: Request, auth_policy_manager: AzureAuthorizationPolicyManager, logger=None) -> Tuple[Union[str, None], bool]:
        """
        Enforces the policy on a request.
        :param request: The request to enforce the policy on.
        :return: True if the request is allowed, False otherwise.
        """
        print("check_request", flush=True)
        sys.stdout.flush()
        
        request_contents = request.get_json(cache=True)
        print(">>>request:", request_contents)

        # Handle attached managed identity capability
        if "managedIdentities" not in request_contents:
            return (None, True)
        
        # Expect a single attached managed identity
        if len(request_contents["managedIdentities"]) != 1:
            if logger:
                logger.log_text("Only one managed identity may be attached", severity="WARNING")
            else:
                print("Only one managed identity may be attached")
            return (None, False)

        # Expect a capability of the form:
        #   { 'nonce': XX, 'header': XX, 'ciphertext': XX, 'tag': XX }
        managed_identity_capability = request_contents["managedIdentities"][0]
        print(">>>managed_identity_capability:", managed_identity_capability)
        if (managed_identity_capability["nonce"] is None or \
            managed_identity_capability["header"] is None or \
            managed_identity_capability["ciphertext"] is None or \
            managed_identity_capability["tag"] is None):
            if logger:
                logger.log_text("Invalid capability format", severity="WARNING")
            else:
                print("Invalid capability format")
            return (None, False)
        
        managed_identity_id, success = auth_policy_manager.check_capability(managed_identity_capability)
        if not success:
            print("Unsuccessful in checking capability")
            return (None, False)

        # Double-check that the managed identity is allowed (e.g., if policy changed since
        # the capability was issued)
        print(self._policy[AzurePolicy.Azure_CLOUD_NAME][0]["authorization"])
        if managed_identity_id not in self._policy[AzurePolicy.Azure_CLOUD_NAME][0]["authorization"]:
            print("managed identity id", managed_identity_id, "not in", self._policy[AzurePolicy.Azure_CLOUD_NAME])
            return (None, False)
        
        # If permitted, add the managed identity to the request
        return (managed_identity_id, True)

    def to_dict(self) -> Dict:
        """
        Converts the policy to a dictionary so that it can be stored.
        :return: The dictionary representation of the policy.
        """
        out_dict = {}
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
        else:
            print("AzureAttachedAuthorization")
        cloud_specific_policy = {}
        can_cloud_run = False
        print("Policy dict:", policy_dict_cloud_level)
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
        print("Cloud-specific attached authorization policy:", cloud_specific_policy)
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
        resource_group: Union[str, None]
        regions: Union[List[str], None]
        virtual_machines: bool
        virtualMachineInstanceView: bool
        network_interfaces: bool
        ip_addresses: bool
        operations: bool
        virtual_networks: bool
        subnets: bool
        network_security_groups: bool
        deployments: bool

    def __init__(self, policy: _PolicyDict, policy_override: Union[bool, None]=None):
        """
        Create a new AzureReadPolicy instance.

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

        assert len(aux_info) > 0 and aux_info[0] in AzureReadPolicy.READ_TYPE_URL_PATTERNS
        read_type = aux_info[0]

        request_info = self._get_request_info(request, read_type)

        if read_type == "virtualMachinesGeneral":
            return self._policy["virtual_machines"]
        elif read_type == "operations":
            return self._policy["operations"] and request_info["region"] in self._policy["regions"]
        else:
            # The rest of the read types should include a resource group
            # TODO: Optionally specify resource group constraint on the GET requests
            return self._policy[read_type]

        # TODO: allow request if unrecognized?
        return True

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
            "virtual_machines": True,
            "virtualMachineInstanceView": True,
            "network_interfaces": True,
            "ip_addresses": True,
            "operations": True,
            "virtual_networks": True,
            "subnets": True,
            "network_security_groups": True,
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
                k: v for k, v in self._policy.items() if v is not None
            }
        }
    
class AzureDeploymentPolicy(ResourcePolicy):
    """
    Defines methods for Azure Deployment policies.
    """

    class MockAzureRequest:
        """
        Internal class used to mock Azure requests on resource creation.
        """
        def __init__(self, json_contents: Dict):
            self.json_contents = json_contents

        def get_json(self, cache=False):
            return self.json_contents

    def __init__(self, azure_vm_policy: AzureVMPolicy, attached_authorization_policy: AzureAttachedAuthorizationPolicy):
        """
        :param policy: The dict of the policy to enforce.
        """
        self._azure_vm_policy = azure_vm_policy
        self._attached_authorization_policy = attached_authorization_policy

        self._param_extractor = re.compile(r"^\[parameters\('(?P<param_name>[^']+)'\)\]$")
    
    def check_request(self, request: Request) -> bool:
        """
        Enforces the policy on a request.
        :param request: The request to enforce the policy on.
        :return: True if the request is allowed, False otherwise.
        """
        request_contents = request.get_json(cache=True)
        if "properties" in request_contents:
            # Load up all of the parameters
            parameters = {}
            if "parameters" in request_contents["properties"]:
                for parameter in request_contents["properties"]["parameters"]:
                    parameters[parameter] = request_contents["properties"]["parameters"][parameter]["value"]

            if "template" in request_contents["properties"]:
                template = request_contents["properties"]["template"]
                if "resources" in template:
                    for resource in template["resources"]:
                        if "type" in resource and resource["type"] == "Microsoft.Compute/virtualMachines":
                            # Check the VM policy
                            vm_request = self.convert_vm_source_to_vm_request(resource, parameters)
                            if not self._azure_vm_policy.check_request(vm_request):
                                return False
        return True
    
    def convert_vm_source_to_vm_request(self, vm_source_dict, parameters_dict) -> 'AzureDeploymentPolicy.MockAzureRequest':
        """
        Converts a the VM template resource into a mock request that can be checked by the vm policy.
        :param vm_source_dict: The VM template resource.
        :param parameters_dict: The parameters for the template.
        """
        request_body = {
            "properties": {
            }
        }
        if "properties" in vm_source_dict:
            if "hardwareProfile" in vm_source_dict["properties"]:
                parameter_substituted_hardware_profile = {}
                for key in vm_source_dict["properties"]["hardwareProfile"]:
                    if key in parameters_dict:
                        match = self._param_extractor.match(parameters_dict[key])
                        if match:
                            parameter_substituted_hardware_profile[key] = parameters_dict[match.group("param_name")]
                        else:
                            parameter_substituted_hardware_profile[key] = vm_source_dict["properties"]["hardwareProfile"][key]
                request_body["properties"]["hardwareProfile"] = parameter_substituted_hardware_profile

            if "storageProfile" in vm_source_dict["properties"]:
                parameter_substituted_storage_profile = {}
                for key in vm_source_dict["properties"]["storageProfile"]:
                    if key in parameters_dict:
                        match = self._param_extractor.match(parameters_dict[key])
                        if match:
                            parameter_substituted_storage_profile[key] = parameters_dict[match.group("param_name")]
                        else:
                            parameter_substituted_storage_profile[key] = vm_source_dict["properties"]["storageProfile"][key]
                request_body["properties"]["storageProfile"] = parameter_substituted_storage_profile

            if "osProfile" in vm_source_dict["properties"]:
                parameter_substituted_os_profile = {}
                for key in vm_source_dict["properties"]["osProfile"]:
                    if key in parameters_dict:
                        match = self._param_extractor.match(parameters_dict[key])
                        if match:
                            parameter_substituted_os_profile[key] = parameters_dict[match.group("param_name")]
                        else:
                            parameter_substituted_os_profile[key] = vm_source_dict["properties"]["osProfile"][key]
                request_body["properties"]["osProfile"] = parameter_substituted_os_profile

            if "networkProfile" in vm_source_dict["properties"]:
                parameter_substituted_network_profile = {}
                for key in vm_source_dict["properties"]["networkProfile"]:
                    if key in parameters_dict:
                        match = self._param_extractor.match(parameters_dict[key])
                        if match:
                            parameter_substituted_network_profile[key] = parameters_dict[match.group("param_name")]
                        else:
                            parameter_substituted_network_profile[key] = vm_source_dict["properties"]["networkProfile"][key]
                request_body["properties"]["networkProfile"] = parameter_substituted_network_profile

        return AzureDeploymentPolicy.MockAzureRequest(request_body)

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
        self._resource_policies = {
            "virtual_machine": vm_policy,
            "attached_authorizations": attached_authorization_policy,
            "read": read_policy,
            "unrecognized": UnrecognizedResourcePolicy(),
            "deployments": AzureDeploymentPolicy(vm_policy, attached_authorization_policy)
        }
        self.valid_authorization: Union[str, None] = None
        print("AzureAuthorizationPolicy init:", self._resource_policies["attached_authorizations"]._policy)

    def get_request_resource_types(self, request: Request) -> List[str]:
        """
        Gets the resource types that the request is trying to access / create / delete.
        :param request: The request to get the resource types from.
        :return: The resource types that the request is trying to access as a list of names.
        """
        resource_types = set([])
        # TODO(later): Refactoring the logic to reuse better
        if request.method == 'GET':
            print("NOT JSON")
            has_match = False
            for read_type, read_path_regex in AzureReadPolicy.READ_TYPE_URL_PATTERNS.items():
                match = read_path_regex.search(request.path)
                if match:
                    has_match = True
                    resource_types.add(("read", read_type))
            
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

            for key in request.get_json(cache=True).keys():
                if key in AzurePolicy.ATTACHED_AUTHORIZATION_KEYS:
                    resource_types.add(("attached_authorizations",))
        if len(resource_types) == 0:
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
        if resource_type_key == "attached_authorizations":
            # Authorization policies
            result = self._resource_policies[resource_type_key].check_request(request, self._authorization_manager)
            self.valid_authorization = result[0]
            return result[1]
        elif resource_type_key == "read":
            # Read policies
            return self._resource_policies[resource_type_key].check_read_request(request, *resource_type_aux)
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
            if resource_type == "unrecognized" or resource_type == "deployments":
                continue
            out_dict[resource_type] = policy.to_dict()
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
        vm_policy = AzureVMPolicy.from_dict(vm_dict)
        attached_policy_dict = {}
        if "attached_authorizations" in policy_dict:
            attached_policy_dict = policy_dict["attached_authorizations"]
        if "attached_authorizations" in vm_dict:
            attached_policy_dict = vm_dict["attached_authorizations"]
        attached_authorization_policy = AzureAttachedAuthorizationPolicy.from_dict(attached_policy_dict)

        if PolicyAction.READ.is_allowed_be_performed(vm_policy.get_policy_standard_form()["actions"]):
            if "reads" in policy_dict:
                read_dict = policy_dict["reads"]
                print("READS_DICT in AzurePolicy:from_dict", read_dict)
                read_policy = AzureReadPolicy.from_dict(read_dict)
            else:
                # if reads are allowed, and there is no granular specification, then allow all
                read_policy = AzureReadPolicy.get_default_allow_policy()
        else:
            # if cannot read, then deny all reads
            read_policy = AzureReadPolicy.get_default_deny_policy()

        return AzurePolicy(vm_policy, attached_authorization_policy, read_policy)