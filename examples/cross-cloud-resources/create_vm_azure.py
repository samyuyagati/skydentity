import base64
import os
from typing import cast

from azure.core.exceptions import ResourceNotFoundError
from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.compute.models import (
    HardwareProfile,
    ImageReference,
    NetworkInterfaceReference,
    NetworkProfile,
    OSProfile,
    StorageProfile,
    VirtualMachine,
    VirtualMachineSizeTypes,
)
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.network.models import (
    AddressSpace,
    IPAllocationMethod,
    IPVersion,
    NetworkInterface,
    NetworkInterfaceIPConfiguration,
    PublicIPAddress,
    PublicIPAddressSku,
    PublicIPAddressSkuName,
    Subnet,
    VirtualNetwork,
)
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.resource.resources import ResourceManagementClient
from azure.mgmt.resource.resources.models import ResourceGroup

# from azure.mgmt.resource.resources.models import ResourceGroup

CREDENTIAL = DefaultAzureCredential(exclude_managed_identity_credential=True)
subscription_client = SubscriptionClient(CREDENTIAL)
SUBSCRIPTION_ID = cast(
    str, list(subscription_client.subscriptions.list())[0].subscription_id
)

RESOURCE_GROUP_NAME = "skydentity"
VNET_NAME = f"{RESOURCE_GROUP_NAME}-vnet"
SUBNET_NAME = f"{RESOURCE_GROUP_NAME}-subnet"
IP_NAME = f"{RESOURCE_GROUP_NAME}-ip"
IP_CONFIG_NAME = f"{RESOURCE_GROUP_NAME}-config"
NIC_NAME = f"{RESOURCE_GROUP_NAME}-nic"

LOCATION = "westus2"

USERNAME = "skydentity"
PASSWORD = "$kyD3ntity1sAwesome"

CLOUD_INIT_FILENAME = "sample_cloudinit.yaml"

BASE_URL = "https://127.0.0.1:6000/"
# BASE_URL = "https://management.azure.com"


def create_resource_group():
    """
    Creates an empty resource group for the VM
    """
    resource_client = ResourceManagementClient(
        CREDENTIAL, SUBSCRIPTION_ID, base_url=BASE_URL
    )
    resource_group = resource_client.resource_groups.create_or_update(
        RESOURCE_GROUP_NAME,
        parameters=ResourceGroup(location=LOCATION),
    )

    return resource_group


def create_network() -> str:
    """
    Creates a vnet, subnet, public IP, and NIC for the VM;
    does not replace any existing entities.
    """
    network_client = NetworkManagementClient(
        CREDENTIAL, SUBSCRIPTION_ID, base_url=BASE_URL
    )

    print("Ensuring vnet exists...")
    try:
        vnet = network_client.virtual_networks.get(RESOURCE_GROUP_NAME, VNET_NAME)
        print(f"Existing vnet {vnet.name}")
    except ResourceNotFoundError:
        vnet = network_client.virtual_networks.begin_create_or_update(
            RESOURCE_GROUP_NAME,
            VNET_NAME,
            VirtualNetwork(
                location=LOCATION,
                address_space=AddressSpace(address_prefixes=["10.143.0.0/16"]),
            ),
        ).result()
        print(f"Provisioned vnet {vnet.name}")

    print("Ensuring subnet exists...")
    try:
        subnet = network_client.subnets.get(RESOURCE_GROUP_NAME, VNET_NAME, SUBNET_NAME)
        print(f"Existing subnet {subnet.name}")
    except ResourceNotFoundError:
        subnet = network_client.subnets.begin_create_or_update(
            RESOURCE_GROUP_NAME,
            VNET_NAME,
            SUBNET_NAME,
            Subnet(address_prefix="10.143.0.0/16"),
        ).result()
        print(f"Provisioned subet {subnet.name}")

    print("Ensuring public IP exists...")
    try:
        ip_addr = network_client.public_ip_addresses.get(RESOURCE_GROUP_NAME, IP_NAME)
        print(f"Existing IP addr {ip_addr.name} with address {ip_addr.ip_address}")
    except ResourceNotFoundError:
        ip_addr = network_client.public_ip_addresses.begin_create_or_update(
            RESOURCE_GROUP_NAME,
            IP_NAME,
            PublicIPAddress(
                location=LOCATION,
                sku=PublicIPAddressSku(name=PublicIPAddressSkuName.STANDARD),
                public_ip_allocation_method=IPAllocationMethod.STATIC,
                public_ip_address_version=IPVersion.I_PV4,
            ),
        ).result()
        print(f"Provisioned IP addr {ip_addr.name} with address {ip_addr.ip_address}")

    print("Ensuring nic exists...")
    try:
        nic = network_client.network_interfaces.get(RESOURCE_GROUP_NAME, NIC_NAME)
        print(f"Existing nic {nic.name}")
    except ResourceNotFoundError:
        nic = network_client.network_interfaces.begin_create_or_update(
            RESOURCE_GROUP_NAME,
            NIC_NAME,
            NetworkInterface(
                location=LOCATION,
                ip_configurations=[
                    NetworkInterfaceIPConfiguration(
                        name=IP_CONFIG_NAME,
                        subnet=subnet,
                        public_ip_address=ip_addr,
                    )
                ],
            ),
        ).result()
        print(f"Provisioned nic {nic.name}")

    assert nic.id is not None
    return nic.id


def generate_cloudinit():
    pass


def create_instance(
    vm_name: str,
    nic_id: str,
    vm_size=VirtualMachineSizeTypes.STANDARD_B1_S,
    crosscloud_role="bucket-reader",
):
    compute_client = ComputeManagementClient(
        CREDENTIAL, SUBSCRIPTION_ID, base_url=BASE_URL
    )

    # cloud init file is relative to the script name
    this_script_file_path = __file__
    this_script_dir_path = os.path.dirname(this_script_file_path)
    cloud_init_file_path = os.path.join(this_script_dir_path, CLOUD_INIT_FILENAME)

    with open(cloud_init_file_path, "r", encoding="utf-8") as cloud_init_file:
        cloud_init_data = cloud_init_file.read()

    vm = VirtualMachine(
        location=LOCATION,
        os_profile=OSProfile(
            computer_name=vm_name,
            admin_username=USERNAME,
            admin_password=PASSWORD,
        ),
        hardware_profile=HardwareProfile(vm_size=vm_size),
        network_profile=NetworkProfile(
            network_interfaces=[NetworkInterfaceReference(id=nic_id)]
        ),
        storage_profile=StorageProfile(
            image_reference=ImageReference(
                publisher="Canonical",
                offer="ubuntu-24_04-lts",
                sku="server",
                version="latest",
            )
        ),
        tags={"skydentity-crosscloud-role": crosscloud_role},
        # user data must be base64 encoded
        user_data=base64.b64encode(cloud_init_data.encode("utf-8")).decode("utf-8"),
    )

    print(f"Creating VM {vm_name}...")

    result = compute_client.virtual_machines.begin_create_or_update(
        resource_group_name=RESOURCE_GROUP_NAME,
        vm_name=vm_name,
        parameters=vm,
    ).result()

    print(f"Successfully created VM {vm_name}")

    return result


def main(vm_name, crosscloud_role):
    create_resource_group()
    print(f"Successfully created resource group {RESOURCE_GROUP_NAME}")

    nic_id = create_network()

    create_instance(vm_name, nic_id, crosscloud_role=crosscloud_role)
    print(f"Sucessfully created VM {vm_name}, with tag {crosscloud_role}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--role",
        type=str,
        default="bucket-reader",
        help="Role to attach to the VM for cross-cloud resource access",
    )
    parser.add_argument("--name", type=str, default="VM-test", help="VM name")

    args = parser.parse_args()
    main(args.name, args.role)
