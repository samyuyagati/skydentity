from azure.identity import AzureCliCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.compute.models import OSProfile, NetworkProfile, ImageReference, ManagedDiskParameters, OSDisk, StorageProfile, HardwareProfile, VirtualMachine, OperatingSystemTypes, DiskCreateOptionTypes

# TODO: Handle secret management + remove uses of 'AzureCliCredential()'
SUBSCRIPTION_ID =
USERNAME =
PASSWORD =
NUM_VMS_TO_CREATE = 1

"""
    Creates a new resource group in the given location (region), or default eastus2.
    This includes creating the virtual network and subnet that are shared between VMs.
    Returns the subnet id necessary to create individual VMs.
"""
def create_resource_group(resource_group_name, subscription_id, location="eastus2"):
    # Get credentials from CLI
    credential = AzureCliCredential()

    # Create resource group
    resource_client = ResourceManagementClient(credential, subscription_id)
    resource_group = resource_client.resource_groups.create_or_update(
        resource_group_name, {"location": location}
    )

    # Create virtual network
    network_client = NetworkManagementClient(credential, subscription_id)

    vnet_name = resource_group_name + "-vnet"
    vnet = network_client.virtual_networks.begin_create_or_update(
        resource_group_name,
        vnet_name,
        {
            "location": location,
            "address_space": {"address_prefixes": ["10.0.0.0/16"]},
        },
    ).result()

    # Create subnet
    subnet_name = resource_group_name + "-subnet"
    subnet = network_client.subnets.begin_create_or_update(
        resource_group_name,
        vnet_name,
        subnet_name,
        {"address_prefix": "10.0.0.0/24"},
    ).result()

    return subnet.id

"""
    Create the public ip address and network interface for an individual VM in a given subnet.
    Returns the network interface id necessary to create a VM instance.
"""
def create_public_ip_and_nic(resource_group_name, subscription_id, subnet_id, location="eastus2"):
    # Get credentials from CLI
    credential = AzureCliCredential()

    # Create public ip address
    network_client = NetworkManagementClient(credential, subscription_id)

    ip_name = resource_group_name + "-ip"
    ip_address = network_client.public_ip_addresses.begin_create_or_update(
        resource_group_name,
        ip_name,
        {
            "location": location,
            "sku": {"name": "Standard"},
            "public_ip_allocation_method": "Static",
            "public_ip_address_version": "IPV4",
        },
    ).result()

    # Create nic
    nic_name = resource_group_name + "-nic"
    ip_config_name = ip_name + "-config"
    nic = network_client.network_interfaces.begin_create_or_update(
        resource_group_name,
        nic_name,
        {
            "location": location,
            "ip_configurations": [
                {
                    "name": ip_config_name,
                    "subnet": {"id": subnet_id},
                    "public_ip_address": {"id": ip_address.id},
                }
            ],
        },
    ).result()

    return nic.id

# TODO: Add type annotations
# TODO: WIP, issue with image reference for disk
# Useful reference: https://learn.microsoft.com/en-us/azure/developer/python/sdk/examples/azure-sdk-samples-managed-disks
def disk_from_image_reference(vm_name, disk_size_gb, image_reference, location="eastus2"):
    credential = AzureCliCredential()
    compute_client = ComputeManagementClient(credential, subscription_id)
    os_disk_name = vm_name + '-osdisk'

    disk = {
        'location': location,
        'disk_size_gb': disk_size_gb,
        'creation_data': {
            'create_option': DiskCreateOptionTypes.from_image,
            "image_reference": image_reference,
        }
    }

    async_disk_creation = compute_client.disks.begin_create_or_update(
        resource_group,
        os_disk_name,
        disk
    )

    return async_disk_creation.result()

# Instead of creating a separate managed disk, could use existing image as in GCP test_server.py
def storage_profile_from_image(group_name, image_name):
    image = compute_client.images.get(group_name, image_name)

    storage_profile = azure.mgmt.compute.models.StorageProfile(
        image_reference = azure.mgmt.compute.models.ImageReference(
            id = image.id
        )
    )
    
    return storage_profile

"""
Creates a new VM with the provided network interface id.

    vm_size : Can be configured with a string or left as default. 
              Options can be found with azure CLI: 
                az vm list-sizes --location your-location --output table, where your-location is 'eastus2' for example
    disk : Set to a azure.mgmt.compute.models.Disk type, can be used instead of the default. 
           If no disk is set, the create_vm request automatically creates a managed disk with the default image_reference:
                publisher='Canonical'
                offer='UbuntuServer'
                sku='16.04-LTS'
                version='latest'
"""
def create_instance(resource_group_name, subscription_id, nic_id, vm_name, vm_size="Standard_B1s", location="eastus2", disk=None):
    credential = AzureCliCredential()
    compute_client = ComputeManagementClient(credential, subscription_id)

    vm = VirtualMachine(
        location=location,
        os_profile=OSProfile(
            computer_name=vm_name,
            admin_username=USERNAME,
            admin_password=PASSWORD,
        ),
        hardware_profile=HardwareProfile(vm_size=vm_size),
        network_profile=NetworkProfile(
            network_interfaces=[{
                'id': nic_id
            }]
        )
    )

    if disk:
        vm.storage_profile = StorageProfile(
            os_disk=OSDisk(
                os_type=OperatingSystemTypes.linux,
                name=vm_name + '-os-disk',
                create_option=DiskCreateOptionTypes.attach,
                managed_disk=ManagedDiskParameters(id=disk.id)
            )
        )
    else:
        vm.storage_profile = StorageProfile(
            image_reference = ImageReference(
                publisher='Canonical',
                offer='UbuntuServer',
                sku='16.04-LTS',
                version='latest'
            )
        )

    # Could create without returning (if so, may want to use .wait() to ensure that the "success" message isn't printed while the vm creation request is still being processed)
    return compute_client.virtual_machines.begin_create_or_update(resource_group_name, vm_name, vm).result()

def main():
    # Create resource group (including vnet and subnet) once
    resource_group_name = "skydentity"
    subnet_id = create_resource_group(resource_group_name, SUBSCRIPTION_ID)

    # Create VMs
    for i in range(NUM_VMS_TO_CREATE):
        nic_id = create_public_ip_and_nic(resource_group_name, SUBSCRIPTION_ID, subnet_id)
        # Name VM 'skydentity-VM#' where # is the 1-indexed VM number
        vm = create_instance(resource_group_name, SUBSCRIPTION_ID, nic_id, "{0}-VM{1}".format(resource_group_name, (i + 1)))
        print("Created {0} successfully".format(vm.name))

if __name__ == "__main__":
    main()