from typing import List

from google.cloud import compute_v1
from google.oauth2 import service_account
from google.api_core.client_options import ClientOptions

import argparse
import time 

DUMMY_CREDS = 'tokens/dummy-service-acct-token.json'

parser = argparse.ArgumentParser(
                    prog='CreateVM',
                    description='Tests VM creation requests to Skydentity')

parser.add_argument('--project', type=str, default='sky-identity', help='Project ID of the GCP project you want to use')
parser.add_argument('--zone', type=str, default='us-west1-b', help='Name of the zone to create the instance in')
parser.add_argument('--api-endpoint', type=str, default=None, help='API endpoint to send requests to; defaults to compute.googleapis.com')
parser.add_argument("--credentials", type=str, default=None, help="Path to the service account key file")
parser.add_argument("--vm-id", type=str, default="", help="ID of the VM to create")

def get_dummy_credentials() -> service_account.Credentials:
    return service_account.Credentials.from_service_account_file(
        DUMMY_CREDS)

def get_image_from_family(project: str, family: str, api_endpoint=None) -> compute_v1.Image:
    """
    Retrieve the newest image that is part of a given family in a project.

    Args:
        project: project ID or project number of the Cloud project you want to get image from.
        family: name of the image family you want to get image from.

    Returns:
        An Image object.
    """
    if api_endpoint != None:
        options = ClientOptions(api_endpoint=api_endpoint)
        image_client = compute_v1.ImagesClient(credentials=get_dummy_credentials(),
            client_options=options)
    else:
        image_client = compute_v1.ImagesClient(credentials=get_dummy_credentials())
    newest_image = image_client.get_from_family(project=project, family=family)
    return newest_image

def local_ssd_disk(zone: str) -> compute_v1.AttachedDisk():
    """
    Create an AttachedDisk object to be used in VM instance creation. The created disk contains
    no data and requires formatting before it can be used.

    Args:
        zone: The zone in which the local SSD drive will be attached.

    Returns:
        AttachedDisk object configured as a local SSD disk.
    """
    disk = compute_v1.AttachedDisk()

    disk.type_ = compute_v1.AttachedDisk.Type.SCRATCH.name
    initialize_params = compute_v1.AttachedDiskInitializeParams()
    initialize_params.disk_type = f"zones/{zone}/diskTypes/local-ssd"
    disk.initialize_params = initialize_params
    disk.auto_delete = True
    return disk

def disk_from_image(
    disk_type: str,
    disk_size_gb: int,
    boot: bool,
    source_image: str,
    auto_delete: bool = True,
) -> compute_v1.AttachedDisk:
    """
    Create an AttachedDisk object to be used in VM instance creation. Uses an image as the
    source for the new disk.

    Args:
         disk_type: the type of disk you want to create. This value uses the following format:
            "zones/{zone}/diskTypes/(pd-standard|pd-ssd|pd-balanced|pd-extreme)".
            For example: "zones/us-west3-b/diskTypes/pd-ssd"
        disk_size_gb: size of the new disk in gigabytes
        boot: boolean flag indicating whether this disk should be used as a boot disk of an instance
        source_image: source image to use when creating this disk. You must have read access to this disk. This can be one
            of the publicly available images or an image from one of your projects.
            This value uses the following format: "projects/{project_name}/global/images/{image_name}"
        auto_delete: boolean flag indicating whether this disk should be deleted with the VM that uses it

    Returns:
        AttachedDisk object configured to be created using the specified image.
    """

    boot_disk = compute_v1.AttachedDisk()
    initialize_params = compute_v1.AttachedDiskInitializeParams()
    initialize_params.source_image = source_image
    initialize_params.disk_size_gb = disk_size_gb
    initialize_params.disk_type = disk_type
    boot_disk.initialize_params = initialize_params
    # Remember to set auto_delete to True if you want the disk to be deleted when you delete
    # your VM instance.
    boot_disk.auto_delete = auto_delete
    boot_disk.boot = boot
    return boot_disk

def create_instance(
    project_id: str,
    zone: str,
    instance_name: str,
    disks: List[compute_v1.AttachedDisk],
    machine_type: str = "e2-micro",
    network_link: str = "global/networks/default",
    api_endpoint=None,
) -> compute_v1.Instance:
    """
    Send an instance creation request to the Compute Engine API and wait for it to complete.

    Args:
        project_id: project ID or project number of the Cloud project you want to use.
        zone: name of the zone to create the instance in. For example: "us-west3-b"
        instance_name: name of the new virtual machine (VM) instance.
        machine_type: machine type of the VM being created. This value uses the
            following format: "zones/{zone}/machineTypes/{type_name}".
            For example: "zones/europe-west3-c/machineTypes/f1-micro"
        network_link: name of the network you want the new instance to use.
            For example: "global/networks/default" represents the network
            named "default", which is created automatically for each project.
    Returns:
        Instance object.
    """
    if api_endpoint != None:
        options = ClientOptions(api_endpoint=api_endpoint)
        instance_client = compute_v1.InstancesClient(credentials=get_dummy_credentials(),
            client_options=options)
    else:
        instance_client = compute_v1.InstancesClient(credentials=get_dummy_credentials())

    # Use the network interface provided in the network_link argument.
    network_interface = compute_v1.NetworkInterface()
    network_interface.network = network_link  

    # Collect information into the Instance object.
    instance = compute_v1.Instance() 
    instance.network_interfaces = [network_interface]
    instance.name = instance_name
    instance.machine_type = f"zones/{zone}/machineTypes/{machine_type}"
    instance.disks = disks
    if api_endpoint != None:
        instance.service_accounts = [compute_v1.ServiceAccount(email="dummy_account")]

    # Cloud init script    
    instance.metadata = compute_v1.Metadata()
    instance.metadata.items = [
        compute_v1.Items(
            key="startup-script",
            value="#! /bin/bash\nsudo echo \"success\" > startup_script.out\n",
        )
    ] 

    # Prepare the request to insert an instance.
    request = compute_v1.InsertInstanceRequest()
    request.zone = zone
    request.project = project_id
    request.instance_resource = instance

    # Wait for the create operation to complete.
    #print(f"Sending creation request for the {instance_name} instance in {zone} to Sky Identity...")

    operation = instance_client.insert(request=request)

    return operation

def delete_instance(project_id: str, zone: str, machine_name: str) -> None:
    """
    Send an instance deletion request to the Compute Engine API and wait for it to complete.

    Args:
        project_id: project ID or project number of the Cloud project you want to use.
        zone: name of the zone you want to use. For example: “us-west3-b”
        machine_name: name of the machine you want to delete.
    """
    instance_client = compute_v1.InstancesClient()

    print(f"Deleting {machine_name} from {zone}...")
    instance_client.delete(
        project=project_id, zone=zone, instance=machine_name
    )

def get_image(api_endpoint=None):
    disks = []
    start = time.time()
    newest_debian = get_image_from_family(project="debian-cloud", family="debian-10", api_endpoint=api_endpoint)
    print(f"Time to get image: ", time.time() - start)
    disk_type = f"zones/{args.zone}/diskTypes/pd-balanced"
    disks.append(disk_from_image(disk_type, 10, True, newest_debian.self_link, True))
    return disks

def main():
    disks = get_image(api_endpoint=args.api_endpoint)
    start = time.perf_counter()
    create_instance(args.project, args.zone, f"gcp-clilib-{args.vm_id}", disks, api_endpoint=args.api_endpoint)
    print(f"Time for instance creation req: ", time.perf_counter() - start)

if __name__ == "__main__":
    args = parser.parse_args()

    if args.credentials:
        DUMMY_CREDS = args.credentials
    main()