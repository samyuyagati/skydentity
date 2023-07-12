from typing import Any, List

from google.api_core.extended_operation import ExtendedOperation
from google.cloud import compute_v1
from google.oauth2 import service_account
from google.api_core.client_options import ClientOptions

import json
import os
import re

skydentity_creds = '/Users/samyu/.cloud_creds/skydentity-token.json'
api_endpoint="https://34.168.128.47:5000"
#api_endpoint=api_endpoint
def get_skydentity_credentials() -> service_account.Credentials:
    return service_account.Credentials.from_service_account_file(
        skydentity_creds)

def get_image_from_family(project: str, family: str) -> compute_v1.Image:
    """
    Retrieve the newest image that is part of a given family in a project.

    Args:
        project: project ID or project number of the Cloud project you want to get image from.
        family: name of the image family you want to get image from.

    Returns:
        An Image object.
    """
    # GET https://127.0.0.1:5000/compute/v1/skydentity/us-west-1/describe/images/family/debian
    # --> send request to https://127.0.0.1:5000 to launch serverless function
    # ------> with /compute/v1/skydentity/us-west-1/describe/images/family/debian included in the HTTPS request
    options = ClientOptions(api_endpoint=api_endpoint)
    image_client = compute_v1.ImagesClient(credentials=get_skydentity_credentials(),
        client_options=options)
    # List of public operating system (OS) images: https://cloud.google.com/compute/docs/images/os-details
    newest_image = image_client.get_from_family(project=project, family=family)
    # -----> in backend: get_from_family uses REST API to send GET ....
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

#    disk = compute_v1.AttachedDisk(api_endpoint=api_endpoint)
    disk.type_ = compute_v1.AttachedDisk.Type.SCRATCH.name
    initialize_params = compute_v1.AttachedDiskInitializeParams()

#    initialize_params = compute_v1.AttachedDiskInitializeParams(api_endpoint=api_endpoint)
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
#    options = ClientOptions(api_endpoint=api_endpoint)
#    disk_client = compute_v1.DisksClient(credentials=get_skydentity_credentials(),
#        client_options=options)

    boot_disk = compute_v1.AttachedDisk()
    initialize_params = compute_v1.AttachedDiskInitializeParams()

 #   boot_disk = compute_v1.AttachedDisk(api_endpoint=api_endpoint)
 #   initialize_params = compute_v1.AttachedDiskInitializeParams(api_endpoint=api_endpoint)
    initialize_params.source_image = source_image
    initialize_params.disk_size_gb = disk_size_gb
    initialize_params.disk_type = disk_type
    boot_disk.initialize_params = initialize_params
    # Remember to set auto_delete to True if you want the disk to be deleted when you delete
    # your VM instance.
    boot_disk.auto_delete = auto_delete
    boot_disk.boot = boot
    return boot_disk

def wait_for_extended_operation(
    operation: ExtendedOperation, verbose_name: str = "operation", timeout: int = 300
) -> Any:
    """
    Waits for the extended (long-running) operation to complete.

    If the operation is successful, it will return its result.
    If the operation ends with an error, an exception will be raised.
    If there were any warnings during the execution of the operation
    they will be printed to sys.stderr.

    Args:
        operation: a long-running operation you want to wait on.
        verbose_name: (optional) a more verbose name of the operation,
            used only during error and warning reporting.
        timeout: how long (in seconds) to wait for operation to finish.
            If None, wait indefinitely.

    Returns:
        Whatever the operation.result() returns.

    Raises:
        This method will raise the exception received from `operation.exception()`
        or RuntimeError if there is no exception set, but there is an `error_code`
        set for the `operation`.

        In case of an operation taking longer than `timeout` seconds to complete,
        a `concurrent.futures.TimeoutError` will be raised.
    """
    result = operation.result(timeout=timeout)

    if operation.error_code:
        print(
            f"Error during {verbose_name}: [Code: {operation.error_code}]: {operation.error_message}",
            file=sys.stderr,
            flush=True,
        )
        print(f"Operation ID: {operation.name}", file=sys.stderr, flush=True)
        raise operation.exception() or RuntimeError(operation.error_message)

    if operation.warnings:
        print(f"Warnings during {verbose_name}:\n", file=sys.stderr, flush=True)
        for warning in operation.warnings:
            print(f" - {warning.code}: {warning.message}", file=sys.stderr, flush=True)

    return result

def create_instance(
    project_id: str,
    zone: str,
    instance_name: str,
    disks: List[compute_v1.AttachedDisk],
    machine_type: str = "n1-standard-1",
    network_link: str = "global/networks/default",
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
    options = ClientOptions(api_endpoint=api_endpoint)
    instance_client = compute_v1.InstancesClient(credentials=get_skydentity_credentials(),
        client_options=options)

    # Use the network interface provided in the network_link argument.
    network_interface = compute_v1.NetworkInterface()
    network_interface.network = network_link  

    # Collect information into the Instance object.
    instance = compute_v1.Instance() # TODO is this a request we need to proxy?
    instance.network_interfaces = [network_interface]
    instance.name = instance_name
#    if re.match(r"^zones/[a-z\d\-]+/machineTypes/[a-z\d\-]+$", machine_type):
#        instance.machine_type = machine_type
#    else:
    instance.machine_type = f"zones/{zone}/machineTypes/{machine_type}"
    instance.disks = disks
    # Prepare the request to insert an instance.
    request = compute_v1.InsertInstanceRequest()
    request.zone = zone
    request.project = project_id
    request.instance_resource = instance

    # Wait for the create operation to complete.
    print(f"Sending creation request for the {instance_name} instance in {zone} to Sky Identity...")

    operation = instance_client.insert(request=request)

    # THIS PART NEEDS TO BE DONE W/ ACTUAL CREDENTIALS
#    wait_for_extended_operation(operation, "instance creation")

#    print(f"Instance {instance_name} created.")
#    return instance_client.get(project=project_id, zone=zone, instance=instance_name)

def main():
    # Create test token
#    dictionary = {"name": "gcp", "token": "test_token"}
#    json_object = json.dumps(dictionary, indent=4)
#    with open(skydentity_creds, "w") as outfile:
#        outfile.write(json_object)

    # Send VM creation request
    os.environ["SSL_CERT_FILE"] = "/Users/samyu/skydentity/certs/rootCA.crt"
    os.environ["SSL_CERT_DIR"] = "/Users/samyu/skydentity/certs"
    zone = "us-west1-b"
    newest_debian = get_image_from_family(project="debian-cloud", family="debian-10")
    disk_type = f"zones/{zone}/diskTypes/pd-standard"
    disks = [
        disk_from_image(disk_type, 10, True, newest_debian.self_link, True),
        local_ssd_disk(zone),
    ]
    create_instance("sky-identity", zone, "gcp-clilib", disks)

def create_firewall_rule(
    project_id: str, firewall_rule_name: str, network: str = "global/networks/default"
) -> compute_v1.Firewall:
    """
    Creates a simple firewall rule allowing for incoming HTTP and HTTPS access from the entire Internet.

    Args:
        project_id: project ID or project number of the Cloud project you want to use.
        firewall_rule_name: name of the rule that is created.
        network: name of the network the rule will be applied to. Available name formats:
            * https://www.googleapis.com/compute/v1/projects/{project_id}/global/networks/{network}
            * projects/{project_id}/global/networks/{network}
            * global/networks/{network}

    Returns:
        A Firewall object.
    """
    firewall_rule = compute_v1.Firewall()
    firewall_rule.name = firewall_rule_name
    firewall_rule.direction = "INGRESS"

    allowed_ports = compute_v1.Allowed()
    allowed_ports.I_p_protocol = "tcp"
    allowed_ports.ports = ["80", "443"]

    firewall_rule.allowed = [allowed_ports]
    firewall_rule.source_ranges = ["0.0.0.0/0"]
    firewall_rule.network = network
    firewall_rule.description = "Allowing TCP traffic on port 80 and 443 from Internet."

    firewall_rule.target_tags = ["web"]

    # Note that the default value of priority for the firewall API is 1000.
    # If you check the value of `firewall_rule.priority` at this point it
    # will be equal to 0, however it is not treated as "set" by the library and thus
    # the default will be applied to the new rule. If you want to create a rule that
    # has priority == 0, you need to explicitly set it so:
    # TODO: Uncomment to set the priority to 0
    # firewall_rule.priority = 0

    options = ClientOptions(api_endpoint=api_endpoint)
    firewall_client = compute_v1.FirewallsClient(credentials=get_skydentity_credentials(),
        client_options=options)

    operation = firewall_client.insert(
        project=project_id, firewall_resource=firewall_rule
    )

    return firewall_client.get(project=project_id, firewall=firewall_rule_name)


if __name__ == "__main__":
    main()
