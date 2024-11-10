terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "4.51.0"
    }
  }
}

provider "google" {
  project = "sky-identity"
}

# resource "google_compute_network" "vpc_network" {
#   name = "terraform-network"
# }

resource "google_compute_instance" "vm_instance" {
  name         = "terraform-instance"
  machine_type = "n1-standard-1"
  zone         = "us-west1-b"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-10-buster-v20240213"
      size  = 128
      type = "pd-balanced"
    }
  }

  network_interface {
    network = "default"
    access_config {
    }
  }

  metadata_startup_script = file("./startup.sh")
}

