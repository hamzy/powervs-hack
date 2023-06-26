terraform {
  required_providers {
    ibm = {
      source  = "ibm-cloud/ibm"
      version = "1.39.0"
    }
  }
  required_version = ">= 1.0.0"
}

provider "ibm" {
  ibmcloud_api_key = var.ibmcloud_api_key
  region           = var.ibmcloud_region
  zone             = var.ibmcloud_zone
}

variable "ibmcloud_api_key" {
  type = string
}

variable "ibmcloud_region" {
  type = string
}

variable "ibmcloud_zone" {
  type = string
}

variable "pub_key" {
  type = string
}

variable "vm_id" {
  type = string
}

variable "system_type" {
  type = string
}

variable "service_instance_id" {
  type = string
}

variable "network_id" {
  type = string
}

locals {
 user_data_string = <<EOF
#cloud-config
packages:
  - bind
  - bind-utils
runcmd:
  - systemctl enable named.service
  - systemctl start named.service
write_files:
- path: /root/test.flag
  permissions: '0644'
  content: |
    cloudinit wrote this
EOF
}

resource "ibm_pi_instance" "rhcos_instances" {
  pi_memory            = "4"
  pi_processors        = "0.5"
  pi_instance_name     = "${var.vm_id}"
  pi_proc_type         = "shared"
  pi_image_id          = "ae3747b4-e0ac-45cc-a83c-42ed632f24dd" # local.image_id
  pi_key_pair_name     = "error-hamzy-key" # data.ibm_pi_key.key.id
  pi_sys_type          = var.system_type
  pi_storage_type      = "tier3"
  pi_cloud_instance_id = var.service_instance_id
  pi_health_status     = "WARNING"
  pi_network {
    network_id = var.network_id
  }
  pi_user_data = base64encode(local.user_data_string)
}
