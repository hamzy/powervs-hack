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

resource "ibm_is_vpc" "vpc" {
  name = "${var.vm_id}-vpc"
}

resource "ibm_is_security_group" "sg1" {
  name = "${var.vm_id}-sg1"
  vpc  = ibm_is_vpc.vpc.id
}

# allow all outgoing network traffic
resource "ibm_is_security_group_rule" "ingress_outgoing_all" {
  group     = ibm_is_security_group.sg1.id
  direction = "outbound"
  remote    = "0.0.0.0/0"
}

# allow all incoming network traffic on port 22
resource "ibm_is_security_group_rule" "ingress_ssh_all" {
  group     = ibm_is_security_group.sg1.id
  direction = "inbound"
  remote    = "0.0.0.0/0"

  tcp {
    port_min = 22
    port_max = 22
  }
}

resource "ibm_is_subnet" "subnet1" {
  name                     = "${var.vm_id}-subnet1"
  vpc                      = ibm_is_vpc.vpc.id
  zone                     = var.ibmcloud_zone
  total_ipv4_address_count = 256
}

data "ibm_is_image" "centos" {
  name = "ibm-centos-7-9-minimal-amd64-6"
}

data "ibm_is_ssh_key" "ssh_key_id" {
  name = "hamzy-key"
}

resource "ibm_is_instance" "vsi1" {
  name    = "${var.vm_id}-vsi1"
  vpc     = ibm_is_vpc.vpc.id
  zone    = var.ibmcloud_zone
  keys    = [data.ibm_is_ssh_key.ssh_key_id.id]
  image   = data.ibm_is_image.centos.id
  profile = "cx2-2x4"

  primary_network_interface {
    subnet          = ibm_is_subnet.subnet1.id
    security_groups = [ibm_is_security_group.sg1.id]
  }

  user_data = base64encode(local.user_data_string)
}

resource "ibm_is_floating_ip" "fip1" {
  name   = "${var.vm_id}-fip1"
  target = ibm_is_instance.vsi1.primary_network_interface[0].id
}

output "sshcommand" {
  value = "ssh root@${ibm_is_floating_ip.fip1.address}"
}
