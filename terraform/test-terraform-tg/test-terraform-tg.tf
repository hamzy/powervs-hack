terraform {
  required_providers {
    ibm = {
      source  = "ibm-cloud/ibm"
      version = "1.55.0-beta0"
    }
    ignition = {
      source  = "community-terraform-providers/ignition"
      version = "~> 2.1.0"
    }
  }
  required_version = ">= 1.0.0"
}

provider "ibm" {
  ibmcloud_api_key = var.ibmcloud_api_key
  region           = var.ibmcloud_region
  zone             = var.ibmcloud_zone
}

#
# Variables
#
variable "ibmcloud_api_key" {
  type        = string
  description = "The API key to use."
}

variable "ibmcloud_region" {
  type        = string
  description = "The name of the Power VS region to use."
}

variable "ibmcloud_zone" {
  type        = string
  description = "The name of the Power VS zone to use."
}

variable "resource_group" {
  type        = string
  description = "The name of the Power VS resource group to which the user belongs."
}

variable "service_instance" {
  type        = string
  description = "The name of the Power VS service instance to use."
}

variable "pub_key" {
  type        = string
  description = "Your .ssh/id_rsa.pub file contents."
}

#
# Locals
#
locals {
  user = "hamzy"

  prefix = "${local.user}-test"

  dollar = "$"

  is_centos_version = "ibm-centos-stream-8-amd64-3"
  pi_centos_version = "CentOS-Stream-8"

  instance_count = 7

  one_pi_network = [
    {
      network_id = data.ibm_pi_network.internal_network.id
    }
  ]

  both_pi_networks = [
    {
      network_id = data.ibm_pi_network.public_network.id
    },
    {
      network_id = data.ibm_pi_network.internal_network.id
    }
  ]
}

# The zone used in "is" is different than the zone used in "pi" :(
#
# https://registry.terraform.io/providers/IBM-Cloud/ibm/latest/docs/data-sources/is_zones
data "ibm_is_zones" "zone_list" {
  region = var.ibmcloud_region
}

#
# Create the VPC
#
# https://registry.terraform.io/providers/IBM-Cloud/ibm/latest/docs/resources/is_vpc
resource "ibm_is_vpc" "vpc" {
  name = "${local.prefix}-vpc"
}

#
# Create the VMs on the VPC
#
# https://registry.terraform.io/providers/IBM-Cloud/ibm/latest/docs/resources/is_instance
resource "ibm_is_instance" "vsi1" {
  name    = "${local.prefix}-vsi1"
  vpc     = ibm_is_vpc.vpc.id
  zone    = sort(data.ibm_is_zones.zone_list.zones)[0]
  keys    = [data.ibm_is_ssh_key.ssh_key_id.id]
  image   = data.ibm_is_image.centos.id
  profile = "cx2-2x4"

  primary_network_interface {
    subnet          = ibm_is_subnet.is_subnet1.id
    security_groups = [ibm_is_security_group.sg1.id]
  }
}

# https://registry.terraform.io/providers/IBM-Cloud/ibm/latest/docs/resources/is_instance
resource "ibm_is_instance" "vsi2" {
  name    = "${local.prefix}-vsi2"
  vpc     = ibm_is_vpc.vpc.id
  zone    = sort(data.ibm_is_zones.zone_list.zones)[0]
  keys    = [data.ibm_is_ssh_key.ssh_key_id.id]
  image   = data.ibm_is_image.centos.id
  profile = "cx2-2x4"

  primary_network_interface {
    subnet          = ibm_is_subnet.is_subnet1.id
    security_groups = [ibm_is_security_group.sg1.id]
  }
}

#
# Create the security group for the VMs on the VPC
#
# https://registry.terraform.io/providers/IBM-Cloud/ibm/latest/docs/resources/is_security_group
resource "ibm_is_security_group" "sg1" {
  name = "${local.prefix}-sg1"
  vpc  = ibm_is_vpc.vpc.id
}

#
# allow all outgoing network traffic
#
# https://registry.terraform.io/providers/IBM-Cloud/ibm/latest/docs/resources/is_security_group_rule
resource "ibm_is_security_group_rule" "ingress_outgoing_all" {
  group     = ibm_is_security_group.sg1.id
  direction = "outbound"
  remote    = "0.0.0.0/0"
}

#
# allow all incoming network traffic on port 22
#
# https://registry.terraform.io/providers/IBM-Cloud/ibm/latest/docs/resources/is_security_group_rule
resource "ibm_is_security_group_rule" "ingress_ssh_all" {
  group     = ibm_is_security_group.sg1.id
  direction = "inbound"
  remote    = "0.0.0.0/0"

  tcp {
    port_min = 22
    port_max = 22
  }
}

#
# Create the subnet for the VMs on the VPC
#
# https://registry.terraform.io/providers/IBM-Cloud/ibm/latest/docs/resources/is_subnet
resource "ibm_is_subnet" "is_subnet1" {
  name                     = "${local.prefix}-subnet1"
  vpc                      = ibm_is_vpc.vpc.id
  zone                     = sort(data.ibm_is_zones.zone_list.zones)[0]
  total_ipv4_address_count = 256
}

#
# Query for the Centos image information
#
# https://registry.terraform.io/providers/IBM-Cloud/ibm/latest/docs/resources/is_image
data "ibm_is_image" "centos" {
  name = local.is_centos_version
}

#
# Query for the ssh key information
#
# https://registry.terraform.io/providers/IBM-Cloud/ibm/latest/docs/resources/is_ssh_key
data "ibm_is_ssh_key" "ssh_key_id" {
  name = "${local.user}-key"
}

#
# Create an external IP address (called a floating ip)
#
# https://registry.terraform.io/providers/IBM-Cloud/ibm/latest/docs/resources/is_floating_ip
resource "ibm_is_floating_ip" "fip1" {
  name   = "${local.prefix}-fip1"
  target = ibm_is_instance.vsi1.primary_network_interface[0].id
}

#
# Create the VMs on the Power Server
#
# https://registry.terraform.io/providers/IBM-Cloud/ibm/latest/docs/resources/pi_instance
resource "ibm_pi_instance" "pi_instance" {
  count                = local.instance_count
  pi_memory            = "16"
  pi_processors        = "0.5"
  pi_instance_name     = "${local.prefix}-ins${count.index + 1}"
  pi_proc_type         = "shared"
  pi_image_id          = data.ibm_pi_image.boot_image.id
  pi_key_pair_name     = "${local.user}-key"
  pi_sys_type          = "s922"
  pi_storage_type      = "tier3"
  pi_cloud_instance_id = data.ibm_resource_instance.pi_service_instance.guid
  pi_health_status     = "WARNING"
  dynamic "pi_network" {
    for_each = count.index == 0 ? local.both_pi_networks : local.one_pi_network
    content {
      network_id = pi_network.value["network_id"]
    }
  }
}

# https://registry.terraform.io/providers/IBM-Cloud/ibm/latest/docs/resources/pi_image
data "ibm_pi_image" "boot_image" {
  pi_image_name        = local.pi_centos_version
  pi_cloud_instance_id = data.ibm_resource_instance.pi_service_instance.guid
}

# https://registry.terraform.io/providers/IBM-Cloud/ibm/latest/docs/resources/pi_network
data "ibm_pi_network" "internal_network" {
  pi_network_name      = "rdr-${local.prefix}-net"
  pi_cloud_instance_id = data.ibm_resource_instance.pi_service_instance.guid
}

# https://registry.terraform.io/providers/IBM-Cloud/ibm/latest/docs/resources/pi_network
data "ibm_pi_network" "public_network" {
  pi_network_name      = "${local.user}-public-network"
  pi_cloud_instance_id = data.ibm_resource_instance.pi_service_instance.guid
}

#
# Create the Transit Gateway
#
# https://registry.terraform.io/providers/IBM-Cloud/ibm/latest/docs/resources/tg_gateway
resource "ibm_tg_gateway" "tg" {
  name           = "${local.prefix}-tg"
  location       = "us-south"
  global         = true
  resource_group = data.ibm_resource_group.rg_pvs_ipi_rg.id
}

# https://registry.terraform.io/providers/IBM-Cloud/ibm/latest/docs/data-sources/resource_group
data "ibm_resource_group" "rg_pvs_ipi_rg" {
  name = var.resource_group
}

# https://registry.terraform.io/providers/IBM-Cloud/ibm/latest/docs/data-sources/resource_instance
data "ibm_resource_instance" "pi_service_instance" {
  name              = var.service_instance
  service           = "power-iaas"
  resource_group_id = data.ibm_resource_group.rg_pvs_ipi_rg.id
}

# https://registry.terraform.io/providers/IBM-Cloud/ibm/latest/docs/resources/tg_connection
resource "ibm_tg_connection" "tg_connection1" {
  gateway      = ibm_tg_gateway.tg.id
  network_type = "vpc"
  name         = "${local.prefix}-tg-connection1"
  network_id   = ibm_is_vpc.vpc.resource_crn
}

# @BUG
# Error: "network_type" must contain a value from []string{
# "classic", "directlink", "vpc", "gre_tunnel", "unbound_gre_tunnel"
# }, got "power_virtual_server"
#
# https://registry.terraform.io/providers/IBM-Cloud/ibm/latest/docs/resources/tg_connection
#resource "ibm_tg_connection" "tg_connection2" {
#  gateway      = ibm_tg_gateway.tg.id
#  network_type = "power_virtual_server"
#  name         = "${local.prefix}-tg-connection2"
#  network_id   = data.ibm_resource_instance.pi_service_instance.crn
#}

#
# Outputs
#
output "sshcommand-vs1" {
  value = "(set -e; IP=\"${ibm_is_floating_ip.fip1.address}\"; ssh-keygen -f ~/.ssh/known_hosts -R ${local.dollar}{IP} || true; ssh-keyscan ${local.dollar}{IP} >> ~/.ssh/known_hosts; ssh -A vpcuser@${local.dollar}{IP})"
}

output "sshcommand-ins1" {
  value = "(set -e; IP=\"${ibm_pi_instance.pi_instance[0].pi_network[0].external_ip}\"; ssh-keygen -f ~/.ssh/known_hosts -R ${local.dollar}{IP} || true; ssh-keyscan ${local.dollar}{IP} >> ~/.ssh/known_hosts; ssh -A cloud-user@${local.dollar}{IP})"
}

# @BUG - CLI work around
output "tg-con2" {
  value = "ibmcloud tg connection-create ${ibm_tg_gateway.tg.id} --name ${local.prefix}-tg-connection2 --network-type power_virtual_server --network-id '${data.ibm_resource_instance.pi_service_instance.crn}'"
}
