terraform {
  required_providers {
    ibm = {
      source  = "ibm-cloud/ibm"
      version = "1.45.0"
    }
    ignition = {
      source  = "community-terraform-providers/ignition"
      version = "~> 2.1.0"
    }
  }
  required_version = ">= 1.0.0"
}

provider "ibm" {
# alias            = "powervs"
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

variable "resource_group" {
  type        = string
  description = "The name of the Power VS resource group to which the user belongs."
}

variable "cluster_id" {
  type        = string
  description = "The ID created by the installer to uniquely identify the created cluster."
}

variable "cos_instance_location" {
  type        = string
  description = "Specifies whether the Cloud Object Store instance is global or in a specific region. Used for the ignition file."
}

variable "cos_bucket_location" {
  type        = string
  description = "The region in which to create the Cloud Object Store bucket. Used for the igntion file."
}

variable "cos_storage_class" {
  type        = string
  description = "The storage class for the Cloud Object Store instance."
}

variable "cloud_connection_id" {
  type        = string
  description = "The Power VS Service Instance (aka Cloud Instance) ID."
}

variable "service_instance_id" {
  type        = string
  description = "The Power VS Service Instance (aka Cloud Instance) ID."
}

variable "network_id" {
  type        = string
  description = "The ID of the Power VS DHCP network."
}

variable "pub_key" {
  type = string
}

variable "cos_region" {
  type        = string
  description = "The region where your COS instance is located in"
}

variable "image_bucket_file_name" {
  type        = string
  description = "File name of the image in the COS bucket."
}

variable "image_bucket_name" {
  type        = string
  description = "Name of the COS bucket containing the image to be imported."
}

data "ibm_resource_group" "cos_group" {
  name = var.resource_group
}

resource "ibm_resource_instance" "cos_instance" {
  name              = "${var.cluster_id}-cos"
  resource_group_id = data.ibm_resource_group.cos_group.id
  service           = "cloud-object-storage"
  plan              = "standard"
  location          = var.cos_instance_location
  tags              = [var.cluster_id]
}

resource "ibm_pi_image" "boot_image" {
# provider                  = ibm.powervs
  pi_image_name             = "rhcos-${var.cluster_id}"
  pi_cloud_instance_id      = var.service_instance_id
  pi_image_bucket_name      = var.image_bucket_name
  pi_image_bucket_access    = "public"
  pi_image_bucket_region    = var.cos_region
  pi_image_bucket_file_name = var.image_bucket_file_name
  pi_image_storage_type     = "tier3"
}

# Create an IBM COS Bucket to store ignition
resource "ibm_cos_bucket" "ignition" {
  bucket_name          = "${var.cluster_id}-bootstrap-ign"
  resource_instance_id = ibm_resource_instance.cos_instance.id
  region_location      = var.cos_bucket_location
  storage_class        = var.cos_storage_class
}

resource "ibm_resource_key" "cos_service_cred" {
  name                 = "${var.cluster_id}-cred"
  role                 = "Reader"
  resource_instance_id = ibm_resource_instance.cos_instance.id
  parameters           = { HMAC = true }
}

# 1.39.0 does not support pi_dhcp_name, 1.45.0 does
resource "ibm_pi_dhcp" "new_dhcp_service" {
  pi_cloud_connection_id = var.cloud_connection_id
  pi_cloud_instance_id   = var.service_instance_id
  pi_dhcp_name           = "${var.cluster_id}-dhcp"
}

data "ibm_pi_dhcp" "dhcp_network" {
  pi_cloud_instance_id   = var.service_instance_id
  pi_dhcp_id             = ibm_pi_dhcp.new_dhcp_service.dhcp_id
}

data "ignition_config" "vm_ignition" {
# replace = [data.ignition_replace.source.rendered]
  users   = [data.ignition_user.vm_user.rendered]
  files   = [data.ignition_file.vm_hostname.rendered]
# systemd = [data.ignition_systemd_unit.example.rendered]
}

#data "ignition_replace" "source" {
#  source      =
#  httpHeaders =
#        "source": "${PROTOCOL}://${HOSTNAME}/${BUCKET_NAME}/${OBJECT_NAME}",
#        "httpHeaders": [
#          {
#            "name": "Authorization",
#            "value": "${IAM_TOKEN}"
#          }
#}

data "ignition_user" "vm_user" {
  name                = "core"
  password_hash       = "$1$7A5bIi0z$5LZS.ZQk7hRv7W8qNvlRS1"
  ssh_authorized_keys = ["${var.pub_key}"]
}

data "ignition_file" "vm_hostname" {
  overwrite = true
  mode      = "420" // 0644
  path      = "/etc/hostname"
  content {
    content = <<EOF
${var.cluster_id}-rhocs
EOF
  }
}

#data "ignition_systemd_unit" "example" {
#}

# Place the bootstrap ignition file in the ignition COS bucket
resource "ibm_cos_bucket_object" "ignition" {
  bucket_crn      = ibm_cos_bucket.ignition.crn
  bucket_location = ibm_cos_bucket.ignition.region_location
  content         = data.ignition_config.vm_ignition.rendered
  key             = "bootstrap.ign"
  etag            = md5(data.ignition_config.vm_ignition.rendered)
}

data "ibm_iam_auth_token" "iam_token" {}

resource "ibm_pi_instance" "rhcos_instance" {
  pi_memory            = "4"
  pi_processors        = "0.5"
  pi_instance_name     = "${var.cluster_id}-vm"
  pi_proc_type         = "shared"
  pi_image_id          = ibm_pi_image.boot_image.image_id
  pi_key_pair_name     = "hamzy-key" # data.ibm_pi_key.key.id
  pi_sys_type          = "s922"
  pi_storage_type      = "tier3"
  pi_cloud_instance_id = var.service_instance_id
  pi_health_status     = "WARNING"
  pi_network {
    network_id = data.ibm_pi_dhcp.dhcp_network.network_id
#   network_id = var.network_id
#   ip_address = var.network_ip
  }
  pi_user_data = base64encode(templatefile("${path.module}/bootstrap.ign", {
    PROTOCOL    = "https"
    HOSTNAME    = ibm_cos_bucket.ignition.s3_endpoint_public
    BUCKET_NAME = ibm_cos_bucket.ignition.bucket_name
    OBJECT_NAME = ibm_cos_bucket_object.ignition.key
    IAM_TOKEN   = data.ibm_iam_auth_token.iam_token.iam_access_token
  }))
}
