terraform {
  required_providers {
    ibm = {
      source  = "ibm-cloud/ibm"
      version = "1.39.0"
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

data "ignition_config" "vm_ignition" {
  users = [data.ignition_user.vm_user.rendered]
  files = [data.ignition_file.vm_hostname.rendered]
  systemd = [data.ignition_systemd_unit.example.rendered]
}

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
${var.vm_id}-rhocs
EOF
  }
}

data "ignition_systemd_unit" "example" {
  name = "example.service"
  content = <<EOF
[Unit]
Description=Layer additional rpms
Wants=network-online.target
After=network-online.target
# We run before `zincati.service` to avoid conflicting rpm-ostree transactions.
Before=zincati.service
ConditionPathExists=!/var/lib/%N.stamp
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/rpm-ostree install --apply-live --allow-inactive tmux
ExecStart=/bin/touch /var/lib/%N.stamp
[Install]
WantedBy=multi-user.target
EOF
}

resource "ibm_pi_instance" "rhcos_instances" {
  pi_memory            = "4"
  pi_processors        = "0.5"
  pi_instance_name     = "${var.vm_id}-rhcos"
  pi_proc_type         = "shared"
  pi_image_id          = "0cac2539-b410-4229-9ab7-75352645e17e" # local.image_id
  pi_key_pair_name     = "hamzy-key" # data.ibm_pi_key.key.id
  pi_sys_type          = var.system_type
  pi_storage_type      = "tier3"
  pi_cloud_instance_id = var.service_instance_id
  pi_health_status     = "WARNING"
  pi_network {
    network_id = var.network_id
  }
  pi_user_data = base64encode(data.ignition_config.vm_ignition.rendered)
}
