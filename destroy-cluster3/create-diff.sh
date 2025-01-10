#!/usr/bin/env bash
set -euo pipefail

cd /home/OpenShift/git/hamzy-installer/pkg/destroy/powervs/

(
	sed -n -e '/^const ($/,$p' cloud-instance.go
	sed -n -e '/^const cosTypeName.*$/,$p' cloudobjectstorage.go
	sed -e '0,/^package powervs$/d' cloudresource.go
	sed -n -e '/^const ($/,$p' cloud-sshkey.go
	sed -n -e '/^const ($/,$p' dhcp.go
	sed -n -e '/^const ($/,$p' dns-dns.go
	sed -n -e '/^const ($/,$p' dns-resource.go
	sed -n -e '/^const ($/,$p' errortracker.go
	sed -n -e '/^const imageTypeName.*$/,$p' image.go
	sed -n -e '/^const jobTypeName.*$/,$p' job.go
	sed -n -e '/^const loadBalancerTypeName.*$/,$p' loadbalancer.go
	sed -n -e '/^const ($/,$p' power-instance.go
	sed -n -e '/^const powerSSHKeyTypeName.*$/,$p' power-sshkey.go
	sed -n -e '/^const ($/,$p' publicgateway.go
	sed -n -e '/^const securityGroupTypeName.*$/,$p' securitygroup.go
	sed -n -e '/^const subnetTypeName.*$/,$p' power-subnet.go
	sed -n -e '/^const vpcTypeName.*$/,$p' vpc.go
# const networkTypeName = "network"
	sed -n -e '/^const ($/,$p' serviceinstance.go
) | sed -e 's,o\.contextWithTimeout,contextWithTimeout,g'
