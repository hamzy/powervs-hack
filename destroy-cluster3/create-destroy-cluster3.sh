#!/usr/bin/env bash
set -euo pipefail

cd /home/OpenShift/git/hamzy-installer/pkg/destroy/powervs/

(
	cat << '___EOF___'
package main

import (
	"context"
	"fmt"
	"github.com/IBM-Cloud/bluemix-go/crn"
	"github.com/IBM-Cloud/power-go-client/power/models"
	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/networking-go-sdk/resourcerecordsv1"
	"github.com/IBM/networking-go-sdk/transitgatewayapisv1"
	"github.com/IBM/platform-services-go-sdk/resourcecontrollerv2"
	"github.com/IBM/vpc-go-sdk/vpcv1"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/wait"
	"math"
	gohttp "net/http"
	"regexp"
	"strings"
	"time"
)

___EOF___
	sed -n -e '/^const ($/,$p' cloud-instance.go
	echo
	sed -n -e '/^const cosTypeName.*$/,$p' cloudobjectstorage.go
	echo
	sed -e '0,/^package powervs$/d' cloudresource.go
	echo
	sed -n -e '/^const ($/,$p' cloud-sshkey.go
	echo
	sed -e '0,/^const cloudSubnetTypeName.*$/d' cloud-subnet.go
	echo
	sed -n -e '/^const ($/,$p' cloud-transit-gateways.go
	echo
	sed -n -e '/^const ($/,$p' dhcp.go
	echo
	sed -n -e '/^const ($/,$p' dns-dns.go
	echo
	sed -n -e '/^const ($/,$p' dns-resource.go
	echo
	sed -n -e '/^const ($/,$p' errortracker.go
	echo
	sed -n -e '/^const imageTypeName.*$/,$p' image.go
	echo
	sed -n -e '/^const jobTypeName.*$/,$p' job.go
	echo
	sed -n -e '/^const loadBalancerTypeName.*$/,$p' loadbalancer.go
	echo
	sed -n -e '/^const ($/,$p' power-instance.go
	echo
	sed -n -e '/^const powerSSHKeyTypeName.*$/,$p' power-sshkey.go
	echo
	sed -n -e '/^const powerSubnetTypeName.*$/,$p' power-subnet.go
	echo
	sed -n -e '/^const ($/,$p' publicgateway.go
	echo
	sed -n -e '/^const securityGroupTypeName.*$/,$p' securitygroup.go
	echo
	sed -n -e '/^const subnetTypeName.*$/,$p' power-subnet.go
	echo
	sed -n -e '/^const vpcTypeName.*$/,$p' vpc.go
	echo
# const networkTypeName = "network"
	sed -n -e '/^const ($/,$p' serviceinstance.go
) 2>&1 | sed -re 's,([^/])(\<http\>),\1gohttp,g' -e 's,cloudSubnetTypeName,publicGatewayTypeName,'

# 2>&1 | sed -e 's,o\.contextWithTimeout,contextWithTimeout,g'
