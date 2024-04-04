#!/usr/bin/env bash

set -euo pipefail

DIR=/home/OpenShift/git/hamzy-installer/pkg/destroy/powervs
SCRIPT_DIR=$(cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)

cat << '___EOF___'
//
// (cd destroy-cluster2/; go build; ./destroy-cluster2 -apiKey "${IBMCLOUD_API_KEY}" -baseDomain "scnl-ibm.com" -clusterName "rdr-hamzy-test" -infraID "rdr-hamzy-test" -CISInstanceCRN $(ibmcloud cis instances --output json | jq -r '.[] | select (.name|test("'${CIS_INSTANCE}'")) | .crn') -region "${POWERVS_REGION}" -zone "${POWERVS_ZONE}" -serviceInstanceGUID $(ibmcloud resource service-instance ${SERVICE_INSTANCE} --output json | jq -r '.[].guid') -resourceGroupID "powervs-ipi-resource-group" -shouldDebug true -shouldDelete true
//

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/IBM-Cloud/bluemix-go"
	"github.com/IBM-Cloud/bluemix-go/api/resource/resourcev2/controllerv2"
	"github.com/IBM-Cloud/bluemix-go/authentication"
	"github.com/IBM-Cloud/bluemix-go/crn"
	"github.com/IBM-Cloud/bluemix-go/http"
	bxmodels "github.com/IBM-Cloud/bluemix-go/models"
	"github.com/IBM-Cloud/bluemix-go/rest"
	bxsession "github.com/IBM-Cloud/bluemix-go/session"
	"github.com/IBM-Cloud/power-go-client/clients/instance"
	"github.com/IBM-Cloud/power-go-client/ibmpisession"
	"github.com/IBM-Cloud/power-go-client/power/models"
	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/networking-go-sdk/dnsrecordsv1"
	"github.com/IBM/networking-go-sdk/dnszonesv1"
	"github.com/IBM/networking-go-sdk/resourcerecordsv1"
	"github.com/IBM/networking-go-sdk/zonesv1"
	"github.com/IBM/platform-services-go-sdk/resourcecontrollerv2"
	"github.com/IBM/platform-services-go-sdk/resourcemanagerv2"
	"github.com/IBM/vpc-go-sdk/vpcv1"
	"github.com/openshift/installer/pkg/version"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"io"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	"io/ioutil"
	"math"
	gohttp "net/http"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"
)

var log *logrus.Logger = nil
var shouldDelete = false
var shouldDeleteDHCP = false

//func leftInContext(ctx context.Context) time.Time {
//	deadline, ok := ctx.Deadline()
//	if !ok {
//		// https://stackoverflow.com/a/32620397
//		return time.Unix(1<<63-62135596801, 999999999)
//	}
//
//	duration := deadline.Sub(time.Now())
//
//	return time.Time{}.Add(duration)
//}

func leftInContext(ctx context.Context) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return math.MaxInt64
	}

	duration := deadline.Sub(time.Now())

//	log.Debugf("leftInContext: duration = %v", duration)

	return duration
}
___EOF___

(
	cat \
		${DIR}/cloudconnection.go \
		${DIR}/cloud-instance.go \
		${DIR}/cloudobjectstorage.go \
		${DIR}/cloudresource.go \
		${DIR}/cloud-sshkey.go \
		${DIR}/dhcp.go \
		${DIR}/dns-dns.go \
		${DIR}/dns-resource.go \
		${DIR}/errortracker.go \
		${DIR}/image.go \
		${DIR}/job.go \
		${DIR}/loadbalancer.go \
		${DIR}/power-instance.go \
		${DIR}/power-sshkey.go \
		${DIR}/publicgateway.go \
		${DIR}/securitygroup.go \
		${DIR}/subnet.go \
		${DIR}/vpc.go
) | sed \
	-e '/^package powervs$/d' \
	-e '/^import ($/,/^)$/d' \
	-e 's, http.StatusNotFound, gohttp.StatusNotFound,g' \
	-e 's, http.StatusInternalServerError, gohttp.StatusInternalServerError,g' \
	-e 's, http.StatusNoContent, gohttp.StatusNoContent,g'

cat << '___EOF___'
// listVPCInCloudConnections removes VPCs attached to CloudConnections and returs a list of jobs.
func (o *ClusterUninstaller) listVPCInCloudConnections() (cloudResources, error) {
	var (
		ctx context.Context

		// https://github.com/IBM-Cloud/power-go-client/blob/v1.0.88/power/models/cloud_connections.go#L20-L25
		cloudConnections *models.CloudConnections

		// https://github.com/IBM-Cloud/power-go-client/blob/v1.0.88/power/models/cloud_connection.go#L20-L71
		cloudConnection          *models.CloudConnection
		cloudConnectionUpdateNew *models.CloudConnection

		// https://github.com/IBM-Cloud/power-go-client/blob/v1.0.88/power/models/job_reference.go#L18-L27
		jobReference *models.JobReference

		err error

		cloudConnectionID string

		// https://github.com/IBM-Cloud/power-go-client/blob/v1.0.88/power/models/cloud_connection_endpoint_v_p_c.go#L19-L26
		endpointVpc       *models.CloudConnectionEndpointVPC
		endpointUpdateVpc models.CloudConnectionEndpointVPC

		// https://github.com/IBM-Cloud/power-go-client/blob/v1.0.88/power/models/cloud_connection_v_p_c.go#L18-L26
		Vpc *models.CloudConnectionVPC

		// https://github.com/IBM-Cloud/power-go-client/blob/v1.0.88/power/models/cloud_connection_update.go#L20
		cloudConnectionUpdate models.CloudConnectionUpdate

		foundOne bool = false
		foundVpc bool = false
	)

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	o.Logger.Printf("Listing VPCs in Cloud Connections")

	select {
	case <-ctx.Done():
		o.Logger.Printf("listVPCInCloudConnections: case <-ctx.Done()")
		return nil, o.Context.Err() // we're cancelled, abort
	default:
	}

	cloudConnections, err = o.cloudConnectionClient.GetAll()
	if err != nil {
		o.Logger.Fatalf("Failed to list cloud connections: %v", err)
	}

	result := []cloudResource{}
	for _, cloudConnection = range cloudConnections.CloudConnections {
		select {
		case <-ctx.Done():
			o.Logger.Printf("listVPCInCloudConnections: case <-ctx.Done()")
			return nil, o.Context.Err() // we're cancelled, abort
		default:
		}

		if !strings.Contains(*cloudConnection.Name, o.InfraID) {
			// Skip this one!
			continue
		}

		foundOne = true

		o.Logger.Printf("listVPCInCloudConnections: FOUND: %s (%s)", *cloudConnection.Name, *cloudConnection.CloudConnectionID)

		cloudConnectionID = *cloudConnection.CloudConnectionID

		cloudConnection, err = o.cloudConnectionClient.Get(cloudConnectionID)
		if err != nil {
			o.Logger.Fatalf("Failed to get cloud connection %s: %v", cloudConnectionID, err)
		}

		endpointVpc = cloudConnection.Vpc

		o.Logger.Printf("listVPCInCloudConnections: endpointVpc = %+v", endpointVpc)

		foundVpc = false
		for _, Vpc = range endpointVpc.Vpcs {
			o.Logger.Printf("listVPCInCloudConnections: Vpc = %+v", Vpc)
			o.Logger.Printf("listVPCInCloudConnections: Vpc.Name = %v, o.InfraID = %v", Vpc.Name, o.InfraID)
			if strings.Contains(Vpc.Name, o.InfraID) {
				foundVpc = true
			}
		}
		o.Logger.Printf("listVPCInCloudConnections: foundVpc = %v", foundVpc)
		if !foundVpc {
			continue
		}

		// https://github.com/IBM-Cloud/power-go-client/blob/v1.0.88/power/models/cloud_connection_v_p_c.go#L18
		var vpcsUpdate []*models.CloudConnectionVPC

		for _, Vpc = range endpointVpc.Vpcs {
			if !strings.Contains(Vpc.Name, o.InfraID) {
				vpcsUpdate = append (vpcsUpdate, Vpc)
			}
		}

		if len(vpcsUpdate) > 0 {
			endpointUpdateVpc.Enabled = true
		} else {
			endpointUpdateVpc.Enabled = false
		}

		endpointUpdateVpc.Vpcs = vpcsUpdate

		cloudConnectionUpdate.Vpc = &endpointUpdateVpc

		var vpcsStrings []string

		for _, Vpc = range vpcsUpdate {
			vpcsStrings = append (vpcsStrings, Vpc.Name)
		}
		o.Logger.Printf("listVPCInCloudConnections: vpcsUpdate = %v", vpcsStrings)
		o.Logger.Printf("listVPCInCloudConnections: endpointUpdateVpc = %+v", endpointUpdateVpc)

		if !shouldDelete {
			o.Logger.Printf("Skipping updating the cloud connection %q since shouldDelete is false", *cloudConnection.Name)
			continue
		}

		cloudConnectionUpdateNew, jobReference, err = o.cloudConnectionClient.Update(*cloudConnection.CloudConnectionID, &cloudConnectionUpdate)
		if err != nil {
			o.Logger.Fatalf("Failed to update cloud connection %v", err)
		}

		o.Logger.Printf("listVPCInCloudConnections: cloudConnectionUpdateNew = %+v", cloudConnectionUpdateNew)
		o.Logger.Printf("listVPCInCloudConnections: jobReference = %+v", jobReference)

		result = append(result, cloudResource{
			key:      *jobReference.ID,
			name:     *jobReference.ID,
			status:   "",
			typeName: jobTypeName,
			id:       *jobReference.ID,
		})
	}

	if !foundOne {
		o.Logger.Printf("listVPCInCloudConnections: NO matching cloud connections")
		for _, cloudConnection = range cloudConnections.CloudConnections {
			o.Logger.Printf("listVPCInCloudConnections: only found cloud connection: %s", *cloudConnection.Name)
		}
	}

	return cloudResources{}.insert(result...), nil
}

// destroyVPCInCloudConnections removes all VPCs in cloud connections that have a name prefixed
// with the cluster's infra ID.
func (o *ClusterUninstaller) destroyVPCInCloudConnections() error {
	firstPassList, err := o.listVPCInCloudConnections()
	if err != nil {
		return err
	}

	if len(firstPassList.list()) == 0 {
		return nil
	}

	items := o.insertPendingItems(jobTypeName, firstPassList.list())

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	for _, item := range items {
		select {
		case <-o.Context.Done():
			o.Logger.Debugf("destroyVPCInCloudConnections: case <-o.Context.Done()")
			return o.Context.Err() // we're cancelled, abort
		default:
		}

		backoff := wait.Backoff{
			Duration: 15 * time.Second,
			Factor:   1.1,
			Cap:      leftInContext(ctx),
			Steps:    math.MaxInt32}
		err = wait.ExponentialBackoffWithContext(ctx, backoff, func() (bool, error) {
			result, err2 := o.deleteJob(item)
			switch result {
			case DeleteJobSuccess:
				o.Logger.Debugf("destroyVPCInCloudConnections: deleteJob returns DeleteJobSuccess")
				return true, nil
			case DeleteJobRunning:
				o.Logger.Debugf("destroyVPCInCloudConnections: deleteJob returns DeleteJobRunning")
				return false, nil
			case DeleteJobError:
				o.Logger.Debugf("destroyVPCInCloudConnections: deleteJob returns DeleteJobError: %v", err2)
				return false, err2
			default:
				return false, errors.Errorf("destroyVPCInCloudConnections: deleteJob unknown result enum %v", result)
			}
		})
		if err != nil {
			o.Logger.Fatal("destroyVPCInCloudConnections: ExponentialBackoffWithContext (destroy) returns ", err)
		}
	}

	if items = o.getPendingItems(jobTypeName); len(items) > 0 {
		for _, item := range items {
			o.Logger.Debugf("destroyVPCInCloudConnections: found %s in pending items", item.name)
		}
		return errors.Errorf("destroyVPCInCloudConnections: %d undeleted items pending", len(items))
	}

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func() (bool, error) {
		secondPassList, err2 := o.listVPCInCloudConnections()
		if err2 != nil {
			return false, err2
		}
		if len(secondPassList) == 0 {
			// We finally don't see any remaining instances!
			return true, nil
		}
		for _, item := range secondPassList {
			o.Logger.Debugf("destroyVPCInCloudConnections: found %s in second pass", item.name)
		}
		return false, nil
	})
	if err != nil {
		o.Logger.Fatal("destroyVPCInCloudConnections: ExponentialBackoffWithContext (list) returns ", err)
	}

	return nil
}

const networkTypeName = "network"

// listNetworks lists networks in the cloud.
func (o *ClusterUninstaller) listNetworks() (cloudResources, error) {
	var (
		// https://github.com/IBM-Cloud/power-go-client/blob/v1.0.88/power/models/networks.go#L20
		networks *models.Networks

		// https://github.com/IBM-Cloud/power-go-client/blob/v1.0.88/power/models/network_reference.go#L20
		networkRef *models.NetworkReference

		err error
	)

	o.Logger.Debugf("Listing Networks")

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("listNetworks: case <-ctx.Done()")
		return nil, o.Context.Err() // we're cancelled, abort
	default:
	}

	networks, err = o.networkClient.GetAll()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to list networks")
	}

	var foundOne = false

	result := []cloudResource{}
	for _, networkRef = range networks.Networks {
		if strings.Contains(*networkRef.Name, o.InfraID) {
			foundOne = true
			o.Logger.Debugf("listNetworks: FOUND: %s, %s", *networkRef.NetworkID, *networkRef.Name)
			result = append(result, cloudResource{
				key:      *networkRef.NetworkID,
				name:     *networkRef.Name,
				status:   "",
				typeName: networkTypeName,
				id:       *networkRef.NetworkID,
			})
		}
	}
	if !foundOne {
		o.Logger.Debugf("listNetworks: NO matching subnet against: %s", o.InfraID)
		for _, networkRef := range networks.Networks {
			o.Logger.Debugf("listNetworks: network: %s", *networkRef.Name)
		}
	}

	return cloudResources{}.insert(result...), nil
}

func (o *ClusterUninstaller) deleteNetwork(item cloudResource) error {
	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("deleteNetwork: case <-ctx.Done()")
		return o.Context.Err() // we're cancelled, abort
	default:
	}

	err := o.networkClient.Delete(item.id)
	if err != nil {
		return errors.Wrapf(err, "failed to delete network %s", item.name)
	}

	o.Logger.Debugf("Deleting Network %q", item.name)
	o.deletePendingItems(item.typeName, []cloudResource{item})

	return nil
}

// destroyNetworks removes all network resources that have a name prefixed
// with the cluster's infra ID.
func (o *ClusterUninstaller) destroyNetworks() error {
	firstPassList, err := o.listNetworks()
	if err != nil {
		return err
	}

	if len(firstPassList.list()) == 0 {
		return nil
	}

	items := o.insertPendingItems(networkTypeName, firstPassList.list())

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	for _, item := range items {
		select {
		case <-ctx.Done():
			o.Logger.Debugf("destroyNetworks: case <-ctx.Done()")
			return o.Context.Err() // we're cancelled, abort
		default:
		}

		backoff := wait.Backoff{
			Duration: 15 * time.Second,
			Factor:   1.1,
			Cap:      leftInContext(ctx),
			Steps:    math.MaxInt32}
		err = wait.ExponentialBackoffWithContext(ctx, backoff, func() (bool, error) {
			err2 := o.deleteNetwork(item)
			if err2 == nil {
				return true, err2
			}
			o.errorTracker.suppressWarning(item.key, err2, o.Logger)
			return false, err2
		})
		if err != nil {
			o.Logger.Fatal("destroyNetworks: ExponentialBackoffWithContext (destroy) returns ", err)
		}
	}

	if items = o.getPendingItems(networkTypeName); len(items) > 0 {
		for _, item := range items {
			o.Logger.Debugf("destroyNetworks: found %s in pending items", item.name)
		}
		return errors.Errorf("destroyNetworks: %d undeleted items pending", len(items))
	}

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func() (bool, error) {
		secondPassList, err2 := o.listNetworks()
		if err2 != nil {
			return false, err2
		}
		if len(secondPassList) == 0 {
			// We finally don't see any remaining instances!
			return true, nil
		}
		for _, item := range secondPassList {
			o.Logger.Debugf("destroyNetworks: found %s in second pass", item.name)
		}
		return false, nil
	})
	if err != nil {
		o.Logger.Fatal("destroyNetworks: ExponentialBackoffWithContext (list) returns ", err)
	}

	return nil
}

const serviceInstanceTypeName = "serviceInstance"

// listServiceInstances lists serviceInstances in the cloud.
func (o *ClusterUninstaller) listServiceInstances() (cloudResources, error) {
	o.Logger.Debugf("Listing ServiceInstances")

	select {
	case <-o.Context.Done():
		o.Logger.Debugf("listServiceInstances: case <-o.Context.Done()")
		return nil, o.Context.Err() // we're cancelled, abort
	default:
	}

	// https://raw.githubusercontent.com/IBM/platform-services-go-sdk/main/resourcecontrollerv2/resource_controller_v2.go
	var (
		ctx       context.Context
		options   *resourcecontrollerv2.ListResourceInstancesOptions
		resources *resourcecontrollerv2.ResourceInstancesList
		err       error
		perPage   int64   = 20
		moreData  bool    = true
		nextURL   *string
		foundOne  bool    = false
	)

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	result := []cloudResource{}

	options = o.controllerSvc.NewListResourceInstancesOptions()
	options.SetResourceGroupID(o.resourceGroupID)
	// resource ID for Power Systems Virtual Server in the Global catalog
	options.SetResourceID("abd259f0-9990-11e8-acc8-b9f54a8f1661")
	options.SetLimit(perPage)

	for moreData {

		o.Logger.Debugf("options = %+v", options)
		o.Logger.Debugf("options.Limit = %v", *options.Limit)
		if options.Start != nil {
			o.Logger.Debugf("optionsStart = %v", *options.Start)
		}
		resources, _, err = o.controllerSvc.ListResourceInstancesWithContext(ctx, options)
		if err != nil {
			o.Logger.Fatalf("Failed to list resource instances: %v", err)
		}

		o.Logger.Debugf("resources.RowsCount = %v", *resources.RowsCount)

		for _, resource := range resources.Resources {
			if strings.Contains(*resource.Name, o.InfraID) {
				foundOne = true
				o.Logger.Debugf("listServiceInstances: FOUND: %s, %s", *resource.ID, *resource.Name)
				result = append(result, cloudResource{
					key:      *resource.ID,
					name:     *resource.Name,
					status:   "",
					typeName: serviceInstanceTypeName,
					id:       *resource.ID,
				})
			}
		}

		// Based on: https://cloud.ibm.com/apidocs/resource-controller/resource-controller?code=go#list-resource-instances
		nextURL, err = core.GetQueryParam(resources.NextURL, "start")
		if err != nil {
			o.Logger.Fatalf("Failed to GetQueryParam on start: %v", err)
		}
		if nextURL == nil {
			o.Logger.Debugf("nextURL = nil")
			options.SetStart("")
		} else {
			o.Logger.Debugf("nextURL = %v", *nextURL)
			options.SetStart(*nextURL)
		}

		moreData = *resources.RowsCount == perPage

	}

	if !foundOne {
		o.Logger.Debugf("listServiceInstances: NO matching serviceInstance against: %s", o.InfraID)

		options = o.controllerSvc.NewListResourceInstancesOptions()
		options.SetType("service_instance")
		options.SetLimit(perPage)

		moreData = true

		for moreData {

			o.Logger.Debugf("options = %+v", options)
			o.Logger.Debugf("options.Limit = %v", *options.Limit)
			if options.Start != nil {
				o.Logger.Debugf("optionsStart = %v", *options.Start)
			}
			resources, _, err = o.controllerSvc.ListResourceInstancesWithContext(ctx, options)
			if err != nil {
				o.Logger.Fatalf("Failed to list COS instances: %v", err)
			}

			o.Logger.Debugf("resources.RowsCount = %v", *resources.RowsCount)

			for _, resource := range resources.Resources {
				o.Logger.Debugf("listServiceInstances: FOUND: %s, %s", *resource.ID, *resource.Name)
			}

			// Based on: https://cloud.ibm.com/apidocs/resource-controller/resource-controller?code=go#list-resource-instances
			nextURL, err = core.GetQueryParam(resources.NextURL, "start")
			if err != nil {
				o.Logger.Fatalf("Failed to GetQueryParam on start: %v", err)
			}
			if nextURL == nil {
				o.Logger.Debugf("nextURL = nil")
				options.SetStart("")
			} else {
				o.Logger.Debugf("nextURL = %v", *nextURL)
				options.SetStart(*nextURL)
			}

			moreData = *resources.RowsCount == perPage

		}
	}

	return cloudResources{}.insert(result...), nil
}

func (o *ClusterUninstaller) deleteServiceInstance(item cloudResource) error {
	// https://raw.githubusercontent.com/IBM/platform-services-go-sdk/main/resourcecontrollerv2/resource_controller_v2.go
	var (
		ctx           context.Context
		getOptions    *resourcecontrollerv2.GetResourceInstanceOptions
		deleteOptions *resourcecontrollerv2.DeleteResourceInstanceOptions
		response      *core.DetailedResponse
		err           error
	)

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	select {
	case <-o.Context.Done():
		o.Logger.Debugf("deleteServiceInstance: case <-o.Context.Done()")
		return o.Context.Err() // we're cancelled, abort
	default:
	}

	getOptions = o.controllerSvc.NewGetResourceInstanceOptions(item.id)

	_, response, err = o.controllerSvc.GetResourceInstanceWithContext(ctx, getOptions)

	if err != nil && response != nil && response.StatusCode == gohttp.StatusNotFound {
		// The resource is gone
		o.deletePendingItems(item.typeName, []cloudResource{item})
		o.Logger.Infof("Deleted Service Instance %q", item.name)
		return nil
	}
	if err != nil && response != nil && response.StatusCode == gohttp.StatusInternalServerError {
		o.Logger.Infof("deleteServiceInstance: internal server error")
		return nil
	}

	if !shouldDelete {
		o.Logger.Debugf("Skipping deleting serviceInstance %q since shouldDelete is false", item.name)
		o.deletePendingItems(item.typeName, []cloudResource{item})
		return nil
	}

	deleteOptions = o.controllerSvc.NewDeleteResourceInstanceOptions(item.id)

	_, err = o.controllerSvc.DeleteResourceInstanceWithContext(ctx, deleteOptions)
	if err != nil {
		return errors.Wrapf(err, "failed to delete serviceInstance %s", item.name)
	}

	o.Logger.Debugf("Deleting Service Instance %q", item.name)
	o.deletePendingItems(item.typeName, []cloudResource{item})

	return nil
}

// destroyServiceInstances removes all serviceInstance resources that have a name prefixed
// with the cluster's infra ID.
func (o *ClusterUninstaller) destroyServiceInstances() error {
	firstPassList, err := o.listServiceInstances()
	if err != nil {
		return err
	}

	if len(firstPassList.list()) == 0 {
		return nil
	}

	items := o.insertPendingItems(serviceInstanceTypeName, firstPassList.list())

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	for _, item := range items {
		select {
		case <-o.Context.Done():
			o.Logger.Debugf("destroyServiceInstances: case <-o.Context.Done()")
			return o.Context.Err() // we're cancelled, abort
		default:
		}

		backoff := wait.Backoff{
			Duration: 15 * time.Second,
			Factor:   1.1,
			Cap:      leftInContext(ctx),
			Steps:    math.MaxInt32}
		err = wait.ExponentialBackoffWithContext(ctx, backoff, func() (bool, error) {
			err2 := o.deleteServiceInstance(item)
			if err2 == nil {
				return true, err2
			}
			o.errorTracker.suppressWarning(item.key, err2, o.Logger)
			return false, err2
		})
		if err != nil {
			o.Logger.Fatal("destroyServiceInstances: ExponentialBackoffWithContext (destroy) returns ", err)
		}
	}

	if items = o.getPendingItems(serviceInstanceTypeName); len(items) > 0 {
		for _, item := range items {
			o.Logger.Debugf("destroyServiceInstances: found %s in pending items", item.name)
		}
		return errors.Errorf("destroyServiceInstances: %d undeleted items pending", len(items))
	}

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func() (bool, error) {
		secondPassList, err2 := o.listServiceInstances()
		if err2 != nil {
			return false, err2
		}
		if len(secondPassList) == 0 {
			// We finally don't see any remaining instances!
			return true, nil
		}
		for _, item := range secondPassList {
			o.Logger.Debugf("destroyServiceInstances: found %s in second pass", item.name)
		}
		return false, nil
	})
	if err != nil {
		o.Logger.Fatal("destroyServiceInstances: ExponentialBackoffWithContext (list) returns ", err)
	}

	return nil
}
___EOF___

cat << '___EOF___'
var (
	defaultTimeout = 15 * time.Minute
	stageTimeout   = 15 * time.Minute
)

const (
	// cisServiceID is the Cloud Internet Services' catalog service ID.
	cisServiceID = "75874a60-cb12-11e7-948e-37ac098eb1b9"
)

// User information.
type User struct {
	ID         string
	Email      string
	Account    string
	cloudName  string `default:"bluemix"`
	cloudType  string `default:"public"`
	generation int    `default:"2"`
}

func fetchUserDetails(bxSession *bxsession.Session, generation int) (*User, error) {
	config := bxSession.Config
	user := User{}
	var bluemixToken string

	if strings.HasPrefix(config.IAMAccessToken, "Bearer") {
		bluemixToken = config.IAMAccessToken[7:len(config.IAMAccessToken)]
	} else {
		bluemixToken = config.IAMAccessToken
	}

	token, err := jwt.Parse(bluemixToken, func(token *jwt.Token) (interface{}, error) {
		return "", nil
	})
	if err != nil && !strings.Contains(err.Error(), "key is of invalid type") {
		return &user, err
	}

	claims := token.Claims.(jwt.MapClaims)
	if email, ok := claims["email"]; ok {
		user.Email = email.(string)
	}
	user.ID = claims["id"].(string)
	user.Account = claims["account"].(map[string]interface{})["bss"].(string)
	iss := claims["iss"].(string)
	if strings.Contains(iss, "https://iam.cloud.ibm.com") {
		user.cloudName = "bluemix"
	} else {
		user.cloudName = "staging"
	}
	user.cloudType = "public"

	user.generation = generation
	return &user, nil
}

// GetRegion converts from a zone into a region.
func GetRegion(zone string) (region string, err error) {
	err = nil
	switch {
	case strings.HasPrefix(zone, "dal"), strings.HasPrefix(zone, "us-south"):
		region = "us-south"
	case strings.HasPrefix(zone, "sao"):
		region = "sao"
	case strings.HasPrefix(zone, "us-east"):
		region = "us-east"
	case strings.HasPrefix(zone, "tor"):
		region = "tor"
	case strings.HasPrefix(zone, "eu-de-"):
		region = "eu-de"
	case strings.HasPrefix(zone, "lon"):
		region = "lon"
	case strings.HasPrefix(zone, "syd"):
		region = "syd"
	case strings.HasPrefix(zone, "tok"):
		region = "tok"
	case strings.HasPrefix(zone, "osa"):
		region = "osa"
	case strings.HasPrefix(zone, "mon"):
		region = "mon"
	default:
		return "", fmt.Errorf("region not found for the zone: %s", zone)
	}
	return
}

// ClusterUninstaller holds the various options for the cluster we want to delete.
type ClusterUninstaller struct {
	APIKey         string
	BaseDomain     string
	CISInstanceCRN string
	ClusterName    string
	Context        context.Context
	DNSInstanceCRN string
	DNSZone        string
	InfraID        string
	Logger         logrus.FieldLogger
	Region         string
	ServiceGUID    string
	VPCRegion      string
	Zone           string

	managementSvc         *resourcemanagerv2.ResourceManagerV2
	controllerSvc         *resourcecontrollerv2.ResourceControllerV2
	vpcSvc                *vpcv1.VpcV1
	zonesSvc              *zonesv1.ZonesV1
	dnsRecordsSvc         *dnsrecordsv1.DnsRecordsV1
	dnsZonesSvc           *dnszonesv1.DnsZonesV1
	resourceRecordsSvc    *resourcerecordsv1.ResourceRecordsV1
	piSession             *ibmpisession.IBMPISession
	instanceClient        *instance.IBMPIInstanceClient
	imageClient           *instance.IBMPIImageClient
	jobClient             *instance.IBMPIJobClient
	keyClient             *instance.IBMPIKeyClient
	cloudConnectionClient *instance.IBMPICloudConnectionClient
	dhcpClient            *instance.IBMPIDhcpClient
	networkClient         *instance.IBMPINetworkClient

	resourceGroupID string
	cosInstanceID   string
	dnsZoneID       string

	errorTracker
	pendingItemTracker
}

// New returns an IBMCloud destroyer from ClusterMetadata.
func New(log logrus.FieldLogger,
	apiKey string,
	baseDomain string,
	serviceInstanceGUID string,
	clusterName string,
	infraID string,
	cisInstanceCRN string,
	dnsInstanceCRN string,
	region string,
	zone string,
	resourceGroupID string) (*ClusterUninstaller, error) {

	var vpcRegion string
	var err error

	vpcRegion, err = VPCRegionForPowerVSZone(zone)
	if err != nil {
		return nil, err
	}
	log.Printf("vpcRegion = %v", vpcRegion)

	return &ClusterUninstaller{
		APIKey:             apiKey,
		BaseDomain:         baseDomain,
		ClusterName:        clusterName,
		Context:            context.Background(),
		Logger:             log,
		InfraID:            infraID,
		CISInstanceCRN:     cisInstanceCRN,
		DNSInstanceCRN:     dnsInstanceCRN,
		Region:             region,
		ServiceGUID:        serviceInstanceGUID,
		VPCRegion:          vpcRegion,
		Zone:               zone,
		pendingItemTracker: newPendingItemTracker(),
		resourceGroupID:    resourceGroupID,
	}, nil
}

// Run is the entrypoint to start the uninstall process.
func (o *ClusterUninstaller) Run() (error) {
	o.Logger.Debugf("powervs.Run")

	var ctx context.Context
	var deadline time.Time
	var ok bool
	var err error

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	if ctx == nil {
		return errors.Wrap(err, "powervs.Run: contextWithTimeout returns nil")
	}

	deadline, ok = ctx.Deadline()
	if !ok {
		return errors.Wrap(err, "powervs.Run: failed to call ctx.Deadline")
	}

	var duration time.Duration = deadline.Sub(time.Now())

	o.Logger.Debugf("powervs.Run: duration = %v", duration)

	if duration <= 0 {
		return fmt.Errorf("powervs.Run: duration is <= 0 (%v)", duration)
	}

	err = wait.PollImmediateInfinite(
		duration,
		o.PolledRun,
	)

	o.Logger.Debugf("powervs.Run: after wait.PollImmediateInfinite, err = %v", err)

	return err
}

// PolledRun is the Run function which will be called with Polling.
func (o *ClusterUninstaller) PolledRun() (bool, error) {
	o.Logger.Debugf("powervs.PolledRun")

	var err error

	err = o.loadSDKServices()
	if err != nil {
		o.Logger.Debugf("powervs.PolledRun: Failed loadSDKServices")
		return false, err
	}

	err = o.destroyCluster()
	if err != nil {
		o.Logger.Debugf("powervs.PolledRun: Failed destroyCluster")
		return false, errors.Wrap(err, "failed to destroy cluster")
	}

	return true, nil
}

func (o *ClusterUninstaller) destroyCluster() error {
	stagedFuncs := [][]struct {
		name    string
		execute func() error
	}{{
		{name: "Cloud Instances", execute: o.destroyCloudInstances},
	}, {
		{name: "Power Instances", execute: o.destroyPowerInstances},
	}, {
		{name: "Load Balancers", execute: o.destroyLoadBalancers},
	}, {
		{name: "Subnets", execute: o.destroySubnets},
	}, {
		{name: "Public Gateways", execute: o.destroyPublicGateways},
	}, {
		{name: "DHCPs", execute: o.destroyDHCPNetworks},
	}, {
		{name: "Images", execute: o.destroyImages},
		{name: "Security Groups", execute: o.destroySecurityGroups},
	}, {
		{name: "VPC Cloud Connections", execute: o.destroyVPCInCloudConnections},
	}, {
		{name: "Cloud Connections", execute: o.destroyCloudConnections},
	}, {
		{name: "Networks", execute: o.destroyNetworks},
	}, {
		{name: "VPCs", execute: o.destroyVPCs},
	}, {
		{name: "Cloud Object Storage Instances", execute: o.destroyCOSInstances},
		{name: "DNS Records", execute: o.destroyDNSRecords},
		{name: "Cloud SSH Keys", execute: o.destroyCloudSSHKeys},
		{name: "Power SSH Keys", execute: o.destroyPowerSSHKeys},
	}, {
		{name: "Service Instances", execute: o.destroyServiceInstances},
	}}

	for _, stage := range stagedFuncs {
		var wg sync.WaitGroup
		errCh := make(chan error)
		wgDone := make(chan bool)

		for _, f := range stage {
			wg.Add(1)
			// Start a parallel goroutine
			go o.executeStageFunction(f, errCh, &wg)
		}

		// Start a parallel goroutine
		go func() {
			wg.Wait()
			close(wgDone)
		}()

		select {
		// Did the wait group goroutine finish?
		case <-wgDone:
			// On to the next stage
			o.Logger.Debugf("destroyCluster: <-wgDone")
			continue
		// Have we taken too long?
		case <-time.After(stageTimeout):
			return fmt.Errorf("destroyCluster: timed out")
		// Has an error been sent via the channel?
		case err := <-errCh:
			return err
		}
	}

	return nil
}

func (o *ClusterUninstaller) executeStageFunction(f struct {
	name    string
	execute func() error
}, errCh chan error, wg *sync.WaitGroup) error {
	o.Logger.Debugf("executeStageFunction: Adding: %s", f.name)

	defer wg.Done()

	var ctx context.Context
	var deadline time.Time
	var ok bool
	var err error

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	if ctx == nil {
		return errors.Wrap(err, "executeStageFunction contextWithTimeout returns nil")
	}

	deadline, ok = ctx.Deadline()
	if !ok {
		return errors.Wrap(err, "executeStageFunction failed to call ctx.Deadline")
	}

	var duration time.Duration = deadline.Sub(time.Now())

	o.Logger.Debugf("executeStageFunction: duration = %v", duration)
	if duration <= 0 {
		return fmt.Errorf("executeStageFunction: duration is <= 0 (%v)", duration)
	}

	err = wait.PollImmediateInfinite(
		duration,
		func() (bool, error) {
			var err error

			o.Logger.Debugf("executeStageFunction: Executing: %s", f.name)

			err = f.execute()
			if err != nil {
				o.Logger.Debugf("ERROR: executeStageFunction: %s: %v", f.name, err)

				return false, err
			}

			return true, nil
		},
	)

	if err != nil {
		errCh <- err
	}
	return nil
}

// GetCISInstanceCRN gets the CRN name for the specified base domain.
func GetCISInstanceCRN(BaseDomain string) (string, error) {
	var CISInstanceCRN string = ""
	var APIKey string
	var bxSession *bxsession.Session
	var err error
	var tokenProviderEndpoint string = "https://iam.cloud.ibm.com"
	var tokenRefresher *authentication.IAMAuthRepository
	var authenticator *core.IamAuthenticator
	var controllerSvc *resourcecontrollerv2.ResourceControllerV2
	var listInstanceOptions *resourcecontrollerv2.ListResourceInstancesOptions
	var listResourceInstancesResponse *resourcecontrollerv2.ResourceInstancesList
	var instance resourcecontrollerv2.ResourceInstance
	var zonesService *zonesv1.ZonesV1
	var listZonesOptions *zonesv1.ListZonesOptions
	var listZonesResponse *zonesv1.ListZonesResp

	if APIKey = os.Getenv("IBMCLOUD_API_KEY"); len(APIKey) == 0 {
		return CISInstanceCRN, fmt.Errorf("getCISInstanceCRN: environment variable IBMCLOUD_API_KEY not set")
	}
	bxSession, err = bxsession.New(&bluemix.Config{
		BluemixAPIKey:         APIKey,
		TokenProviderEndpoint: &tokenProviderEndpoint,
		Debug:                 false,
	})
	if err != nil {
		return CISInstanceCRN, fmt.Errorf("getCISInstanceCRN: bxsession.New: %v", err)
	}
	tokenRefresher, err = authentication.NewIAMAuthRepository(bxSession.Config, &rest.Client{
		DefaultHeader: gohttp.Header{
			"User-Agent": []string{http.UserAgent()},
		},
	})
	if err != nil {
		return CISInstanceCRN, fmt.Errorf("getCISInstanceCRN: authentication.NewIAMAuthRepository: %v", err)
	}
	err = tokenRefresher.AuthenticateAPIKey(bxSession.Config.BluemixAPIKey)
	if err != nil {
		return CISInstanceCRN, fmt.Errorf("getCISInstanceCRN: tokenRefresher.AuthenticateAPIKey: %v", err)
	}
	authenticator = &core.IamAuthenticator{
		ApiKey: APIKey,
	}
	err = authenticator.Validate()
	if err != nil {
		return CISInstanceCRN, fmt.Errorf("getCISInstanceCRN: authenticator.Validate: %v", err)
	}
	// Instantiate the service with an API key based IAM authenticator
	controllerSvc, err = resourcecontrollerv2.NewResourceControllerV2(&resourcecontrollerv2.ResourceControllerV2Options{
		Authenticator: authenticator,
		ServiceName:   "cloud-object-storage",
		URL:           "https://resource-controller.cloud.ibm.com",
	})
	if err != nil {
		return CISInstanceCRN, fmt.Errorf("getCISInstanceCRN: creating ControllerV2 Service: %v", err)
	}
	listInstanceOptions = controllerSvc.NewListResourceInstancesOptions()
	listInstanceOptions.SetResourceID(cisServiceID)
	listResourceInstancesResponse, _, err = controllerSvc.ListResourceInstances(listInstanceOptions)
	if err != nil {
		return CISInstanceCRN, fmt.Errorf("getCISInstanceCRN: ListResourceInstances: %v", err)
	}
	for _, instance = range listResourceInstancesResponse.Resources {
		authenticator = &core.IamAuthenticator{
			ApiKey: APIKey,
		}

		err = authenticator.Validate()
		if err != nil {
		}

		zonesService, err = zonesv1.NewZonesV1(&zonesv1.ZonesV1Options{
			Authenticator: authenticator,
			Crn:           instance.CRN,
		})
		if err != nil {
			return CISInstanceCRN, fmt.Errorf("getCISInstanceCRN: NewZonesV1: %v", err)
		}
		listZonesOptions = zonesService.NewListZonesOptions()
		listZonesResponse, _, err = zonesService.ListZones(listZonesOptions)
		if listZonesResponse == nil {
			return CISInstanceCRN, fmt.Errorf("getCISInstanceCRN: ListZones: %v", err)
		}
		for _, zone := range listZonesResponse.Result {
			if *zone.Status == "active" {
				if *zone.Name == BaseDomain {
					CISInstanceCRN = *instance.CRN
				}
			}
		}
	}

	return CISInstanceCRN, nil
}

func (o *ClusterUninstaller) loadSDKServices() error {
	var (
		bxSession             *bxsession.Session
		tokenProviderEndpoint string = "https://iam.cloud.ibm.com"
		tokenRefresher        *authentication.IAMAuthRepository
		err                   error
		ctrlv2                controllerv2.ResourceControllerAPIV2
		resourceClientV2      controllerv2.ResourceServiceInstanceRepository
		serviceInstance       bxmodels.ServiceInstanceV2
	)

	defer func() {
		o.Logger.Debugf("loadSDKServices: bxSession = %v", bxSession)
		o.Logger.Debugf("loadSDKServices: tokenRefresher = %v", tokenRefresher)
		o.Logger.Debugf("loadSDKServices: ctrlv2 = %v", ctrlv2)
		o.Logger.Debugf("loadSDKServices: resourceClientV2 = %v", resourceClientV2)
		o.Logger.Debugf("loadSDKServices: o.ServiceGUID = %v", o.ServiceGUID)
		o.Logger.Debugf("loadSDKServices: serviceInstance = %v", serviceInstance)
		o.Logger.Debugf("loadSDKServices: o.piSession = %v", o.piSession)
		o.Logger.Debugf("loadSDKServices: o.instanceClient = %v", o.instanceClient)
		o.Logger.Debugf("loadSDKServices: o.imageClient = %v", o.imageClient)
		o.Logger.Debugf("loadSDKServices: o.jobClient = %v", o.jobClient)
		o.Logger.Debugf("loadSDKServices: o.keyClient = %v", o.keyClient)
		o.Logger.Debugf("loadSDKServices: o.cloudConnectionClient = %v", o.cloudConnectionClient)
		o.Logger.Debugf("loadSDKServices: o.dhcpClient = %v", o.dhcpClient)
		o.Logger.Debugf("loadSDKServices: o.networkClient = %v", o.networkClient)
		o.Logger.Debugf("loadSDKServices: o.vpcSvc = %v", o.vpcSvc)
		o.Logger.Debugf("loadSDKServices: o.managementSvc = %v", o.managementSvc)
		o.Logger.Debugf("loadSDKServices: o.controllerSvc = %v", o.controllerSvc)
	}()

	if o.APIKey == "" {
		return fmt.Errorf("loadSDKServices: missing APIKey in metadata.json")
	}

	bxSession, err = bxsession.New(&bluemix.Config{
		BluemixAPIKey:         o.APIKey,
		TokenProviderEndpoint: &tokenProviderEndpoint,
		Debug:                 false,
	})
	if err != nil {
		return fmt.Errorf("loadSDKServices: bxsession.New: %v", err)
	}

	tokenRefresher, err = authentication.NewIAMAuthRepository(bxSession.Config, &rest.Client{
		DefaultHeader: gohttp.Header{
			"User-Agent": []string{http.UserAgent()},
		},
	})
	if err != nil {
		return fmt.Errorf("loadSDKServices: authentication.NewIAMAuthRepository: %v", err)
	}
	err = tokenRefresher.AuthenticateAPIKey(bxSession.Config.BluemixAPIKey)
	if err != nil {
		return fmt.Errorf("loadSDKServices: tokenRefresher.AuthenticateAPIKey: %v", err)
	}

	user, err := fetchUserDetails(bxSession, 2)
	if err != nil {
		return fmt.Errorf("loadSDKServices: fetchUserDetails: %v", err)
	}

	ctrlv2, err = controllerv2.New(bxSession)
	if err != nil {
		return fmt.Errorf("loadSDKServices: controllerv2.New: %v", err)
	}

	resourceClientV2 = ctrlv2.ResourceServiceInstanceV2()
	if err != nil {
		return fmt.Errorf("loadSDKServices: ctrlv2.ResourceServiceInstanceV2: %v", err)
	}

	if o.ServiceGUID == "" {
		return fmt.Errorf("loadSDKServices: ServiceGUID is empty")
	}
	o.Logger.Debugf("loadSDKServices: o.ServiceGUID = %v", o.ServiceGUID)

	serviceInstance, err = resourceClientV2.GetInstance(o.ServiceGUID)
	if err != nil {
		return fmt.Errorf("loadSDKServices: resourceClientV2.GetInstance: %v", err)
	}

	region, err := GetRegion(serviceInstance.RegionID)
	if err != nil {
		return fmt.Errorf("loadSDKServices: GetRegion: %v", err)
	}

	var authenticator core.Authenticator = &core.IamAuthenticator{
		ApiKey: o.APIKey,
	}

	err = authenticator.Validate()
	if err != nil {
		return fmt.Errorf("loadSDKServices: loadSDKServices: authenticator.Validate: %v", err)
	}

	var options *ibmpisession.IBMPIOptions = &ibmpisession.IBMPIOptions{
		Authenticator: authenticator,
		Debug:         false,
		Region:        region,
		UserAccount:   user.Account,
		Zone:          serviceInstance.RegionID,
	}

	o.piSession, err = ibmpisession.NewIBMPISession(options)
	if (err != nil) || (o.piSession == nil) {
		if err != nil {
			return fmt.Errorf("loadSDKServices: ibmpisession.New: %v", err)
		}
		return fmt.Errorf("loadSDKServices: loadSDKServices: o.piSession is nil")
	}

	o.instanceClient = instance.NewIBMPIInstanceClient(context.Background(), o.piSession, o.ServiceGUID)
	if o.instanceClient == nil {
		return fmt.Errorf("loadSDKServices: loadSDKServices: o.instanceClient is nil")
	}

	o.imageClient = instance.NewIBMPIImageClient(context.Background(), o.piSession, o.ServiceGUID)
	if o.imageClient == nil {
		return fmt.Errorf("loadSDKServices: loadSDKServices: o.imageClient is nil")
	}

	o.jobClient = instance.NewIBMPIJobClient(context.Background(), o.piSession, o.ServiceGUID)
	if o.jobClient == nil {
		return fmt.Errorf("loadSDKServices: loadSDKServices: o.jobClient is nil")
	}

	o.keyClient = instance.NewIBMPIKeyClient(context.Background(), o.piSession, o.ServiceGUID)
	if o.keyClient == nil {
		return fmt.Errorf("loadSDKServices: loadSDKServices: o.keyClient is nil")
	}

	o.cloudConnectionClient = instance.NewIBMPICloudConnectionClient(context.Background(), o.piSession, o.ServiceGUID)
	if o.cloudConnectionClient == nil {
		return fmt.Errorf("loadSDKServices: loadSDKServices: o.cloudConnectionClient is nil")
	}

	o.dhcpClient = instance.NewIBMPIDhcpClient(context.Background(), o.piSession, o.ServiceGUID)
	if o.dhcpClient == nil {
		return fmt.Errorf("loadSDKServices: loadSDKServices: o.dhcpClient is nil")
	}

	o.networkClient = instance.NewIBMPINetworkClient(context.Background(), o.piSession, o.ServiceGUID)
	if o.networkClient == nil {
		return fmt.Errorf("loadSDKServices: loadSDKServices: o.networkClient is nil")
	}

	authenticator = &core.IamAuthenticator{
		ApiKey: o.APIKey,
	}

	err = authenticator.Validate()
	if err != nil {
		return fmt.Errorf("loadSDKServices: loadSDKServices: authenticator.Validate: %v", err)
	}

	// https://raw.githubusercontent.com/IBM/vpc-go-sdk/master/vpcv1/vpc_v1.go
	o.vpcSvc, err = vpcv1.NewVpcV1(&vpcv1.VpcV1Options{
		Authenticator: authenticator,
		URL:           "https://" + o.VPCRegion + ".iaas.cloud.ibm.com/v1",
	})
	if err != nil {
		return fmt.Errorf("loadSDKServices: loadSDKServices: vpcv1.NewVpcV1: %v", err)
	}

	userAgentString := fmt.Sprintf("OpenShift/4.x Destroyer/%s", version.Raw)
	o.vpcSvc.Service.SetUserAgent(userAgentString)

	authenticator = &core.IamAuthenticator{
		ApiKey: o.APIKey,
	}

	err = authenticator.Validate()
	if err != nil {
	}

	// Instantiate the service with an API key based IAM authenticator
	o.managementSvc, err = resourcemanagerv2.NewResourceManagerV2(&resourcemanagerv2.ResourceManagerV2Options{
		Authenticator: authenticator,
	})
	if err != nil {
		return fmt.Errorf("loadSDKServices: loadSDKServices: creating ResourceManagerV2 Service: %v", err)
	}

	authenticator = &core.IamAuthenticator{
		ApiKey: o.APIKey,
	}

	err = authenticator.Validate()
	if err != nil {
	}

	// Instantiate the service with an API key based IAM authenticator
	o.controllerSvc, err = resourcecontrollerv2.NewResourceControllerV2(&resourcecontrollerv2.ResourceControllerV2Options{
		Authenticator: authenticator,
		ServiceName:   "cloud-object-storage",
		URL:           "https://resource-controller.cloud.ibm.com",
	})
	if err != nil {
		return fmt.Errorf("loadSDKServices: loadSDKServices: creating ControllerV2 Service: %v", err)
	}

	// Either CISInstanceCRN is set or DNSInstanceCRN is set. Both should not be set at the same time,
	// but check both just to be safe.
	if len(o.CISInstanceCRN) > 0 {
		authenticator = &core.IamAuthenticator{
			ApiKey: o.APIKey,
		}

		err = authenticator.Validate()
		if err != nil {
		}

		o.zonesSvc, err = zonesv1.NewZonesV1(&zonesv1.ZonesV1Options{
			Authenticator: authenticator,
			Crn:           &o.CISInstanceCRN,
		})
		if err != nil {
			return fmt.Errorf("loadSDKServices: loadSDKServices: creating zonesSvc: %v", err)
		}

		ctx, cancel := o.contextWithTimeout()
		defer cancel()

		// Get the Zone ID
		zoneOptions := o.zonesSvc.NewListZonesOptions()
		zoneResources, detailedResponse, err := o.zonesSvc.ListZonesWithContext(ctx, zoneOptions)
		if err != nil {
			return fmt.Errorf("loadSDKServices: loadSDKServices: Failed to list Zones: %v and the response is: %s", err, detailedResponse)
		}

		for _, zone := range zoneResources.Result {
			o.Logger.Debugf("loadSDKServices: Zone: %v", *zone.Name)
			if strings.Contains(o.BaseDomain, *zone.Name) {
				o.dnsZoneID = *zone.ID
			}
		}
		o.dnsRecordsSvc, err = dnsrecordsv1.NewDnsRecordsV1(&dnsrecordsv1.DnsRecordsV1Options{
			Authenticator:  authenticator,
			Crn:            &o.CISInstanceCRN,
			ZoneIdentifier: &o.dnsZoneID,
		})
		if err != nil {
			return fmt.Errorf("loadSDKServices: loadSDKServices: Failed to instantiate dnsRecordsSvc: %v", err)
		}
	}

	if len(o.DNSInstanceCRN) > 0 {
		authenticator = &core.IamAuthenticator{
			ApiKey: o.APIKey,
		}

		err = authenticator.Validate()
		if err != nil {
		}

		o.dnsZonesSvc, err = dnszonesv1.NewDnsZonesV1(&dnszonesv1.DnsZonesV1Options{
			Authenticator: authenticator,
		})
		if err != nil {
			return fmt.Errorf("loadSDKServices: loadSDKServices: creating zonesSvc: %v", err)
		}

		// Get the Zone ID
		dnsCRN, err := crn.Parse(o.DNSInstanceCRN)
		if err != nil {
			return errors.Wrap(err, "Failed to parse DNSInstanceCRN")
		}
		options := o.dnsZonesSvc.NewListDnszonesOptions(dnsCRN.ServiceInstance)
		listZonesResponse, detailedResponse, err := o.dnsZonesSvc.ListDnszones(options)
		if err != nil {
			return fmt.Errorf("loadSDKServices: loadSDKServices: Failed to list Zones: %v and the response is: %s", err, detailedResponse)
		}

		for _, zone := range listZonesResponse.Dnszones {
			o.Logger.Debugf("loadSDKServices: Zone: %v", *zone.Name)
			if strings.Contains(o.BaseDomain, *zone.Name) {
				o.dnsZoneID = *zone.ID
			}
		}

		o.resourceRecordsSvc, err = resourcerecordsv1.NewResourceRecordsV1(&resourcerecordsv1.ResourceRecordsV1Options{
			Authenticator: authenticator,
		})
		if err != nil {
			return fmt.Errorf("loadSDKServices: loadSDKServices: Failed to instantiate resourceRecordsSvc: %v", err)
		}
	}

	return nil
}

func (o *ClusterUninstaller) contextWithTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(o.Context, defaultTimeout)
}

func (o *ClusterUninstaller) timeout(ctx context.Context) bool {
	var deadline time.Time
	var ok bool

	deadline, ok = ctx.Deadline()
	if !ok {
		o.Logger.Debugf("timeout: deadline, ok = %v, %v", deadline, ok)
		return true
	}

	var after bool = time.Now().After(deadline)

	if after {
		// 01/02 03:04:05PM ‘06 -0700
		o.Logger.Debugf("timeout: after deadline! (%v)", deadline.Format("2006-01-02 03:04:05PM"))
	}

	return after
}

type ibmError struct {
	Status  int
	Message string
}

func isNoOp(err *ibmError) bool {
	if err == nil {
		return false
	}

	return err.Status == gohttp.StatusNotFound
}

// aggregateError is a utility function that takes a slice of errors and an
// optional pending argument, and returns an error or nil.
func aggregateError(errs []error, pending ...int) error {
	err := utilerrors.NewAggregate(errs)
	if err != nil {
		return err
	}
	if len(pending) > 0 && pending[0] > 0 {
		return errors.Errorf("%d items pending", pending[0])
	}
	return nil
}

// pendingItemTracker tracks a set of pending item names for a given type of resource.
type pendingItemTracker struct {
	pendingItems map[string]cloudResources
}

func newPendingItemTracker() pendingItemTracker {
	return pendingItemTracker{
		pendingItems: map[string]cloudResources{},
	}
}

// GetAllPendintItems returns a slice of all of the pending items across all types.
func (t pendingItemTracker) GetAllPendingItems() []cloudResource {
	var items []cloudResource
	for _, is := range t.pendingItems {
		for _, i := range is {
			items = append(items, i)
		}
	}
	return items
}

// getPendingItems returns the list of resources to be deleted.
func (t pendingItemTracker) getPendingItems(itemType string) []cloudResource {
	lastFound, exists := t.pendingItems[itemType]
//	log.Debugf("getPendingItems: lastFound = %+v, exists = %v", lastFound, exists)
	if !exists {
		lastFound = cloudResources{}
	}
	return lastFound.list()
}

// insertPendingItems adds to the list of resources to be deleted.
func (t pendingItemTracker) insertPendingItems(itemType string, items []cloudResource) []cloudResource {
	lastFound, exists := t.pendingItems[itemType]
//	log.Debugf("insertPendingItems: lastFound = %+v, exists = %v", lastFound, exists)
	if !exists {
		lastFound = cloudResources{}
	}
	lastFound = lastFound.insert(items...)
	t.pendingItems[itemType] = lastFound
//	l := lastFound.list()
//	log.Debugf("insertPendingItems: l = %+v", l)
//	return l
	return lastFound.list()
}

// deletePendingItems removes from the list of resources to be deleted.
func (t pendingItemTracker) deletePendingItems(itemType string, items []cloudResource) []cloudResource {
	lastFound, exists := t.pendingItems[itemType]
//	log.Debugf("deletePendingItems: lastFound = %+v, exists = %v", lastFound, exists)
	if !exists {
		lastFound = cloudResources{}
	}
	lastFound = lastFound.delete(items...)
	t.pendingItems[itemType] = lastFound
//	l := lastFound.list()
//	log.Debugf("deletePendingItems: l = %+v", l)
//	return l
	return lastFound.list()
}

func isErrorStatus(code int64) bool {
	return code != 0 && (code < 200 || code >= 300)
}

// Since there is no API to query these, we have to hard-code them here.

// Region describes resources associated with a region in Power VS.
// We're using a few items from the IBM Cloud VPC offering. The region names
// for VPC are different so another function of this is to correlate those.
type Region struct {
	Description string
	VPCRegion   string
	Zones       []string
}

// Regions holds the regions for IBM Power VS, and descriptions used during the survey.
var Regions = map[string]Region{
	"dal": {
		Description: "Dallas, USA",
		VPCRegion:   "us-south",
		Zones:       []string{"dal12"},
	},
	"eu-de": {
		Description: "Frankfurt, Germany",
		VPCRegion:   "eu-de",
		Zones: []string{
			"eu-de-1",
			"eu-de-2",
		},
	},
	"lon": {
		Description: "London, UK.",
		VPCRegion:   "eu-gb",
		Zones: []string{
			"lon04",
			"lon06",
		},
	},
	"osa": {
		Description: "Osaka, Japan",
		VPCRegion:   "jp-osa",
		Zones:       []string{"osa21"},
	},
	"syd": {
		Description: "Sydney, Australia",
		VPCRegion:   "au-syd",
		Zones:       []string{
			"syd04",
			"syd05",
		},
	},
	"mon": {
		Description: "Montreal, Canada",
		VPCRegion:   "ca-tor",
		Zones:       []string{"mon01"},
	},
	"sao": {
		Description: "São Paulo, Brazil",
		VPCRegion:   "br-sao",
		Zones:       []string{"sao01"},
	},
	"tor": {
		Description: "Toronto, Canada",
		VPCRegion:   "ca-tor",
		Zones:       []string{"tor01"},
	},
	"tok": {
		Description: "Tokyo, Japan",
		VPCRegion:   "jp-tok",
		Zones:       []string{"tok04"},
	},
	"us-east": {
		Description: "Washington DC, USA",
		VPCRegion:   "us-east",
		Zones:       []string{"us-east"},
	},
}

// VPCRegionForPowerVSRegion returns the VPC region for the specified PowerVS region.
func VPCRegionForPowerVSRegion(region string) (string, error) {
	if r, ok := Regions[region]; ok {
		return r.VPCRegion, nil
	}

	return "", fmt.Errorf("VPC region corresponding to a PowerVS region %s not found ", region)
}

// VPCRegionForPowerVSZone returns the VPC region for the specified PowerVS zone.
func VPCRegionForPowerVSZone(zone string) (string, error) {
	for _, currentRegion := range Regions {
		for _, currentZone := range currentRegion.Zones {
			if currentZone == zone {
				return currentRegion.VPCRegion, nil
			}
		}
	}

	return "", fmt.Errorf("VPC region corresponding to a PowerVS zone %s not found ", zone)
}

type PowerVSStruct struct {
	CISInstanceCRN string `json:"cisInstanceCRN"`
	DNSInstanceCRN string `json:"dnsInstanceCRN"`
	Region         string `json:"region"`
	Zone           string `json:"zone"`
}
type Metadata struct {
	ClusterName string `json:"ClusterName"`
	ClusterID   string `json:"ClusterID"`
	InfraID     string `json:"InfraID"`
	PowerVS *PowerVSStruct
}

func readMetadata(fileName string) (*Metadata, error) {
	var data = Metadata{}
	var err error

	file, err := ioutil.ReadFile(fileName)
	if err != nil {
		return &data, fmt.Errorf("Error: ReadFile returns %v", err)
	}

	err = json.Unmarshal([]byte(file), &data)
	if err != nil {
		return &data, fmt.Errorf("Error: Unmarshal returns %v", err)
	}

	return &data, nil
}

func GetNext(next interface{}) string {

	if reflect.ValueOf(next).IsNil() {
		return ""
	}

	u, err := url.Parse(reflect.ValueOf(next).Elem().FieldByName("Href").Elem().String())
	if err != nil {
		return ""
	}

	q := u.Query()
	return q.Get("start")

}

func getServiceGuid(ptrApiKey *string, ptrZone *string, ptrServiceName *string) (string, error) {

	var bxSession *bxsession.Session
	var tokenProviderEndpoint string = "https://iam.cloud.ibm.com"
	var err error
	var serviceGuid string = ""

	bxSession, err = bxsession.New(&bluemix.Config{
		BluemixAPIKey:         *ptrApiKey,
		TokenProviderEndpoint: &tokenProviderEndpoint,
		Debug:                 false,
	})
	if err != nil {
		return "", fmt.Errorf("Error bxsession.New: %v", err)
	}
	log.Printf("bxSession = %+v", bxSession)

	tokenRefresher, err := authentication.NewIAMAuthRepository(bxSession.Config, &rest.Client{
		DefaultHeader: gohttp.Header{
			"User-Agent": []string{http.UserAgent()},
		},
	})
	if err != nil {
		return "", fmt.Errorf("Error authentication.NewIAMAuthRepository: %v", err)
	}
	log.Printf("tokenRefresher = %+v", tokenRefresher)
	err = tokenRefresher.AuthenticateAPIKey(bxSession.Config.BluemixAPIKey)
	if err != nil {
		return "", fmt.Errorf("Error tokenRefresher.AuthenticateAPIKey: %v", err)
	}

	ctrlv2, err := controllerv2.New(bxSession)
	if err != nil {
		return "", fmt.Errorf("Error controllerv2.New: %v", err)
	}
	log.Printf("ctrlv2 = %+v", ctrlv2)

	resourceClientV2 := ctrlv2.ResourceServiceInstanceV2()
	if err != nil {
		return "", fmt.Errorf("Error ctrlv2.ResourceServiceInstanceV2: %v", err)
	}
	log.Printf("resourceClientV2 = %+v", resourceClientV2)

	svcs, err := resourceClientV2.ListInstances(controllerv2.ServiceInstanceQuery{
		Type: "service_instance",
	})
	if err != nil {
		return "", fmt.Errorf("Error resourceClientV2.ListInstances: %v", err)
	}

	for _, svc := range svcs {
		log.Printf("Guid = %v", svc.Guid)
		log.Printf("RegionID = %v", svc.RegionID)
		log.Printf("Name = %v", svc.Name)
		log.Printf("Crn = %v", svc.Crn)
		if (ptrServiceName != nil) && (svc.Name == *ptrServiceName) {
			serviceGuid = svc.Guid
			break
		}
		if (ptrZone != nil) && (svc.RegionID == *ptrZone) {
			serviceGuid = svc.Guid
			break
		}
	}

	if serviceGuid == "" {
		return "", fmt.Errorf("%s not found in list of service instances!", *ptrServiceName)
	} else {
		return serviceGuid, nil
	}

}

func createPiSession(ptrApiKey *string, serviceGuid string, ptrZone *string, ptrServiceName *string) (*ibmpisession.IBMPISession, error) {

	var bxSession *bxsession.Session
	var tokenProviderEndpoint string = "https://iam.cloud.ibm.com"
	var err error

	bxSession, err = bxsession.New(&bluemix.Config{
		BluemixAPIKey:         *ptrApiKey,
		TokenProviderEndpoint: &tokenProviderEndpoint,
		Debug:                 false,
	})
	if err != nil {
		return nil, fmt.Errorf("Error bxsession.New: %v", err)
	}
	log.Printf("bxSession = %+v", bxSession)

	tokenRefresher, err := authentication.NewIAMAuthRepository(bxSession.Config, &rest.Client{
		DefaultHeader: gohttp.Header{
			"User-Agent": []string{http.UserAgent()},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("Error authentication.NewIAMAuthRepository: %v", err)
	}
	log.Printf("tokenRefresher = %+v", tokenRefresher)
	err = tokenRefresher.AuthenticateAPIKey(bxSession.Config.BluemixAPIKey)
	if err != nil {
		return nil, fmt.Errorf("Error tokenRefresher.AuthenticateAPIKey: %v", err)
	}

	user, err := fetchUserDetails(bxSession, 2)
	if err != nil {
		return nil, fmt.Errorf("Error fetchUserDetails: %v", err)
	}

	ctrlv2, err := controllerv2.New(bxSession)
	if err != nil {
		return nil, fmt.Errorf("Error controllerv2.New: %v", err)
	}
	log.Printf("ctrlv2 = %+v", ctrlv2)

	resourceClientV2 := ctrlv2.ResourceServiceInstanceV2()
	if err != nil {
		return nil, fmt.Errorf("Error ctrlv2.ResourceServiceInstanceV2: %v", err)
	}
	log.Printf("resourceClientV2 = %+v", resourceClientV2)

	serviceInstance, err := resourceClientV2.GetInstance(serviceGuid)
	if err != nil {
		return nil, fmt.Errorf("Error resourceClientV2.GetInstance: %v", err)
	}
	log.Printf("serviceInstance = %+v", serviceInstance)

	region, err:= GetRegion(serviceInstance.RegionID)
	if err != nil {
		return nil, fmt.Errorf("Error GetRegion: %v", err)
	}

	var authenticator core.Authenticator = &core.IamAuthenticator{
		ApiKey: *ptrApiKey,
	}

	var options *ibmpisession.IBMPIOptions = &ibmpisession.IBMPIOptions{
		Authenticator: authenticator,
		Debug:         false,
		Region:        region,
		UserAccount:   user.Account,
		Zone:          serviceInstance.RegionID,
	}

	var piSession *ibmpisession.IBMPISession

	piSession, err = ibmpisession.NewIBMPISession(options)
	if err != nil {
		return nil, fmt.Errorf("Error ibmpisession.New: %v", err)
	}
	log.Printf("piSession = %+v", piSession)

	return piSession, nil

}

func main() {

	var logMain *logrus.Logger = &logrus.Logger{
		Out: os.Stderr,
		Formatter: new(logrus.TextFormatter),
		Level: logrus.DebugLevel,
	}

	var data *Metadata = nil
	var err error

//{
//	"clusterName":"rdr-hamzy-test"
//	"clusterID":"55f0b68e-de46-4088-a883-736538acbfdc"
//	"infraID":"rdr-hamzy-test-zq782",
//	"powervs":{
//		"cisInstanceCRN":"crn:v1:bluemix:public:internet-svcs:global:a/65b64c1f1c29460e8c2e4bbfbd893c2c:453c4cff-2ee0-4309-95f1-2e9384d9bb96::",
//		"region":"syd",
//		"zone":"syd05"
//	}
//}

	// CLI parameters:
	var ptrMetadaFilename *string
	var ptrShouldDebug *string
	var ptrShouldDelete *string
	var ptrShouldDeleteDHCP *string

	var ptrApiKey *string
	var ptrBaseDomain *string
	var ptrServiceInstanceGUID *string
	var ptrClusterName *string		// In metadata.json
	var ptrInfraID *string			// In metadata.json
	var ptrCISInstanceCRN *string		// In metadata.json
	var ptrDNSInstanceCRN *string		// In metadata.json
	var ptrRegion *string			// In metadata.json
	var ptrZone *string			// In metadata.json
	var ptrResourceGroupID *string

	var shouldDebug = false

	var needAPIKey = true
	var needBaseDomain = true
	var needServiceInstanceGUID = true
	var needClusterName = true
	var needInfraID = true
	var needCISInstanceCRN = true
	var needDNSInstanceCRN = true
	var needRegion = true
	var needZone = true
	var needResourceGroupID = true

	ptrMetadaFilename = flag.String("metadata", "", "The filename containing cluster metadata")
	ptrShouldDebug = flag.String("shouldDebug", "false", "Should output debug output")
	ptrShouldDelete = flag.String("shouldDelete", "false", "Should delete matching records")
	ptrShouldDeleteDHCP = flag.String("shouldDeleteDHCP", "false", "Should delete all DHCP records")

	ptrApiKey = flag.String("apiKey", "", "Your IBM Cloud API key")
	ptrBaseDomain = flag.String("baseDomain", "", "The DNS zone Ex: scnl-ibm.com")
	ptrServiceInstanceGUID = flag.String("serviceInstanceGUID", "", "The GUID of the service instance")
	ptrClusterName = flag.String("clusterName", "", "The cluster name")
	ptrInfraID = flag.String("infraID", "", "The infra ID")
	ptrCISInstanceCRN = flag.String("CISInstanceCRN", "", "ibmcloud cis instances --output json | jq -r '.[] | select (.name|test(\"powervs-ipi-cis\")) | .crn'")
	ptrDNSInstanceCRN = flag.String("DNSInstanceCRN", "", "ibmcloud cis instances --output json | jq -r '.[] | select (.name|test(\"powervs-ipi-cis\")) | .crn'")
	ptrRegion = flag.String("region", "", "The region to use")
	ptrZone = flag.String("zone", "", "The zone to use")
	ptrResourceGroupID = flag.String("resourceGroupID", "", "The resource group to use")

	flag.Parse()

	switch strings.ToLower(*ptrShouldDebug) {
	case "true":
		shouldDebug = true
	case "false":
		shouldDebug = false
	default:
		logMain.Fatalf("Error: shouldDebug is not true/false (%s)", *ptrShouldDebug)
	}

	var out io.Writer

	if shouldDebug {
		out = os.Stderr
	} else {
		out = io.Discard
	}
	log = &logrus.Logger{
		Out: out,
		Formatter: new(logrus.TextFormatter),
		Level: logrus.DebugLevel,
	}

	if shouldDebug {
		logMain.Printf("ptrMetadaFilename      = %v", *ptrMetadaFilename)
		logMain.Printf("ptrShouldDebug         = %v", *ptrShouldDebug)
		logMain.Printf("ptrShouldDelete        = %v", *ptrShouldDelete)
		logMain.Printf("ptrShouldDeleteDHCP    = %v", *ptrShouldDeleteDHCP)
		logMain.Printf("ptrApiKey              = %v", *ptrApiKey)
		logMain.Printf("ptrBaseDomain          = %v", *ptrBaseDomain)
		logMain.Printf("ptrServiceInstanceGUID = %v", *ptrServiceInstanceGUID)
		logMain.Printf("ptrClusterName         = %v", *ptrClusterName)
		logMain.Printf("ptrInfraID             = %v", *ptrInfraID)
		logMain.Printf("ptrCISInstanceCRN      = %v", *ptrCISInstanceCRN)
		logMain.Printf("ptrDNSInstanceCRN      = %v", *ptrDNSInstanceCRN)
		logMain.Printf("ptrRegion              = %v", *ptrRegion)
		logMain.Printf("ptrZone                = %v", *ptrZone)
		logMain.Printf("ptrResourceGroupID     = %v", *ptrResourceGroupID)
	}

	switch strings.ToLower(*ptrShouldDeleteDHCP) {
	case "true":
		shouldDeleteDHCP = true
	case "false":
		shouldDeleteDHCP = false
	default:
		logMain.Fatalf("Error: shouldDeleteDHCP is not true/false (%s)", *ptrShouldDeleteDHCP)
	}

	if *ptrMetadaFilename != "" {
		data, err = readMetadata(*ptrMetadaFilename)
		if err != nil {
			logMain.Fatal(err)
		}

		if shouldDebug {
			logMain.Printf("ClusterName    = %v", data.ClusterName)
			logMain.Printf("ClusterID      = %v", data.ClusterID)
			logMain.Printf("InfraID        = %v", data.InfraID)
			logMain.Printf("CISInstanceCRN = %v", data.PowerVS.CISInstanceCRN)
			logMain.Printf("DNSInstanceCRN = %v", data.PowerVS.DNSInstanceCRN)
			logMain.Printf("Region         = %v", data.PowerVS.Region)
			logMain.Printf("Zone           = %v", data.PowerVS.Zone)
		}

		// Handle:
		// {
		//   "clusterName": "rdr-hamzy-test",
		//   "clusterID": "ffbb8a77-1ae7-445b-83ad-44cae63a8679",
		//   "infraID": "rdr-hamzy-test-rwmtj",
		//   "powervs": {
		//     "cisInstanceCRN": "crn:v1:bluemix:public:internet-svcs:global:a/65b64c1f1c29460e8c2e4bbfbd893c2c:453c4cff-2ee0-4309-95f1-2e9384d9bb96::",
		//     "region": "lon",
		//     "zone": "lon04"
		//   }
		// }

		ptrInfraID = &data.InfraID
		needInfraID = false

		ptrCISInstanceCRN= &data.PowerVS.CISInstanceCRN
		needCISInstanceCRN = false

		ptrDNSInstanceCRN= &data.PowerVS.DNSInstanceCRN
		needDNSInstanceCRN = false

		ptrRegion = &data.PowerVS.Region
		needRegion = false

		ptrZone = &data.PowerVS.Zone
		needZone = false
	}
	if needAPIKey && *ptrApiKey == "" {
		logMain.Fatal("Error: No API key set, use -apiKey")
	}
	if needBaseDomain && *ptrBaseDomain == "" {
		logMain.Fatal("Error: No base domain set, use -baseDomain")
	}
	if needServiceInstanceGUID && *ptrServiceInstanceGUID == "" {
		logMain.Fatal("Error: No service instance GUID set, use -serviceInstanceGUID")
	}
	if needClusterName && *ptrClusterName == "" {
		logMain.Fatal("Error: No cluster name set, use -clusterName")
	}
	if needInfraID && *ptrInfraID == "" {
		logMain.Fatal("Error: No Infra ID set, use -infraID")
	}
	if *ptrCISInstanceCRN != "" {
		needDNSInstanceCRN = false
	}
	if *ptrDNSInstanceCRN != "" {
		needCISInstanceCRN = false
	}
	if needCISInstanceCRN && *ptrCISInstanceCRN == "" {
		logMain.Fatal("Error: No CISInstanceCRN set, use -CISInstanceCRN")
	}
	if needDNSInstanceCRN && *ptrDNSInstanceCRN == "" {
		logMain.Fatal("Error: No DNSInstanceCRN set, use -DNSInstanceCRN")
	}
	if needRegion && *ptrRegion == "" {
		logMain.Fatal("Error: No region set, use -region")
	}
	if needZone && *ptrZone == "" {
		logMain.Fatal("Error: No zone set, use -zone")
	}
	if needResourceGroupID && *ptrResourceGroupID == "" {
		logMain.Fatal("Error: No resource group ID set, use -resourceGroupID")
	}
	switch strings.ToLower(*ptrShouldDelete) {
	case "true":
		shouldDelete = true
	case "false":
		shouldDelete = false
	default:
		logMain.Fatalf("Error: shouldDelete is not true/false (%s)", *ptrShouldDelete)
	}

	var clusterUninstaller *ClusterUninstaller

	clusterUninstaller, err = New (log,
		*ptrApiKey,
		*ptrBaseDomain,
		*ptrServiceInstanceGUID,
		*ptrClusterName,
		*ptrInfraID,
		*ptrCISInstanceCRN,
		*ptrDNSInstanceCRN,
		*ptrRegion,
		*ptrZone,
		*ptrResourceGroupID)
	if err != nil {
		logMain.Fatalf("Error New: %v", err)
	}
	if shouldDebug { logMain.Printf("clusterUninstaller = %+v", clusterUninstaller) }

	err = clusterUninstaller.Run ()
	if err != nil {
		logMain.Fatalf("Error clusterUninstaller.Run: %v", err)
	}

}
___EOF___

hash go || exit 1
(
	cd ${SCRIPT_DIR}
	rm go.*
	go mod init example/user/destroy-cluster3
	go mod tidy
	go build
)
