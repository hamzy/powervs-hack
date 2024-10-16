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


// listCloudConnections lists cloud connections in the cloud.
func (o *ClusterUninstaller) listCloudConnections() (cloudResources, error) {
	// https://github.com/IBM-Cloud/power-go-client/blob/v1.0.88/power/models/cloud_connections.go#L20-L25
	var cloudConnections *models.CloudConnections

	// https://github.com/IBM-Cloud/power-go-client/blob/v1.0.88/power/models/cloud_connection.go#L20-L71
	var cloudConnection *models.CloudConnection

	// https://github.com/IBM-Cloud/power-go-client/blob/v1.0.88/power/models/job_reference.go#L18-L27
	var jobReference *models.JobReference

	var err error

	o.Logger.Debugf("Listing Cloud Connections")

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("listCloudConnections: case <-ctx.Done()")
		return nil, o.Context.Err() // we're cancelled, abort
	default:
	}

	cloudConnections, err = o.cloudConnectionClient.GetAll()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to list cloud connections")
	}

	var foundOne = false

	result := []cloudResource{}
	for _, cloudConnection = range cloudConnections.CloudConnections {
		if strings.Contains(*cloudConnection.Name, o.InfraID) {
			o.Logger.Debugf("listCloudConnections: FOUND: %s (%s)", *cloudConnection.Name, *cloudConnection.CloudConnectionID)
			foundOne = true

			jobReference, err = o.cloudConnectionClient.Delete(*cloudConnection.CloudConnectionID)
			if err != nil {
				errors.Errorf("Failed to delete cloud connection (%s): %v", *cloudConnection.CloudConnectionID, err)
			}

			o.Logger.Debugf("listCloudConnections: jobReference.ID = %s", *jobReference.ID)

			result = append(result, cloudResource{
				key:      *jobReference.ID,
				name:     *jobReference.ID,
				status:   "",
				typeName: jobTypeName,
				id:       *jobReference.ID,
			})
		}
	}
	if !foundOne {
		o.Logger.Debugf("listCloudConnections: NO matching cloud connections against: %s", o.InfraID)
		for _, cloudConnection = range cloudConnections.CloudConnections {
			o.Logger.Debugf("listCloudConnections: only found cloud connection: %s", *cloudConnection.Name)
		}
	}

	return cloudResources{}.insert(result...), nil
}

// destroyCloudConnections removes all cloud connections that have a name prefixed
// with the cluster's infra ID.
func (o *ClusterUninstaller) destroyCloudConnections() error {
	firstPassList, err := o.listCloudConnections()
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
		case <-ctx.Done():
			o.Logger.Debugf("destroyCloudConnections: case <-ctx.Done()")
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
				o.Logger.Debugf("destroyCloudConnections: deleteJob returns DeleteJobSuccess")
				return true, nil
			case DeleteJobRunning:
				o.Logger.Debugf("destroyCloudConnections: deleteJob returns DeleteJobRunning")
				return false, nil
			case DeleteJobError:
				o.Logger.Debugf("destroyCloudConnections: deleteJob returns DeleteJobError: %v", err2)
				return false, err2
			default:
				return false, errors.Errorf("destroyCloudConnections: deleteJob unknown result enum %v", result)
			}
		})
		if err != nil {
			o.Logger.Fatal("destroyCloudConnections: ExponentialBackoffWithContext (destroy) returns ", err)
		}
	}

	if items = o.getPendingItems(jobTypeName); len(items) > 0 {
		for _, item := range items {
			o.Logger.Debugf("destroyCloudConnections: found %s in pending items", item.name)
		}
		return errors.Errorf("destroyCloudConnections: %d undeleted items pending", len(items))
	}

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func() (bool, error) {
		secondPassList, err2 := o.listCloudConnections()
		if err2 != nil {
			return false, err2
		}
		if len(secondPassList) == 0 {
			// We finally don't see any remaining instances!
			return true, nil
		}
		for _, item := range secondPassList {
			o.Logger.Debugf("destroyCloudConnections: found %s in second pass", item.name)
		}
		return false, nil
	})
	if err != nil {
		o.Logger.Fatal("destroyCloudConnections: ExponentialBackoffWithContext (list) returns ", err)
	}

	return nil
}


const (
	cloudInstanceTypeName = "cloudInstance"
)

// listCloudInstances lists instances in the cloud server.
func (o *ClusterUninstaller) listCloudInstances() (cloudResources, error) {
	o.Logger.Debugf("Listing virtual Cloud service instances")

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	options := o.vpcSvc.NewListInstancesOptions()

	// https://raw.githubusercontent.com/IBM/vpc-go-sdk/master/vpcv1/vpc_v1.go
	resources, _, err := o.vpcSvc.ListInstancesWithContext(ctx, options)
	if err != nil {
		o.Logger.Warnf("Error o.vpcSvc.ListInstancesWithContext: %v", err)
		return nil, err
	}

	var foundOne = false

	result := []cloudResource{}
	for _, instance := range resources.Instances {
		if strings.Contains(*instance.Name, o.InfraID) {
			foundOne = true
			o.Logger.Debugf("listCloudInstances: FOUND: %s, %s, %s", *instance.ID, *instance.Name, *instance.Status)
			result = append(result, cloudResource{
				key:      *instance.ID,
				name:     *instance.Name,
				status:   *instance.Status,
				typeName: cloudInstanceTypeName,
				id:       *instance.ID,
			})
		}
	}
	if !foundOne {
		o.Logger.Debugf("listCloudInstances: NO matching virtual instance against: %s", o.InfraID)
		for _, instance := range resources.Instances {
			o.Logger.Debugf("listCloudInstances: only found virtual instance: %s", *instance.Name)
		}
	}

	return cloudResources{}.insert(result...), nil
}

// destroyCloudInstance deletes a given instance.
func (o *ClusterUninstaller) destroyCloudInstance(item cloudResource) error {
	var (
		ctx                   context.Context
		err                   error
		getInstanceOptions    *vpcv1.GetInstanceOptions
		deleteInstanceOptions *vpcv1.DeleteInstanceOptions
		response              *core.DetailedResponse
	)

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	getInstanceOptions = o.vpcSvc.NewGetInstanceOptions(item.id)

	_, _, err = o.vpcSvc.GetInstanceWithContext(ctx, getInstanceOptions)
	if err != nil {
		o.deletePendingItems(item.typeName, []cloudResource{item})
		o.Logger.Infof("Deleted Cloud Instance %q", item.name)
		return nil
	}

	o.Logger.Debugf("Deleting Cloud instance %q", item.name)

	deleteInstanceOptions = o.vpcSvc.NewDeleteInstanceOptions(item.id)

	response, err = o.vpcSvc.DeleteInstanceWithContext(ctx, deleteInstanceOptions)
	if err != nil {
		o.Logger.Infof("Error: o.vpcSvc.DeleteInstanceWithContext: %q %q", err, response)
		return err
	}

	o.deletePendingItems(item.typeName, []cloudResource{item})
	o.Logger.Infof("Deleted Cloud Instance %q", item.name)

	return nil
}

// destroyCloudInstances searches for Cloud instances that have a name that starts with
// the cluster's infra ID.
func (o *ClusterUninstaller) destroyCloudInstances() error {
	firstPassList, err := o.listCloudInstances()
	if err != nil {
		return err
	}

	if len(firstPassList.list()) == 0 {
		return nil
	}

	items := o.insertPendingItems(cloudInstanceTypeName, firstPassList.list())

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	for _, item := range items {
		select {
		case <-ctx.Done():
			o.Logger.Debugf("destroyCloudInstances: case <-ctx.Done()")
			return o.Context.Err() // we're cancelled, abort
		default:
		}

		backoff := wait.Backoff{
			Duration: 15 * time.Second,
			Factor:   1.1,
			Cap:      leftInContext(ctx),
			Steps:    math.MaxInt32}
		err = wait.ExponentialBackoffWithContext(ctx, backoff, func() (bool, error) {
			err2 := o.destroyCloudInstance(item)
			if err2 == nil {
				return true, err2
			}
			o.errorTracker.suppressWarning(item.key, err2, o.Logger)
			return false, err2
		})
		if err != nil {
			o.Logger.Fatal("destroyCloudInstances: ExponentialBackoffWithContext (destroy) returns ", err)
		}
	}

	if items = o.getPendingItems(cloudInstanceTypeName); len(items) > 0 {
		for _, item := range items {
			o.Logger.Debugf("destroyCloudInstances: found %s in pending items", item.name)
		}
		return errors.Errorf("destroyCloudInstances: %d undeleted items pending", len(items))
	}

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func() (bool, error) {
		secondPassList, err2 := o.listCloudInstances()
		if err2 != nil {
			return false, err2
		}
		if len(secondPassList) == 0 {
			// We finally don't see any remaining instances!
			return true, nil
		}
		for _, item := range secondPassList {
			o.Logger.Debugf("destroyCloudInstances: found %s in second pass", item.name)
		}
		return false, nil
	})
	if err != nil {
		o.Logger.Fatal("destroyCloudInstances: ExponentialBackoffWithContext (list) returns ", err)
	}

	return nil
}


const cosTypeName = "cos instance"

// $ ibmcloud catalog service cloud-object-storage --output json | jq -r '.[].id'
// dff97f5c-bc5e-4455-b470-411c3edbe49c
const cosResourceID = "dff97f5c-bc5e-4455-b470-411c3edbe49c"

// listCOSInstances lists COS service instances.
// ibmcloud resource service-instances --output JSON --service-name cloud-object-storage | jq -r '.[] | select(.name|test("rdr-hamzy.*")) | "\(.name) - \(.id)"'
func (o *ClusterUninstaller) listCOSInstances() (cloudResources, error) {
	o.Logger.Debugf("Listing COS instances")

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	options := o.controllerSvc.NewListResourceInstancesOptions()
	options.SetResourceID(cosResourceID)
	options.SetType("service_instance")

	resources, _, err := o.controllerSvc.ListResourceInstancesWithContext(ctx, options)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to list COS instances")
	}

	var foundOne = false

	result := []cloudResource{}
	for _, instance := range resources.Resources {
		// Match the COS instances created by both the installer and the
		// cluster-image-registry-operator.
		if strings.Contains(*instance.Name, o.InfraID) {
			if !(strings.HasSuffix(*instance.Name, "-cos") ||
				strings.HasSuffix(*instance.Name, "-image-registry")) {
				continue
			}
			foundOne = true
			o.Logger.Debugf("listCOSInstances: FOUND %s %s", *instance.Name, *instance.GUID)
			result = append(result, cloudResource{
				key:      *instance.ID,
				name:     *instance.Name,
				status:   *instance.State,
				typeName: cosTypeName,
				id:       *instance.GUID,
			})
		}
	}
	if !foundOne {
		o.Logger.Debugf("listCOSInstances: NO matching COS instance against: %s", o.InfraID)
		for _, instance := range resources.Resources {
			o.Logger.Debugf("listCOSInstances: only found COS instance: %s", *instance.Name)
		}
	}

	return cloudResources{}.insert(result...), nil
}

func (o *ClusterUninstaller) findReclaimedCOSInstance(item cloudResource) (*resourcecontrollerv2.ResourceInstance, *resourcecontrollerv2.Reclamation) {
	var getReclamationOptions *resourcecontrollerv2.ListReclamationsOptions
	var reclamations *resourcecontrollerv2.ReclamationsList
	var response *core.DetailedResponse
	var err error
	var reclamation resourcecontrollerv2.Reclamation
	var getInstanceOptions *resourcecontrollerv2.GetResourceInstanceOptions
	var cosInstance *resourcecontrollerv2.ResourceInstance

	getReclamationOptions = o.controllerSvc.NewListReclamationsOptions()

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	reclamations, response, err = o.controllerSvc.ListReclamationsWithContext(ctx, getReclamationOptions)
	if err != nil {
		o.Logger.Debugf("Error: ListReclamationsWithContext: %v, response is %v", err, response)
		return nil, nil
	}

	// ibmcloud resource reclamations --output json
	for _, reclamation = range reclamations.Resources {
		getInstanceOptions = o.controllerSvc.NewGetResourceInstanceOptions(*reclamation.ResourceInstanceID)

		cosInstance, response, err = o.controllerSvc.GetResourceInstanceWithContext(ctx, getInstanceOptions)
		if err != nil {
			o.Logger.Debugf("Error: GetResourceInstanceWithContext: %v", err)
			return nil, nil
		}

		if *cosInstance.Name == item.name {
			return cosInstance, &reclamation
		}
	}

	return nil, nil
}

func (o *ClusterUninstaller) destroyCOSInstance(item cloudResource) error {
	var cosInstance *resourcecontrollerv2.ResourceInstance

	cosInstance, _ = o.findReclaimedCOSInstance(item)
	if cosInstance != nil {
		// The resource is gone
		o.deletePendingItems(item.typeName, []cloudResource{item})
		o.Logger.Infof("Deleted COS Instance %q", item.name)
		return nil
	}

	var getOptions *resourcecontrollerv2.GetResourceInstanceOptions
	var response *core.DetailedResponse
	var err error

	getOptions = o.controllerSvc.NewGetResourceInstanceOptions(item.id)

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	_, response, err = o.controllerSvc.GetResourceInstanceWithContext(ctx, getOptions)

	if err != nil && response != nil && response.StatusCode == gohttp.StatusNotFound {
		// The resource is gone
		o.deletePendingItems(item.typeName, []cloudResource{item})
		o.Logger.Infof("Deleted COS Instance %q", item.name)
		return nil
	}
	if err != nil && response != nil && response.StatusCode == gohttp.StatusInternalServerError {
		o.Logger.Infof("destroyCOSInstance: internal server error")
		return nil
	}

	options := o.controllerSvc.NewDeleteResourceInstanceOptions(item.id)
	options.SetRecursive(true)

	response, err = o.controllerSvc.DeleteResourceInstanceWithContext(ctx, options)

	if err != nil && response != nil && response.StatusCode != gohttp.StatusNotFound {
		return errors.Wrapf(err, "failed to delete COS instance %s", item.name)
	}

	var reclamation *resourcecontrollerv2.Reclamation

	cosInstance, reclamation = o.findReclaimedCOSInstance(item)
	if cosInstance != nil {
		var reclamationActionOptions *resourcecontrollerv2.RunReclamationActionOptions

		reclamationActionOptions = o.controllerSvc.NewRunReclamationActionOptions(*reclamation.ID, "reclaim")

		_, response, err = o.controllerSvc.RunReclamationActionWithContext(ctx, reclamationActionOptions)
		if err != nil {
			return errors.Wrapf(err, "failed RunReclamationActionWithContext")
		}
	}

	o.Logger.Infof("Deleted COS Instance %q", item.name)
	o.deletePendingItems(item.typeName, []cloudResource{item})

	return nil
}

// destroyCOSInstances removes the COS service instance resources that have a
// name prefixed with the cluster's infra ID.
func (o *ClusterUninstaller) destroyCOSInstances() error {
	firstPassList, err := o.listCOSInstances()
	if err != nil {
		return err
	}

	if len(firstPassList.list()) == 0 {
		return nil
	}

	items := o.insertPendingItems(cosTypeName, firstPassList.list())

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	for _, item := range items {
		select {
		case <-ctx.Done():
			o.Logger.Debugf("destroyCOSInstances: case <-ctx.Done()")
			return o.Context.Err() // we're cancelled, abort
		default:
		}

		backoff := wait.Backoff{
			Duration: 15 * time.Second,
			Factor:   1.1,
			Cap:      leftInContext(ctx),
			Steps:    math.MaxInt32}
		err = wait.ExponentialBackoffWithContext(ctx, backoff, func() (bool, error) {
			err2 := o.destroyCOSInstance(item)
			if err2 == nil {
				return true, err2
			}
			o.errorTracker.suppressWarning(item.key, err2, o.Logger)
			return false, err2
		})
		if err != nil {
			o.Logger.Fatal("destroyCOSInstances: ExponentialBackoffWithContext (destroy) returns ", err)
		}
	}

	if items = o.getPendingItems(cosTypeName); len(items) > 0 {
		for _, item := range items {
			o.Logger.Debugf("destroyCOSInstances: found %s in pending items", item.name)
		}
		return errors.Errorf("destroyCOSInstances: %d undeleted items pending", len(items))
	}

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func() (bool, error) {
		secondPassList, err2 := o.listCOSInstances()
		if err2 != nil {
			return false, err2
		}
		if len(secondPassList) == 0 {
			// We finally don't see any remaining instances!
			return true, nil
		}
		for _, item := range secondPassList {
			o.Logger.Debugf("destroyCOSInstances: found %s in second pass", item.name)
		}
		return false, nil
	})
	if err != nil {
		o.Logger.Fatal("destroyCOSInstances: ExponentialBackoffWithContext (list) returns ", err)
	}

	return nil
}

// COSInstanceID returns the ID of the Cloud Object Storage service instance
// created by the installer during installation.
func (o *ClusterUninstaller) COSInstanceID() (string, error) {
	if o.cosInstanceID != "" {
		return o.cosInstanceID, nil
	}
	cosInstances, err := o.listCOSInstances()
	if err != nil {
		return "", err
	}
	instanceList := cosInstances.list()
	if len(instanceList) == 0 {
		return "", errors.Errorf("COS instance not found")
	}

	// Locate the installer's COS instance by name.
	for _, instance := range instanceList {
		if instance.name == fmt.Sprintf("%s-cos", o.InfraID) {
			o.cosInstanceID = instance.id
			return instance.id, nil
		}
	}
	return "", errors.Errorf("COS instance not found")
}

// cloudResource hold various fields for any given cloud resource
type cloudResource struct {
	key      string
	name     string
	status   string
	typeName string
	id       string
}

type cloudResources map[string]cloudResource

func (r cloudResources) insert(resources ...cloudResource) cloudResources {
	for _, resource := range resources {
		r[resource.key] = resource
	}
	return r
}

func (r cloudResources) delete(resources ...cloudResource) cloudResources {
	for _, resource := range resources {
		delete(r, resource.key)
	}
	return r
}

func (r cloudResources) list() []cloudResource {
	values := []cloudResource{}
	for _, value := range r {
		values = append(values, value)
	}
	return values
}


const (
	cloudSSHKeyTypeName = "cloudSshKey"
)

// listCloudSSHKeys lists images in the vpc.
func (o *ClusterUninstaller) listCloudSSHKeys() (cloudResources, error) {
	o.Logger.Debugf("Listing Cloud SSHKeys")

	// https://raw.githubusercontent.com/IBM/vpc-go-sdk/master/vpcv1/vpc_v1.go
	var (
		ctx              context.Context
		foundOne         bool  = false
		perPage          int64 = 20
		moreData         bool  = true
		listKeysOptions  *vpcv1.ListKeysOptions
		sshKeyCollection *vpcv1.KeyCollection
		detailedResponse *core.DetailedResponse
		err              error
		sshKey           vpcv1.Key
	)

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("listCloudSSHKeys: case <-ctx.Done()")
		return nil, o.Context.Err() // we're cancelled, abort
	default:
	}

	listKeysOptions = o.vpcSvc.NewListKeysOptions()
	listKeysOptions.SetLimit(perPage)

	result := []cloudResource{}

	for moreData {
		sshKeyCollection, detailedResponse, err = o.vpcSvc.ListKeysWithContext(ctx, listKeysOptions)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to list Cloud ssh keys: %v and the response is: %s", err, detailedResponse)
		}

		for _, sshKey = range sshKeyCollection.Keys {
			if strings.Contains(*sshKey.Name, o.InfraID) {
				foundOne = true
				o.Logger.Debugf("listCloudSSHKeys: FOUND: %v", *sshKey.Name)
				result = append(result, cloudResource{
					key:      *sshKey.Name,
					name:     *sshKey.Name,
					status:   "",
					typeName: cloudSSHKeyTypeName,
					id:       *sshKey.ID,
				})
			}
		}

		if sshKeyCollection.First != nil {
			o.Logger.Debugf("listCloudSSHKeys: First = %v", *sshKeyCollection.First.Href)
		}
		if sshKeyCollection.Limit != nil {
			o.Logger.Debugf("listCloudSSHKeys: Limit = %v", *sshKeyCollection.Limit)
		}
		if sshKeyCollection.Next != nil {
			o.Logger.Debugf("listCloudSSHKeys: Next = %v", *sshKeyCollection.Next.Href)
			listKeysOptions.SetStart(*sshKeyCollection.Next.Href)
		}

		moreData = sshKeyCollection.Next != nil
		o.Logger.Debugf("listCloudSSHKeys: moreData = %v", moreData)
	}
	if !foundOne {
		o.Logger.Debugf("listCloudSSHKeys: NO matching sshKey against: %s", o.InfraID)

		listKeysOptions = o.vpcSvc.NewListKeysOptions()
		listKeysOptions.SetLimit(perPage)
		moreData = true

		for moreData {
			sshKeyCollection, detailedResponse, err = o.vpcSvc.ListKeysWithContext(ctx, listKeysOptions)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to list Cloud ssh keys: %v and the response is: %s", err, detailedResponse)
			}
			for _, sshKey = range sshKeyCollection.Keys {
				o.Logger.Debugf("listCloudSSHKeys: FOUND: %v", *sshKey.Name)
			}
			if sshKeyCollection.First != nil {
				o.Logger.Debugf("listCloudSSHKeys: First = %v", *sshKeyCollection.First.Href)
			}
			if sshKeyCollection.Limit != nil {
				o.Logger.Debugf("listCloudSSHKeys: Limit = %v", *sshKeyCollection.Limit)
			}
			if sshKeyCollection.Next != nil {
				o.Logger.Debugf("listCloudSSHKeys: Next = %v", *sshKeyCollection.Next.Href)
				listKeysOptions.SetStart(*sshKeyCollection.Next.Href)
			}
			moreData = sshKeyCollection.Next != nil
			o.Logger.Debugf("listCloudSSHKeys: moreData = %v", moreData)
		}
	}

	return cloudResources{}.insert(result...), nil
}

// deleteCloudSSHKey deletes a given ssh key.
func (o *ClusterUninstaller) deleteCloudSSHKey(item cloudResource) error {
	var (
		ctx              context.Context
		getKeyOptions    *vpcv1.GetKeyOptions
		deleteKeyOptions *vpcv1.DeleteKeyOptions
		err              error
	)

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("deleteCloudSSHKey: case <-ctx.Done()")
		return o.Context.Err() // we're cancelled, abort
	default:
	}

	getKeyOptions = o.vpcSvc.NewGetKeyOptions(item.id)

	_, _, err = o.vpcSvc.GetKey(getKeyOptions)
	if err != nil {
		o.deletePendingItems(item.typeName, []cloudResource{item})
		o.Logger.Infof("Deleted Cloud SSHKey %q", item.name)
		return nil
	}

	deleteKeyOptions = o.vpcSvc.NewDeleteKeyOptions(item.id)

	_, err = o.vpcSvc.DeleteKeyWithContext(ctx, deleteKeyOptions)
	if err != nil {
		return errors.Wrapf(err, "failed to delete sshKey %s", item.name)
	}

	o.Logger.Infof("Deleted Cloud SSHKey %q", item.name)
	o.deletePendingItems(item.typeName, []cloudResource{item})

	return nil
}

// destroyCloudSSHKeys removes all key resources that have a name prefixed
// with the cluster's infra ID.
func (o *ClusterUninstaller) destroyCloudSSHKeys() error {
	firstPassList, err := o.listCloudSSHKeys()
	if err != nil {
		return err
	}

	if len(firstPassList.list()) == 0 {
		return nil
	}

	items := o.insertPendingItems(cloudSSHKeyTypeName, firstPassList.list())

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	for _, item := range items {
		select {
		case <-ctx.Done():
			o.Logger.Debugf("destroyCloudSSHKeys: case <-ctx.Done()")
			return o.Context.Err() // we're cancelled, abort
		default:
		}

		backoff := wait.Backoff{
			Duration: 15 * time.Second,
			Factor:   1.1,
			Cap:      leftInContext(ctx),
			Steps:    math.MaxInt32}
		err = wait.ExponentialBackoffWithContext(ctx, backoff, func() (bool, error) {
			err2 := o.deleteCloudSSHKey(item)
			if err2 == nil {
				return true, err2
			}
			o.errorTracker.suppressWarning(item.key, err2, o.Logger)
			return false, err2
		})
		if err != nil {
			o.Logger.Fatal("destroyCloudSSHKeys: ExponentialBackoffWithContext (destroy) returns ", err)
		}
	}

	if items = o.getPendingItems(cloudSSHKeyTypeName); len(items) > 0 {
		for _, item := range items {
			o.Logger.Debugf("destroyCloudSSHKeys: found %s in pending items", item.name)
		}
		return errors.Errorf("destroyCloudSSHKeys: %d undeleted items pending", len(items))
	}

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func() (bool, error) {
		secondPassList, err2 := o.listCloudSSHKeys()
		if err2 != nil {
			return false, err2
		}
		if len(secondPassList) == 0 {
			// We finally don't see any remaining instances!
			return true, nil
		}
		for _, item := range secondPassList {
			o.Logger.Debugf("destroyCloudSSHKeys: found %s in second pass", item.name)
		}
		return false, nil
	})
	if err != nil {
		o.Logger.Fatal("destroyCloudSSHKeys: ExponentialBackoffWithContext (list) returns ", err)
	}

	return nil
}


const (
	dhcpTypeName = "dhcp"
)

// listDHCPNetworks lists previously found DHCP networks in found instances in the vpc.
func (o *ClusterUninstaller) listDHCPNetworks() (cloudResources, error) {
	// https://github.com/IBM-Cloud/power-go-client/blob/v1.0.88/power/models/d_h_c_p_servers.go#L19
	var dhcpServers models.DHCPServers
	// https://github.com/IBM-Cloud/power-go-client/blob/v1.0.88/power/models/d_h_c_p_server.go#L18-L31
	var dhcpServer *models.DHCPServer
	var err error

	o.Logger.Debugf("Listing DHCP networks")

	dhcpServers, err = o.dhcpClient.GetAll()
	if err != nil {
		o.Logger.Fatalf("Failed to list DHCP servers: %v", err)
	}

	var foundOne = false

	result := []cloudResource{}
	for _, dhcpServer = range dhcpServers {
		if dhcpServer.Network == nil {
			o.Logger.Debugf("listDHCPNetworks: DHCP has empty Network: %s", *dhcpServer.ID)
			continue
		}
		if dhcpServer.Network.Name == nil {
			o.Logger.Debugf("listDHCPNetworks: DHCP has empty Network.Name: %s", *dhcpServer.ID)
			continue
		}

		if strings.Contains(*dhcpServer.Network.Name, o.InfraID) {
			o.Logger.Debugf("listDHCPNetworks: FOUND: %s (%s)", *dhcpServer.Network.Name, *dhcpServer.ID)
			foundOne = true
			result = append(result, cloudResource{
				key:      *dhcpServer.ID,
				name:     *dhcpServer.Network.Name,
				status:   "",
				typeName: dhcpTypeName,
				id:       *dhcpServer.ID,
			})
		}
	}
	if !foundOne {
		o.Logger.Debugf("listDHCPNetworks: NO matching DHCP network found in:")
		for _, dhcpServer = range dhcpServers {
			if dhcpServer.Network == nil {
				continue
			}
			if dhcpServer.Network.Name == nil {
				continue
			}
			o.Logger.Debugf("listDHCPNetworks: only found DHCP: %s", *dhcpServer.Network.Name)
		}
	}

	return cloudResources{}.insert(result...), nil
}

func (o *ClusterUninstaller) destroyDHCPNetwork(item cloudResource) error {
	var err error

	_, err = o.dhcpClient.Get(item.id)
	if err != nil {
		o.deletePendingItems(item.typeName, []cloudResource{item})
		o.Logger.Infof("Deleted DHCP Network %q", item.name)
		return nil
	}

	o.Logger.Debugf("Deleting DHCP network %q", item.name)

	err = o.dhcpClient.Delete(item.id)
	if err != nil {
		o.Logger.Infof("Error: o.dhcpClient.Delete: %q", err)
		return err
	}

	o.deletePendingItems(item.typeName, []cloudResource{item})
	o.Logger.Infof("Deleted DHCP Network %q", item.name)

	return nil
}

// destroyDHCPNetworks searches for DHCP networks that are in a previous list
// the cluster's infra ID.
func (o *ClusterUninstaller) destroyDHCPNetworks() error {
	firstPassList, err := o.listDHCPNetworks()
	if err != nil {
		return err
	}

	if len(firstPassList.list()) == 0 {
		return nil
	}

	items := o.insertPendingItems(dhcpTypeName, firstPassList.list())

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	for _, item := range items {
		select {
		case <-ctx.Done():
			o.Logger.Debugf("destroyDHCPNetworks: case <-ctx.Done()")
			return o.Context.Err() // we're cancelled, abort
		default:
		}

		backoff := wait.Backoff{
			Duration: 15 * time.Second,
			Factor:   1.1,
			Cap:      leftInContext(ctx),
			Steps:    math.MaxInt32}
		err = wait.ExponentialBackoffWithContext(ctx, backoff, func() (bool, error) {
			err2 := o.destroyDHCPNetwork(item)
			if err2 == nil {
				return true, err2
			}
			o.errorTracker.suppressWarning(item.key, err2, o.Logger)
			return false, err2
		})
		if err != nil {
			o.Logger.Fatal("destroyDHCPNetworks: ExponentialBackoffWithContext (destroy) returns ", err)
		}
	}

	if items = o.getPendingItems(dhcpTypeName); len(items) > 0 {
		for _, item := range items {
			o.Logger.Debugf("destroyDHCPNetworks: found %s in pending items", item.name)
		}
		return errors.Errorf("destroyDHCPNetworks: %d undeleted items pending", len(items))
	}

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func() (bool, error) {
		secondPassList, err2 := o.listDHCPNetworks()
		if err2 != nil {
			return false, err2
		}
		if len(secondPassList) == 0 {
			// We finally don't see any remaining instances!
			return true, nil
		}
		for _, item := range secondPassList {
			o.Logger.Debugf("destroyDHCPNetworks: found %s in second pass", item.name)
		}
		return false, nil
	})
	if err != nil {
		o.Logger.Fatal("destroyDHCPNetworks: ExponentialBackoffWithContext (list) returns ", err)
	}

	return nil
}


const (
	cisDNSRecordTypeName = "cis dns record"
)

// listDNSRecords lists DNS records for the cluster.
func (o *ClusterUninstaller) listDNSRecords() (cloudResources, error) {
	o.Logger.Debugf("Listing DNS records")

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("listDNSRecords: case <-ctx.Done()")
		return nil, o.Context.Err() // we're cancelled, abort
	default:
	}

	var (
		foundOne       = false
		perPage  int64 = 20
		page     int64 = 1
		moreData bool  = true
	)

	dnsRecordsOptions := o.dnsRecordsSvc.NewListAllDnsRecordsOptions()
	dnsRecordsOptions.PerPage = &perPage
	dnsRecordsOptions.Page = &page

	result := []cloudResource{}

	for moreData {
		dnsResources, detailedResponse, err := o.dnsRecordsSvc.ListAllDnsRecordsWithContext(ctx, dnsRecordsOptions)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to list DNS records: %v and the response is: %s", err, detailedResponse)
		}

		for _, record := range dnsResources.Result {
			// Match all of the cluster's DNS records
			exp := fmt.Sprintf(`.*\Q%s.%s\E$`, o.ClusterName, o.BaseDomain)
			nameMatches, _ := regexp.Match(exp, []byte(*record.Name))
			contentMatches, _ := regexp.Match(exp, []byte(*record.Content))
			if nameMatches || contentMatches {
				foundOne = true
				o.Logger.Debugf("listDNSRecords: FOUND: %v, %v", *record.ID, *record.Name)
				result = append(result, cloudResource{
					key:      *record.ID,
					name:     *record.Name,
					status:   "",
					typeName: cisDNSRecordTypeName,
					id:       *record.ID,
				})
			}
		}

		o.Logger.Debugf("listDNSRecords: PerPage = %v, Page = %v, Count = %v", *dnsResources.ResultInfo.PerPage, *dnsResources.ResultInfo.Page, *dnsResources.ResultInfo.Count)

		moreData = *dnsResources.ResultInfo.PerPage == *dnsResources.ResultInfo.Count
		o.Logger.Debugf("listDNSRecords: moreData = %v", moreData)

		page++
	}
	if !foundOne {
		o.Logger.Debugf("listDNSRecords: NO matching DNS against: %s", o.InfraID)
		for moreData {
			dnsResources, detailedResponse, err := o.dnsRecordsSvc.ListAllDnsRecordsWithContext(ctx, dnsRecordsOptions)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to list DNS records: %v and the response is: %s", err, detailedResponse)
			}
			for _, record := range dnsResources.Result {
				o.Logger.Debugf("listDNSRecords: FOUND: DNS: %v, %v", *record.ID, *record.Name)
			}
			moreData = *dnsResources.ResultInfo.PerPage == *dnsResources.ResultInfo.Count
			page++
		}
	}

	return cloudResources{}.insert(result...), nil
}

// destroyDNSRecord destroys a DNS record.
func (o *ClusterUninstaller) destroyDNSRecord(item cloudResource) error {
	var (
		response *core.DetailedResponse
		err      error
	)

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("destroyDNSRecord: case <-ctx.Done()")
		return o.Context.Err() // we're cancelled, abort
	default:
	}

	getOptions := o.dnsRecordsSvc.NewGetDnsRecordOptions(item.id)
	_, response, err = o.dnsRecordsSvc.GetDnsRecordWithContext(ctx, getOptions)

	if err != nil && response != nil && response.StatusCode == gohttp.StatusNotFound {
		// The resource is gone
		o.deletePendingItems(item.typeName, []cloudResource{item})
		o.Logger.Infof("Deleted DNS Record %q", item.name)
		return nil
	}
	if err != nil && response != nil && response.StatusCode == gohttp.StatusInternalServerError {
		o.Logger.Infof("destroyDNSRecord: internal server error")
		return nil
	}

	deleteOptions := o.dnsRecordsSvc.NewDeleteDnsRecordOptions(item.id)

	_, _, err = o.dnsRecordsSvc.DeleteDnsRecordWithContext(ctx, deleteOptions)
	if err != nil {
		return errors.Wrapf(err, "failed to delete DNS record %s", item.name)
	}

	o.Logger.Infof("Deleted DNS Record %q", item.name)
	o.deletePendingItems(item.typeName, []cloudResource{item})

	return nil
}

// destroyDNSRecords removes all DNS record resources that have a name containing
// the cluster's infra ID.
func (o *ClusterUninstaller) destroyDNSRecords() error {
	if o.dnsRecordsSvc == nil {
		// Install config didn't specify using these resources
		return nil
	}

	firstPassList, err := o.listDNSRecords()
	if err != nil {
		return err
	}

	if len(firstPassList.list()) == 0 {
		return nil
	}

	items := o.insertPendingItems(cisDNSRecordTypeName, firstPassList.list())

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	for _, item := range items {
		select {
		case <-ctx.Done():
			o.Logger.Debugf("destroyDNSRecords: case <-ctx.Done()")
			return o.Context.Err() // we're cancelled, abort
		default:
		}

		backoff := wait.Backoff{
			Duration: 15 * time.Second,
			Factor:   1.1,
			Cap:      leftInContext(ctx),
			Steps:    math.MaxInt32}
		err = wait.ExponentialBackoffWithContext(ctx, backoff, func() (bool, error) {
			err2 := o.destroyDNSRecord(item)
			if err2 == nil {
				return true, err2
			}
			o.errorTracker.suppressWarning(item.key, err2, o.Logger)
			return false, err2
		})
		if err != nil {
			o.Logger.Fatal("destroyDNSRecords: ExponentialBackoffWithContext (destroy) returns ", err)
		}
	}

	if items = o.getPendingItems(cisDNSRecordTypeName); len(items) > 0 {
		for _, item := range items {
			o.Logger.Debugf("destroyDNSRecords: found %s in pending items", item.name)
		}
		return errors.Errorf("destroyDNSRecords: %d undeleted items pending", len(items))
	}

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func() (bool, error) {
		secondPassList, err2 := o.listDNSRecords()
		if err2 != nil {
			return false, err2
		}
		if len(secondPassList) == 0 {
			// We finally don't see any remaining instances!
			return true, nil
		}
		for _, item := range secondPassList {
			o.Logger.Debugf("destroyDNSRecords: found %s in second pass", item.name)
		}
		return false, nil
	})
	if err != nil {
		o.Logger.Fatal("destroyDNSRecords: ExponentialBackoffWithContext (list) returns ", err)
	}

	return nil
}


const (
	ibmDNSRecordTypeName = "ibm dns record"
)

// listResourceRecords lists DNS Resource records for the cluster.
func (o *ClusterUninstaller) listResourceRecords() (cloudResources, error) {
	o.Logger.Debugf("Listing DNS resource records")

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("listResourceRecords: case <-ctx.Done()")
		return nil, o.Context.Err() // we're cancelled, abort
	default:
	}

	result := []cloudResource{}

	dnsCRN, err := crn.Parse(o.DNSInstanceCRN)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse DNSInstanceCRN")
	}
	records, _, err := o.resourceRecordsSvc.ListResourceRecords(&resourcerecordsv1.ListResourceRecordsOptions{
		InstanceID: &dnsCRN.ServiceInstance,
		DnszoneID:  &o.dnsZoneID,
	})
	for _, record := range records.ResourceRecords {
		// Match all of the cluster's DNS records
		exp := fmt.Sprintf(`.*\Q%s.%s\E$`, o.ClusterName, o.BaseDomain)
		nameMatches, _ := regexp.Match(exp, []byte(*record.Name))
		if nameMatches {
			o.Logger.Debugf("listResourceRecords: FOUND: %v, %v", *record.ID, *record.Name)
			result = append(result, cloudResource{
				key:      *record.ID,
				name:     *record.Name,
				status:   "",
				typeName: ibmDNSRecordTypeName,
				id:       *record.ID,
			})
		}
	}
	if err != nil {
		return nil, errors.Wrap(err, "could not retrieve DNS records")
	}
	return cloudResources{}.insert(result...), nil
}

// destroyResourceRecord destroys a Resource Record.
func (o *ClusterUninstaller) destroyResourceRecord(item cloudResource) error {
	var (
		response *core.DetailedResponse
		err      error
	)

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("destroyResourceRecord: case <-ctx.Done()")
		return o.Context.Err() // we're cancelled, abort
	default:
	}

	if err != nil {
		return errors.Wrapf(err, "failed to delete DNS Resource record %s", item.name)
	}
	dnsCRN, err := crn.Parse(o.DNSInstanceCRN)
	if err != nil {
		return errors.Wrap(err, "Failed to parse DNSInstanceCRN")
	}
	getOptions := o.resourceRecordsSvc.NewGetResourceRecordOptions(dnsCRN.ServiceInstance, o.dnsZoneID, item.id)
	_, response, err = o.resourceRecordsSvc.GetResourceRecord(getOptions)

	if err != nil && response != nil && response.StatusCode == gohttp.StatusNotFound {
		// The resource is gone
		o.deletePendingItems(item.typeName, []cloudResource{item})
		o.Logger.Infof("Deleted DNS Resource Record %q", item.name)
		return nil
	}
	if err != nil && response != nil && response.StatusCode == gohttp.StatusInternalServerError {
		o.Logger.Infof("destroyResourceRecord: internal server error")
		return nil
	}

	deleteOptions := o.resourceRecordsSvc.NewDeleteResourceRecordOptions(dnsCRN.ServiceInstance, o.dnsZoneID, item.id)

	_, err = o.resourceRecordsSvc.DeleteResourceRecord(deleteOptions)
	if err != nil {
		return errors.Wrapf(err, "failed to delete DNS Resource record %s", item.name)
	}

	o.Logger.Infof("Deleted DNS Resource Record %q", item.name)
	o.deletePendingItems(item.typeName, []cloudResource{item})

	return nil
}

// destroyResourceRecords removes all DNS record resources that have a name containing
// the cluster's infra ID.
func (o *ClusterUninstaller) destroyResourceRecords() error {
	if o.resourceRecordsSvc == nil {
		// Install config didn't specify using these resources
		return nil
	}

	firstPassList, err := o.listResourceRecords()
	if err != nil {
		return err
	}

	if len(firstPassList.list()) == 0 {
		return nil
	}

	items := o.insertPendingItems(ibmDNSRecordTypeName, firstPassList.list())

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	for _, item := range items {
		select {
		case <-ctx.Done():
			o.Logger.Debugf("destroyResourceRecords: case <-ctx.Done()")
			return o.Context.Err() // we're cancelled, abort
		default:
		}

		backoff := wait.Backoff{
			Duration: 15 * time.Second,
			Factor:   1.1,
			Cap:      leftInContext(ctx),
			Steps:    math.MaxInt32}
		err = wait.ExponentialBackoffWithContext(ctx, backoff, func() (bool, error) {
			err2 := o.destroyResourceRecord(item)
			if err2 == nil {
				return true, err2
			}
			o.errorTracker.suppressWarning(item.key, err2, o.Logger)
			return false, err2
		})
		if err != nil {
			o.Logger.Fatal("destroyResourceRecords: ExponentialBackoffWithContext (destroy) returns ", err)
		}
	}

	if items = o.getPendingItems(ibmDNSRecordTypeName); len(items) > 0 {
		for _, item := range items {
			o.Logger.Debugf("destroyResourceRecords: found %s in pending items", item.name)
		}
		return errors.Errorf("destroyResourceRecords: %d undeleted items pending", len(items))
	}

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func() (bool, error) {
		secondPassList, err2 := o.listResourceRecords()
		if err2 != nil {
			return false, err2
		}
		if len(secondPassList) == 0 {
			// We finally don't see any remaining instances!
			return true, nil
		}
		for _, item := range secondPassList {
			o.Logger.Debugf("destroyResourceRecords: found %s in second pass", item.name)
		}
		return false, nil
	})
	if err != nil {
		o.Logger.Fatal("destroyResourceRecords: ExponentialBackoffWithContext (list) returns ", err)
	}

	return nil
}


const (
	suppressDuration = time.Minute * 5
)

// errorTracker holds a history of errors.
type errorTracker struct {
	history map[string]time.Time
}

// suppressWarning logs errors WARN once every duration and the rest to DEBUG.
func (o *errorTracker) suppressWarning(identifier string, err error, logger logrus.FieldLogger) {
	if o.history == nil {
		o.history = map[string]time.Time{}
	}
	if firstSeen, ok := o.history[identifier]; ok {
		if time.Since(firstSeen) > suppressDuration {
			logger.Warn(err)
			o.history[identifier] = time.Now() // reset the clock
		} else {
			logger.Debug(err)
		}
	} else { // first error for this identifier
		o.history[identifier] = time.Now()
		logger.Debug(err)
	}
}


const imageTypeName = "image"

// listImages lists images in the vpc.
func (o *ClusterUninstaller) listImages() (cloudResources, error) {
	o.Logger.Debugf("Listing images")

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("listImages: case <-ctx.Done()")
		return nil, o.Context.Err() // we're cancelled, abort
	default:
	}

	images, err := o.imageClient.GetAll()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to list images")
	}

	var foundOne = false

	result := []cloudResource{}
	for _, image := range images.Images {
		if strings.Contains(*image.Name, o.InfraID) {
			foundOne = true
			o.Logger.Debugf("listImages: FOUND: %s, %s, %s", *image.ImageID, *image.Name, *image.State)
			result = append(result, cloudResource{
				key:      *image.ImageID,
				name:     *image.Name,
				status:   *image.State,
				typeName: imageTypeName,
				id:       *image.ImageID,
			})
		}
	}
	if !foundOne {
		o.Logger.Debugf("listImages: NO matching image against: %s", o.InfraID)
		for _, image := range images.Images {
			o.Logger.Debugf("listImages: image: %s", *image.Name)
		}
	}

	return cloudResources{}.insert(result...), nil
}

func (o *ClusterUninstaller) deleteImage(item cloudResource) error {
	var img *models.Image
	var err error

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("deleteImage: case <-ctx.Done()")
		return o.Context.Err() // we're cancelled, abort
	default:
	}

	img, err = o.imageClient.Get(item.id)
	if err != nil {
		o.Logger.Debugf("listImages: deleteImage: image %q no longer exists", item.name)
		o.deletePendingItems(item.typeName, []cloudResource{item})
		o.Logger.Infof("Deleted Image %q", item.name)
		return nil
	}

	if !strings.EqualFold(img.State, "active") {
		o.Logger.Debugf("Waiting for image %q to delete", item.name)
		return nil
	}

	err = o.imageClient.Delete(item.id)
	if err != nil {
		return errors.Wrapf(err, "failed to delete image %s", item.name)
	}

	o.Logger.Infof("Deleted Image %q", item.name)
	o.deletePendingItems(item.typeName, []cloudResource{item})

	return nil
}

// destroyImages removes all image resources that have a name prefixed
// with the cluster's infra ID.
func (o *ClusterUninstaller) destroyImages() error {
	firstPassList, err := o.listImages()
	if err != nil {
		return err
	}

	if len(firstPassList.list()) == 0 {
		return nil
	}

	items := o.insertPendingItems(imageTypeName, firstPassList.list())
	for _, item := range items {
		o.Logger.Debugf("destroyImages: firstPassList: %v / %v", item.name, item.id)
	}

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	for _, item := range items {
		select {
		case <-ctx.Done():
			o.Logger.Debugf("destroyImages: case <-ctx.Done()")
			return o.Context.Err() // we're cancelled, abort
		default:
		}

		backoff := wait.Backoff{
			Duration: 15 * time.Second,
			Factor:   1.1,
			Cap:      leftInContext(ctx),
			Steps:    math.MaxInt32}
		err = wait.ExponentialBackoffWithContext(ctx, backoff, func() (bool, error) {
			err2 := o.deleteImage(item)
			if err2 == nil {
				return true, err2
			}
			o.errorTracker.suppressWarning(item.key, err2, o.Logger)
			return false, err2
		})
		if err != nil {
			o.Logger.Fatal("destroyImages: ExponentialBackoffWithContext (destroy) returns ", err)
		}
	}

	if items = o.getPendingItems(imageTypeName); len(items) > 0 {
		for _, item := range items {
			o.Logger.Debugf("destroyImages: found %s in pending items", item.name)
		}
		return errors.Errorf("destroyImages: %d undeleted items pending", len(items))
	}

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func() (bool, error) {
		secondPassList, err2 := o.listImages()
		if err2 != nil {
			return false, err2
		}
		if len(secondPassList) == 0 {
			// We finally don't see any remaining instances!
			return true, nil
		}
		for _, item := range secondPassList {
			o.Logger.Debugf("destroyImages: found %s in second pass", item.name)
		}
		return false, nil
	})
	if err != nil {
		o.Logger.Fatal("destroyImages: ExponentialBackoffWithContext (list) returns ", err)
	}

	return nil
}


const jobTypeName = "job"

// listJobs lists jobs in the vpc.
func (o *ClusterUninstaller) listJobs() (cloudResources, error) {
	var jobs *models.Jobs
	var job *models.Job
	var err error

	o.Logger.Debugf("Listing jobs")

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("listJobs: case <-ctx.Done()")
		return nil, o.Context.Err() // we're cancelled, abort
	default:
	}

	jobs, err = o.jobClient.GetAll()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to list jobs")
	}

	result := []cloudResource{}
	for _, job = range jobs.Jobs {
		// https://github.com/IBM-Cloud/power-go-client/blob/master/power/models/job.go
		if strings.Contains(*job.Operation.ID, o.InfraID) {
			if *job.Status.State == "completed" {
				continue
			}
			o.Logger.Debugf("listJobs: FOUND: %s (%s) (%s)", *job.Operation.ID, *job.ID, *job.Status.State)
			result = append(result, cloudResource{
				key:      *job.Operation.ID,
				name:     *job.Operation.ID,
				status:   *job.Status.State,
				typeName: jobTypeName,
				id:       *job.ID,
			})
		}
	}

	return cloudResources{}.insert(result...), nil
}

// DeleteJobResult The different states deleting a job can take.
type DeleteJobResult int

const (
	// DeleteJobSuccess A job has finished successfully.
	DeleteJobSuccess DeleteJobResult = iota

	// DeleteJobRunning A job is currently running.
	DeleteJobRunning

	// DeleteJobError A job has resulted in an error.
	DeleteJobError
)

func (o *ClusterUninstaller) deleteJob(item cloudResource) (DeleteJobResult, error) {
	var job *models.Job
	var err error

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("deleteJob: case <-ctx.Done()")
		return DeleteJobError, o.Context.Err() // we're cancelled, abort
	default:
	}

	job, err = o.jobClient.Get(item.id)
	if err != nil {
		o.Logger.Debugf("listJobs: deleteJob: job %q no longer exists", item.name)
		o.deletePendingItems(item.typeName, []cloudResource{item})
		o.Logger.Infof("Deleted Job %q", item.name)
		return DeleteJobSuccess, nil
	}

	switch *job.Status.State {
	case "completed":
		//		err = o.jobClient.Delete(item.id)
		//		if err != nil {
		//			return DeleteJobError, errors.Wrapf(err, "failed to delete job %s", item.name)
		//		}

		o.deletePendingItems(item.typeName, []cloudResource{item})
		o.Logger.Debugf("Deleting job %q", item.name)

		return DeleteJobSuccess, nil

	case "active":
		o.Logger.Debugf("Waiting for job %q to delete (status is %q)", item.name, *job.Status.State)
		return DeleteJobRunning, nil

	case "failed":
		err = errors.Errorf("@TODO we cannot query error message inside the job")
		return DeleteJobError, errors.Wrapf(err, "job %v has failed", item.id)

	default:
		o.Logger.Debugf("Default waiting for job %q to delete (status is %q)", item.name, *job.Status.State)
		return DeleteJobRunning, nil
	}
}

// destroyJobs removes all job resources that have a name prefixed
// with the cluster's infra ID.
func (o *ClusterUninstaller) destroyJobs() error {
	firstPassList, err := o.listJobs()
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
		case <-ctx.Done():
			o.Logger.Debugf("destroyJobs: case <-ctx.Done()")
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
				o.Logger.Debugf("destroyJobs: deleteJob returns DeleteJobSuccess")
				return true, nil
			case DeleteJobRunning:
				o.Logger.Debugf("destroyJobs: deleteJob returns DeleteJobRunning")
				return false, nil
			case DeleteJobError:
				o.Logger.Debugf("destroyJobs: deleteJob returns DeleteJobError: %v", err2)
				return false, err2
			default:
				return false, errors.Errorf("destroyJobs: deleteJob unknown result enum %v", result)
			}
		})
		if err != nil {
			o.Logger.Fatal("destroyJobs: ExponentialBackoffWithContext (destroy) returns ", err)
		}
	}

	if items = o.getPendingItems(jobTypeName); len(items) > 0 {
		for _, item := range items {
			o.Logger.Debugf("destroyJobs: found %s in pending items", item.name)
		}
		return errors.Errorf("destroyJobs: %d undeleted items pending", len(items))
	}

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func() (bool, error) {
		secondPassList, err2 := o.listJobs()
		if err2 != nil {
			return false, err2
		}
		if len(secondPassList) == 0 {
			// We finally don't see any remaining instances!
			return true, nil
		}
		for _, item := range secondPassList {
			o.Logger.Debugf("destroyJobs: found %s in second pass", item.name)
		}
		return false, nil
	})
	if err != nil {
		o.Logger.Fatal("destroyJobs: ExponentialBackoffWithContext (list) returns ", err)
	}

	return nil
}


const loadBalancerTypeName = "load balancer"

// listLoadBalancers lists load balancers in the vpc.
func (o *ClusterUninstaller) listLoadBalancers() (cloudResources, error) {
	o.Logger.Debugf("Listing load balancers")

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("listLoadBalancers: case <-ctx.Done()")
		return nil, o.Context.Err() // we're cancelled, abort
	default:
	}

	options := o.vpcSvc.NewListLoadBalancersOptions()

	resources, _, err := o.vpcSvc.ListLoadBalancersWithContext(ctx, options)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to list load balancers")
	}

	var foundOne = false

	result := []cloudResource{}
	for _, loadbalancer := range resources.LoadBalancers {
		if strings.Contains(*loadbalancer.Name, o.InfraID) {
			foundOne = true
			o.Logger.Debugf("listLoadBalancers: FOUND: %s, %s, %s", *loadbalancer.ID, *loadbalancer.Name, *loadbalancer.ProvisioningStatus)
			result = append(result, cloudResource{
				key:      *loadbalancer.ID,
				name:     *loadbalancer.Name,
				status:   *loadbalancer.ProvisioningStatus,
				typeName: loadBalancerTypeName,
				id:       *loadbalancer.ID,
			})
		}
	}
	if !foundOne {
		o.Logger.Debugf("listLoadBalancers: NO matching loadbalancers against: %s", o.InfraID)
		for _, loadbalancer := range resources.LoadBalancers {
			o.Logger.Debugf("listLoadBalancers: loadbalancer: %s", *loadbalancer.Name)
		}
	}

	return cloudResources{}.insert(result...), nil
}

func (o *ClusterUninstaller) deleteLoadBalancer(item cloudResource) error {
	var getOptions *vpcv1.GetLoadBalancerOptions
	var lb *vpcv1.LoadBalancer
	var response *core.DetailedResponse
	var err error

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("deleteLoadBalancer: case <-ctx.Done()")
		return o.Context.Err() // we're cancelled, abort
	default:
	}

	getOptions = o.vpcSvc.NewGetLoadBalancerOptions(item.id)
	lb, response, err = o.vpcSvc.GetLoadBalancer(getOptions)

	if err == nil && response.StatusCode == gohttp.StatusNoContent {
		return nil
	}
	if err != nil && response != nil && response.StatusCode == gohttp.StatusNotFound {
		// The resource is gone.
		o.deletePendingItems(item.typeName, []cloudResource{item})
		o.Logger.Infof("Deleted Load Balancer %q", item.name)
		return nil
	}
	if err != nil && response != nil && response.StatusCode == gohttp.StatusInternalServerError {
		o.Logger.Infof("deleteLoadBalancer: internal server error")
		return nil
	}
	if lb == nil {
		o.Logger.Debugf("deleteLoadBalancer: lb = %v", lb)
		o.Logger.Debugf("deleteLoadBalancer: response = %v", response)
		o.Logger.Debugf("deleteLoadBalancer: err = %v", err)
		o.Logger.Debugf("Rate and unhandled code, please investigate further")
		return nil
	}

	if *lb.ProvisioningStatus == vpcv1.LoadBalancerProvisioningStatusDeletePendingConst {
		o.Logger.Debugf("Waiting for load balancer %q to delete", item.name)
		return nil
	}

	deleteOptions := o.vpcSvc.NewDeleteLoadBalancerOptions(item.id)

	_, err = o.vpcSvc.DeleteLoadBalancerWithContext(ctx, deleteOptions)
	if err != nil {
		return errors.Wrapf(err, "failed to delete load balancer %s", item.name)
	}

	o.Logger.Infof("Deleted Load Balancer %q", item.name)
	o.deletePendingItems(item.typeName, []cloudResource{item})

	return nil
}

// destroyLoadBalancers removes all load balancer resources that have a name prefixed
// with the cluster's infra ID.
func (o *ClusterUninstaller) destroyLoadBalancers() error {
	firstPassList, err := o.listLoadBalancers()
	if err != nil {
		return err
	}

	if len(firstPassList.list()) == 0 {
		return nil
	}

	items := o.insertPendingItems(loadBalancerTypeName, firstPassList.list())

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	for _, item := range items {
		select {
		case <-ctx.Done():
			o.Logger.Debugf("destroyLoadBalancers: case <-ctx.Done()")
			return o.Context.Err() // we're cancelled, abort
		default:
		}

		backoff := wait.Backoff{
			Duration: 15 * time.Second,
			Factor:   1.1,
			Cap:      leftInContext(ctx),
			Steps:    math.MaxInt32}
		err = wait.ExponentialBackoffWithContext(ctx, backoff, func() (bool, error) {
			err2 := o.deleteLoadBalancer(item)
			if err2 == nil {
				return true, err2
			}
			o.errorTracker.suppressWarning(item.key, err2, o.Logger)
			return false, err2
		})
		if err != nil {
			o.Logger.Fatal("destroyLoadBalancers: ExponentialBackoffWithContext (destroy) returns ", err)
		}
	}

	if items = o.getPendingItems(loadBalancerTypeName); len(items) > 0 {
		for _, item := range items {
			o.Logger.Debugf("destroyLoadBalancers: found %s in pending items", item.name)
		}
		return errors.Errorf("destroyLoadBalancers: %d undeleted items pending", len(items))
	}

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func() (bool, error) {
		secondPassList, err2 := o.listLoadBalancers()
		if err2 != nil {
			return false, err2
		}
		if len(secondPassList) == 0 {
			// We finally don't see any remaining instances!
			return true, nil
		}
		for _, item := range secondPassList {
			o.Logger.Debugf("destroyLoadBalancers: found %s in second pass", item.name)
		}
		return false, nil
	})
	if err != nil {
		o.Logger.Fatal("destroyLoadBalancers: ExponentialBackoffWithContext (list) returns ", err)
	}

	return nil
}


const (
	powerInstanceTypeName = "powerInstance"
)

// listPowerInstances lists instances in the power server.
func (o *ClusterUninstaller) listPowerInstances() (cloudResources, error) {
	o.Logger.Debugf("Listing virtual Power service instances (%s)", o.InfraID)

	instances, err := o.instanceClient.GetAll()
	if err != nil {
		o.Logger.Warnf("Error instanceClient.GetAll: %v", err)
		return nil, err
	}

	var foundOne = false

	result := []cloudResource{}
	for _, instance := range instances.PvmInstances {
		// https://github.com/IBM-Cloud/power-go-client/blob/master/power/models/p_vm_instance.go
		if strings.Contains(*instance.ServerName, o.InfraID) {
			foundOne = true
			o.Logger.Debugf("listPowerInstances: FOUND: %s, %s, %s", *instance.PvmInstanceID, *instance.ServerName, *instance.Status)
			result = append(result, cloudResource{
				key:      *instance.PvmInstanceID,
				name:     *instance.ServerName,
				status:   *instance.Status,
				typeName: powerInstanceTypeName,
				id:       *instance.PvmInstanceID,
			})
		}
	}
	if !foundOne {
		o.Logger.Debugf("listPowerInstances: NO matching virtual instance against: %s", o.InfraID)
		for _, instance := range instances.PvmInstances {
			o.Logger.Debugf("listPowerInstances: only found virtual instance: %s", *instance.ServerName)
		}
	}

	return cloudResources{}.insert(result...), nil
}

// destroyPowerInstance deletes a given instance.
func (o *ClusterUninstaller) destroyPowerInstance(item cloudResource) error {
	var err error

	_, err = o.instanceClient.Get(item.id)
	if err != nil {
		o.deletePendingItems(item.typeName, []cloudResource{item})
		o.Logger.Infof("Deleted Power Instance %q (%q)", item.name, item.status)
		return nil
	}

	o.Logger.Debugf("Deleting Power instance %q", item.name)

	err = o.instanceClient.Delete(item.id)
	if err != nil {
		o.Logger.Infof("Error: o.instanceClient.Delete: %q", err)
		return err
	}

	o.deletePendingItems(item.typeName, []cloudResource{item})
	o.Logger.Infof("Deleted Power Instance %q (%q)", item.name, item.status)

	return nil
}

// destroyPowerInstances searches for Power instances that have a name that starts with
// the cluster's infra ID.
func (o *ClusterUninstaller) destroyPowerInstances() error {
	firstPassList, err := o.listPowerInstances()
	if err != nil {
		return err
	}

	if len(firstPassList.list()) == 0 {
		return nil
	}

	items := o.insertPendingItems(powerInstanceTypeName, firstPassList.list())

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	for _, item := range items {
		select {
		case <-ctx.Done():
			o.Logger.Debugf("destroyPowerInstances: case <-ctx.Done()")
			return o.Context.Err() // we're cancelled, abort
		default:
		}

		backoff := wait.Backoff{
			Duration: 15 * time.Second,
			Factor:   1.1,
			Cap:      leftInContext(ctx),
			Steps:    math.MaxInt32}
		err = wait.ExponentialBackoffWithContext(ctx, backoff, func() (bool, error) {
			err2 := o.destroyPowerInstance(item)
			if err2 == nil {
				return true, err2
			}
			o.errorTracker.suppressWarning(item.key, err2, o.Logger)
			return false, err2
		})
		if err != nil {
			o.Logger.Fatal("destroyPowerInstances: ExponentialBackoffWithContext (destroy) returns ", err)
		}
	}

	if items = o.getPendingItems(powerInstanceTypeName); len(items) > 0 {
		for _, item := range items {
			o.Logger.Debugf("destroyPowerInstances: found %s in pending items", item.name)
		}
		return errors.Errorf("destroyPowerInstances: %d undeleted items pending", len(items))
	}

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func() (bool, error) {
		secondPassList, err2 := o.listPowerInstances()
		if err2 != nil {
			return false, err2
		}
		if len(secondPassList) == 0 {
			// We finally don't see any remaining instances!
			return true, nil
		}
		for _, item := range secondPassList {
			o.Logger.Debugf("destroyPowerInstances: found %s in second pass", item.name)
		}
		return false, nil
	})
	if err != nil {
		o.Logger.Fatal("destroyPowerInstances: ExponentialBackoffWithContext (list) returns ", err)
	}

	return nil
}


const powerSSHKeyTypeName = "powerSshKey"

// listPowerSSHKeys lists ssh keys in the Power server.
func (o *ClusterUninstaller) listPowerSSHKeys() (cloudResources, error) {
	o.Logger.Debugf("Listing Power SSHKeys")

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("listPowerSSHKeys: case <-ctx.Done()")
		return nil, o.Context.Err() // we're cancelled, abort
	default:
	}

	var sshKeys *models.SSHKeys
	var err error

	sshKeys, err = o.keyClient.GetAll()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to list Power sshkeys: %v", err)
	}

	var sshKey *models.SSHKey
	var foundOne = false

	result := []cloudResource{}
	for _, sshKey = range sshKeys.SSHKeys {
		if strings.Contains(*sshKey.Name, o.InfraID) {
			foundOne = true
			o.Logger.Debugf("listPowerSSHKeys: FOUND: %v", *sshKey.Name)
			result = append(result, cloudResource{
				key:      *sshKey.Name,
				name:     *sshKey.Name,
				status:   "",
				typeName: powerSSHKeyTypeName,
				id:       *sshKey.Name,
			})
		}
	}
	if !foundOne {
		o.Logger.Debugf("listPowerSSHKeys: NO matching sshKey against: %s", o.InfraID)
		for _, sshKey := range sshKeys.SSHKeys {
			o.Logger.Debugf("listPowerSSHKeys: sshKey: %s", *sshKey.Name)
		}
	}

	return cloudResources{}.insert(result...), nil
}

func (o *ClusterUninstaller) deletePowerSSHKey(item cloudResource) error {
	var err error

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("deletePowerSSHKey: case <-ctx.Done()")
		return o.Context.Err() // we're cancelled, abort
	default:
	}

	_, err = o.keyClient.Get(item.id)
	if err != nil {
		o.deletePendingItems(item.typeName, []cloudResource{item})
		o.Logger.Infof("Deleted Power SSHKey %q", item.name)
		return nil
	}

	err = o.keyClient.Delete(item.id)
	if err != nil {
		return errors.Wrapf(err, "failed to delete Power sshKey %s", item.name)
	}

	o.Logger.Infof("Deleted Power SSHKey %q", item.name)
	o.deletePendingItems(item.typeName, []cloudResource{item})

	return nil
}

// destroyPowerSSHKeys removes all ssh keys that have a name prefixed
// with the cluster's infra ID.
func (o *ClusterUninstaller) destroyPowerSSHKeys() error {
	firstPassList, err := o.listPowerSSHKeys()
	if err != nil {
		return err
	}

	if len(firstPassList.list()) == 0 {
		return nil
	}

	items := o.insertPendingItems(powerSSHKeyTypeName, firstPassList.list())

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	for _, item := range items {
		select {
		case <-ctx.Done():
			o.Logger.Debugf("destroyPowerSSHKeys: case <-ctx.Done()")
			return o.Context.Err() // we're cancelled, abort
		default:
		}

		backoff := wait.Backoff{
			Duration: 15 * time.Second,
			Factor:   1.1,
			Cap:      leftInContext(ctx),
			Steps:    math.MaxInt32}
		err = wait.ExponentialBackoffWithContext(ctx, backoff, func() (bool, error) {
			err2 := o.deletePowerSSHKey(item)
			if err2 == nil {
				return true, err2
			}
			o.errorTracker.suppressWarning(item.key, err2, o.Logger)
			return false, err2
		})
		if err != nil {
			o.Logger.Fatal("destroyPowerSSHKeys: ExponentialBackoffWithContext (destroy) returns ", err)
		}
	}

	if items = o.getPendingItems(powerSSHKeyTypeName); len(items) > 0 {
		for _, item := range items {
			o.Logger.Debugf("destroyPowerSSHKeys: found %s in pending items", item.name)
		}
		return errors.Errorf("destroyPowerSSHKeys: %d undeleted items pending", len(items))
	}

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func() (bool, error) {
		secondPassList, err2 := o.listPowerSSHKeys()
		if err2 != nil {
			return false, err2
		}
		if len(secondPassList) == 0 {
			// We finally don't see any remaining instances!
			return true, nil
		}
		for _, item := range secondPassList {
			o.Logger.Debugf("destroyPowerSSHKeys: found %s in second pass", item.name)
		}
		return false, nil
	})
	if err != nil {
		o.Logger.Fatal("destroyPowerSSHKeys: ExponentialBackoffWithContext (list) returns ", err)
	}

	return nil
}


const (
	publicGatewayTypeName = "publicGateway"
)

// listAttachedSubnets lists subnets attached to the specified publicGateway.
func (o *ClusterUninstaller) listAttachedSubnets(publicGatewayID string) (cloudResources, error) {
	o.Logger.Debugf("Finding subnets attached to public gateway %s", publicGatewayID)

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	options := o.vpcSvc.NewListSubnetsOptions()
	resources, _, err := o.vpcSvc.ListSubnetsWithContext(ctx, options)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to list subnets")
	}

	result := []cloudResource{}
	for _, subnet := range resources.Subnets {
		if subnet.PublicGateway != nil && *subnet.PublicGateway.ID == publicGatewayID {
			result = append(result, cloudResource{
				key:      *subnet.ID,
				name:     *subnet.Name,
				status:   *subnet.Status,
				typeName: subnetTypeName,
				id:       *subnet.ID,
			})
		}
	}

	return cloudResources{}.insert(result...), nil
}

// listPublicGateways lists publicGateways in the vpc.
func (o *ClusterUninstaller) listPublicGateways() (cloudResources, error) {
	var (
		ctx context.Context
		// https://raw.githubusercontent.com/IBM/vpc-go-sdk/master/vpcv1/vpc_v1.go
		listPublicGatewaysOptions *vpcv1.ListPublicGatewaysOptions
		publicGatewayCollection   *vpcv1.PublicGatewayCollection
		detailedResponse          *core.DetailedResponse
		err                       error
		moreData                  bool  = true
		foundOne                  bool  = false
		perPage                   int64 = 20
	)

	o.Logger.Debugf("Listing publicGateways")

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("listPublicGateways: case <-ctx.Done()")
		return nil, o.Context.Err() // we're cancelled, abort
	default:
	}

	listPublicGatewaysOptions = o.vpcSvc.NewListPublicGatewaysOptions()

	listPublicGatewaysOptions.SetLimit(perPage)

	result := []cloudResource{}

	for moreData {

		publicGatewayCollection, detailedResponse, err = o.vpcSvc.ListPublicGatewaysWithContext(ctx, listPublicGatewaysOptions)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to list publicGateways and the response is: %s", detailedResponse)
		}

		for _, publicGateway := range publicGatewayCollection.PublicGateways {
			if strings.Contains(*publicGateway.Name, o.InfraID) {
				foundOne = true
				o.Logger.Debugf("listPublicGateways: FOUND: %s", *publicGateway.Name)
				result = append(result, cloudResource{
					key:      *publicGateway.Name,
					name:     *publicGateway.Name,
					status:   "",
					typeName: publicGatewayTypeName,
					id:       *publicGateway.ID,
				})
			}
		}

		if publicGatewayCollection.First != nil {
			o.Logger.Debugf("listPublicGateways: First = %v", *publicGatewayCollection.First.Href)
		}
		if publicGatewayCollection.Limit != nil {
			o.Logger.Debugf("listPublicGateways: Limit = %v", *publicGatewayCollection.Limit)
		}
		if publicGatewayCollection.Next != nil {
			o.Logger.Debugf("listPublicGateways: Next = %v", *publicGatewayCollection.Next.Href)
			listPublicGatewaysOptions.SetStart(*publicGatewayCollection.Next.Href)
		}

		moreData = publicGatewayCollection.Next != nil
		o.Logger.Debugf("listPublicGateways: moreData = %v", moreData)
	}
	if !foundOne {
		o.Logger.Debugf("listPublicGateways: NO matching publicGateway against: %s", o.InfraID)

		listPublicGatewaysOptions = o.vpcSvc.NewListPublicGatewaysOptions()
		listPublicGatewaysOptions.SetLimit(perPage)

		for moreData {
			publicGatewayCollection, detailedResponse, err = o.vpcSvc.ListPublicGatewaysWithContext(ctx, listPublicGatewaysOptions)
			if err != nil {
				return nil, errors.Wrapf(err, "Failed to list publicGateways and the response is: %s", detailedResponse)
			}

			for _, publicGateway := range publicGatewayCollection.PublicGateways {
				o.Logger.Debugf("listPublicGateways: FOUND: %s", *publicGateway.Name)
			}
			if publicGatewayCollection.First != nil {
				o.Logger.Debugf("listPublicGateways: First = %v", *publicGatewayCollection.First.Href)
			}
			if publicGatewayCollection.Limit != nil {
				o.Logger.Debugf("listPublicGateways: Limit = %v", *publicGatewayCollection.Limit)
			}
			if publicGatewayCollection.Next != nil {
				o.Logger.Debugf("listPublicGateways: Next = %v", *publicGatewayCollection.Next.Href)
				listPublicGatewaysOptions.SetStart(*publicGatewayCollection.Next.Href)
			}
			moreData = publicGatewayCollection.Next != nil
			o.Logger.Debugf("listPublicGateways: moreData = %v", moreData)
		}
	}

	return cloudResources{}.insert(result...), nil
}

func (o *ClusterUninstaller) deletePublicGateway(item cloudResource) error {
	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("deletePublicGateway: case <-ctx.Done()")
		return o.Context.Err() // we're cancelled, abort
	default:
	}

	getPublicGatewayOptions := o.vpcSvc.NewGetPublicGatewayOptions(item.id)

	_, _, err := o.vpcSvc.GetPublicGatewayWithContext(ctx, getPublicGatewayOptions)
	if err != nil {
		o.Logger.Debugf("deletePublicGateway: publicGateway %q no longer exists", item.name)
		o.deletePendingItems(item.typeName, []cloudResource{item})
		o.Logger.Infof("Deleted Public Gateway %q", item.name)
		return nil
	}

	// Detach gateway from any subnets using it
	subnets, err := o.listAttachedSubnets(item.id)
	if err != nil {
		return errors.Wrapf(err, "failed to list subnets with gateway %s attached", item.name)
	}
	for _, subnet := range subnets {
		unsetSubnetPublicGatewayOptions := o.vpcSvc.NewUnsetSubnetPublicGatewayOptions(subnet.id)

		_, err = o.vpcSvc.UnsetSubnetPublicGatewayWithContext(ctx, unsetSubnetPublicGatewayOptions)
		if err != nil {
			return errors.Wrapf(err, "failed to detach publicGateway %s from subnet %s", item.name, subnet.id)
		}
	}

	deletePublicGatewayOptions := o.vpcSvc.NewDeletePublicGatewayOptions(item.id)

	_, err = o.vpcSvc.DeletePublicGatewayWithContext(ctx, deletePublicGatewayOptions)
	if err != nil {
		return errors.Wrapf(err, "failed to delete publicGateway %s", item.name)
	}

	o.Logger.Infof("Deleted Public Gateway %q", item.name)
	o.deletePendingItems(item.typeName, []cloudResource{item})

	return nil
}

// destroyPublicGateways removes all publicGateway resources that have a name prefixed
// with the cluster's infra ID.
func (o *ClusterUninstaller) destroyPublicGateways() error {
	firstPassList, err := o.listPublicGateways()
	if err != nil {
		return err
	}

	if len(firstPassList.list()) == 0 {
		return nil
	}

	items := o.insertPendingItems(publicGatewayTypeName, firstPassList.list())

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	for _, item := range items {
		select {
		case <-ctx.Done():
			o.Logger.Debugf("destroyPublicGateways: case <-ctx.Done()")
			return o.Context.Err() // we're cancelled, abort
		default:
		}

		backoff := wait.Backoff{
			Duration: 15 * time.Second,
			Factor:   1.1,
			Cap:      leftInContext(ctx),
			Steps:    math.MaxInt32}
		err = wait.ExponentialBackoffWithContext(ctx, backoff, func() (bool, error) {
			err2 := o.deletePublicGateway(item)
			if err2 == nil {
				return true, err2
			}
			o.errorTracker.suppressWarning(item.key, err2, o.Logger)
			return false, err2
		})
		if err != nil {
			o.Logger.Fatal("destroyPublicGateways: ExponentialBackoffWithContext (destroy) returns ", err)
		}
	}

	if items = o.getPendingItems(publicGatewayTypeName); len(items) > 0 {
		for _, item := range items {
			o.Logger.Debugf("destroyPublicGateways: found %s in pending items", item.name)
		}
		return errors.Errorf("destroyPublicGateways: %d undeleted items pending", len(items))
	}

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func() (bool, error) {
		secondPassList, err2 := o.listPublicGateways()
		if err2 != nil {
			return false, err2
		}
		if len(secondPassList) == 0 {
			// We finally don't see any remaining instances!
			return true, nil
		}
		for _, item := range secondPassList {
			o.Logger.Debugf("destroyPublicGateways: found %s in second pass", item.name)
		}
		return false, nil
	})
	if err != nil {
		o.Logger.Fatal("destroyPublicGateways: ExponentialBackoffWithContext (list) returns ", err)
	}

	return nil
}


const securityGroupTypeName = "security group"

// listSecurityGroups lists security groups in the vpc.
func (o *ClusterUninstaller) listSecurityGroups() (cloudResources, error) {
	o.Logger.Debugf("Listing security groups")

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("listSecurityGroups: case <-ctx.Done()")
		return nil, o.Context.Err() // we're cancelled, abort
	default:
	}

	options := o.vpcSvc.NewListSecurityGroupsOptions()
	resources, _, err := o.vpcSvc.ListSecurityGroupsWithContext(ctx, options)

	if err != nil {
		return nil, errors.Wrapf(err, "failed to list security groups")
	}

	var foundOne = false

	result := []cloudResource{}
	for _, securityGroup := range resources.SecurityGroups {
		if strings.Contains(*securityGroup.Name, o.InfraID) {
			foundOne = true
			o.Logger.Debugf("listSecurityGroups: FOUND: %s, %s", *securityGroup.ID, *securityGroup.Name)
			result = append(result, cloudResource{
				key:      *securityGroup.ID,
				name:     *securityGroup.Name,
				status:   "",
				typeName: securityGroupTypeName,
				id:       *securityGroup.ID,
			})
		}
	}
	if !foundOne {
		o.Logger.Debugf("listSecurityGroups: NO matching security group against: %s", o.InfraID)
		for _, securityGroup := range resources.SecurityGroups {
			o.Logger.Debugf("listSecurityGroups: security group: %s", *securityGroup.Name)
		}
	}

	return cloudResources{}.insert(result...), nil
}

func (o *ClusterUninstaller) deleteSecurityGroup(item cloudResource) error {
	var getOptions *vpcv1.GetSecurityGroupOptions
	var response *core.DetailedResponse
	var err error

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("deleteSecurityGroup: case <-ctx.Done()")
		return o.Context.Err() // we're cancelled, abort
	default:
	}

	getOptions = o.vpcSvc.NewGetSecurityGroupOptions(item.id)
	_, response, err = o.vpcSvc.GetSecurityGroup(getOptions)

	if err != nil && response != nil && response.StatusCode == gohttp.StatusNotFound {
		// The resource is gone
		o.deletePendingItems(item.typeName, []cloudResource{item})
		o.Logger.Infof("Deleted Security Group %q", item.name)
		return nil
	}
	if err != nil && response != nil && response.StatusCode == gohttp.StatusInternalServerError {
		o.Logger.Infof("deleteSecurityGroup: internal server error")
		return nil
	}

	deleteOptions := o.vpcSvc.NewDeleteSecurityGroupOptions(item.id)

	_, err = o.vpcSvc.DeleteSecurityGroupWithContext(ctx, deleteOptions)
	if err != nil {
		return errors.Wrapf(err, "failed to delete security group %s", item.name)
	}

	o.Logger.Infof("Deleted Security Group %q", item.name)
	o.deletePendingItems(item.typeName, []cloudResource{item})

	return nil
}

// destroySecurityGroups removes all security group resources that have a name prefixed
// with the cluster's infra ID.
func (o *ClusterUninstaller) destroySecurityGroups() error {
	firstPassList, err := o.listSecurityGroups()
	if err != nil {
		return err
	}

	if len(firstPassList.list()) == 0 {
		return nil
	}

	items := o.insertPendingItems(securityGroupTypeName, firstPassList.list())

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	for _, item := range items {
		select {
		case <-ctx.Done():
			o.Logger.Debugf("destroySecurityGroups: case <-ctx.Done()")
			return o.Context.Err() // we're cancelled, abort
		default:
		}

		backoff := wait.Backoff{
			Duration: 15 * time.Second,
			Factor:   1.1,
			Cap:      leftInContext(ctx),
			Steps:    math.MaxInt32}
		err = wait.ExponentialBackoffWithContext(ctx, backoff, func() (bool, error) {
			err2 := o.deleteSecurityGroup(item)
			if err2 == nil {
				return true, err2
			}
			o.errorTracker.suppressWarning(item.key, err2, o.Logger)
			return false, err2
		})
		if err != nil {
			o.Logger.Fatal("destroySecurityGroups: ExponentialBackoffWithContext (destroy) returns ", err)
		}
	}

	if items = o.getPendingItems(securityGroupTypeName); len(items) > 0 {
		for _, item := range items {
			o.Logger.Debugf("destroyServiceInstances: found %s in pending items", item.name)
		}
		return errors.Errorf("destroySecurityGroups: %d undeleted items pending", len(items))
	}

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func() (bool, error) {
		secondPassList, err2 := o.listSecurityGroups()
		if err2 != nil {
			return false, err2
		}
		if len(secondPassList) == 0 {
			// We finally don't see any remaining instances!
			return true, nil
		}
		for _, item := range secondPassList {
			o.Logger.Debugf("destroySecurityGroups: found %s in second pass", item.name)
		}
		return false, nil
	})
	if err != nil {
		o.Logger.Fatal("destroySecurityGroups: ExponentialBackoffWithContext (list) returns ", err)
	}

	return nil
}


const subnetTypeName = "subnet"

// listSubnets lists subnets in the cloud.
func (o *ClusterUninstaller) listSubnets() (cloudResources, error) {
	o.Logger.Debugf("Listing Subnets")

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("listSubnets: case <-ctx.Done()")
		return nil, o.Context.Err() // we're cancelled, abort
	default:
	}

	options := o.vpcSvc.NewListSubnetsOptions()
	subnets, detailedResponse, err := o.vpcSvc.ListSubnets(options)

	if err != nil {
		return nil, errors.Wrapf(err, "failed to list subnets and the response is: %s", detailedResponse)
	}

	var foundOne = false

	result := []cloudResource{}
	for _, subnet := range subnets.Subnets {
		if strings.Contains(*subnet.Name, o.InfraID) {
			foundOne = true
			o.Logger.Debugf("listSubnets: FOUND: %s, %s", *subnet.ID, *subnet.Name)
			result = append(result, cloudResource{
				key:      *subnet.ID,
				name:     *subnet.Name,
				status:   "",
				typeName: subnetTypeName,
				id:       *subnet.ID,
			})
		}
	}
	if !foundOne {
		o.Logger.Debugf("listSubnets: NO matching subnet against: %s", o.InfraID)
		for _, subnet := range subnets.Subnets {
			o.Logger.Debugf("listSubnets: subnet: %s", *subnet.Name)
		}
	}

	return cloudResources{}.insert(result...), nil
}

func (o *ClusterUninstaller) deleteSubnet(item cloudResource) error {
	var getOptions *vpcv1.GetSubnetOptions
	var response *core.DetailedResponse
	var err error

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("deleteSubnet: case <-ctx.Done()")
		return o.Context.Err() // we're cancelled, abort
	default:
	}

	getOptions = o.vpcSvc.NewGetSubnetOptions(item.id)
	_, response, err = o.vpcSvc.GetSubnet(getOptions)

	if err != nil && response != nil && response.StatusCode == gohttp.StatusNotFound {
		// The resource is gone
		o.deletePendingItems(item.typeName, []cloudResource{item})
		o.Logger.Infof("Deleted Subnet %q", item.name)
		return nil
	}
	if err != nil && response != nil && response.StatusCode == gohttp.StatusInternalServerError {
		o.Logger.Infof("deleteSubnet: internal server error")
		return nil
	}

	deleteOptions := o.vpcSvc.NewDeleteSubnetOptions(item.id)
	_, err = o.vpcSvc.DeleteSubnetWithContext(ctx, deleteOptions)
	if err != nil {
		return errors.Wrapf(err, "failed to delete subnet %s", item.name)
	}

	o.Logger.Infof("Deleted Subnet %q", item.name)
	o.deletePendingItems(item.typeName, []cloudResource{item})

	return nil
}

// destroySubnets removes all subnet resources that have a name prefixed
// with the cluster's infra ID.
func (o *ClusterUninstaller) destroySubnets() error {
	firstPassList, err := o.listSubnets()
	if err != nil {
		return err
	}

	if len(firstPassList.list()) == 0 {
		return nil
	}

	items := o.insertPendingItems(subnetTypeName, firstPassList.list())

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	for _, item := range items {
		select {
		case <-ctx.Done():
			o.Logger.Debugf("destroySubnets: case <-ctx.Done()")
			return o.Context.Err() // we're cancelled, abort
		default:
		}

		backoff := wait.Backoff{
			Duration: 15 * time.Second,
			Factor:   1.1,
			Cap:      leftInContext(ctx),
			Steps:    math.MaxInt32}
		err = wait.ExponentialBackoffWithContext(ctx, backoff, func() (bool, error) {
			err2 := o.deleteSubnet(item)
			if err2 == nil {
				return true, err2
			}
			o.errorTracker.suppressWarning(item.key, err2, o.Logger)
			return false, err2
		})
		if err != nil {
			o.Logger.Fatal("destroySubnets: ExponentialBackoffWithContext (destroy) returns ", err)
		}
	}

	if items = o.getPendingItems(subnetTypeName); len(items) > 0 {
		for _, item := range items {
			o.Logger.Debugf("destroySubnets: found %s in pending items", item.name)
		}
		return errors.Errorf("destroySubnets: %d undeleted items pending", len(items))
	}

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func() (bool, error) {
		secondPassList, err2 := o.listSubnets()
		if err2 != nil {
			return false, err2
		}
		if len(secondPassList) == 0 {
			// We finally don't see any remaining instances!
			return true, nil
		}
		for _, item := range secondPassList {
			o.Logger.Debugf("destroySubnets: found %s in second pass", item.name)
		}
		return false, nil
	})
	if err != nil {
		o.Logger.Fatal("destroySubnets: ExponentialBackoffWithContext (list) returns ", err)
	}

	return nil
}


const vpcTypeName = "vpc"

// listVPCs lists VPCs in the cloud.
func (o *ClusterUninstaller) listVPCs() (cloudResources, error) {
	o.Logger.Debugf("Listing VPCs")

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("listVPCs: case <-ctx.Done()")
		return nil, o.Context.Err() // we're cancelled, abort
	default:
	}

	options := o.vpcSvc.NewListVpcsOptions()
	vpcs, _, err := o.vpcSvc.ListVpcs(options)

	if err != nil {
		return nil, errors.Wrapf(err, "failed to list vps")
	}

	var foundOne = false

	result := []cloudResource{}
	for _, vpc := range vpcs.Vpcs {
		if strings.Contains(*vpc.Name, o.InfraID) {
			foundOne = true
			o.Logger.Debugf("listVPCs: FOUND: %s, %s", *vpc.ID, *vpc.Name)
			result = append(result, cloudResource{
				key:      *vpc.ID,
				name:     *vpc.Name,
				status:   "",
				typeName: vpcTypeName,
				id:       *vpc.ID,
			})
		}
	}
	if !foundOne {
		o.Logger.Debugf("listVPCs: NO matching vpc against: %s", o.InfraID)
		for _, vpc := range vpcs.Vpcs {
			o.Logger.Debugf("listVPCs: vpc: %s", *vpc.Name)
		}
	}

	return cloudResources{}.insert(result...), nil
}

func (o *ClusterUninstaller) deleteVPC(item cloudResource) error {
	var getOptions *vpcv1.GetVPCOptions
	var getResponse *core.DetailedResponse
	var deleteResponse *core.DetailedResponse
	var err error

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("deleteVPC: case <-ctx.Done()")
		return o.Context.Err() // we're cancelled, abort
	default:
	}

	getOptions = o.vpcSvc.NewGetVPCOptions(item.id)
	_, getResponse, err = o.vpcSvc.GetVPC(getOptions)

	o.Logger.Debugf("deleteVPC: getResponse = %v", getResponse)
	o.Logger.Debugf("deleteVPC: err = %v", err)

	// Sadly, there is no way to get the status of this VPC to check on the results of the
	// delete call.

	if err == nil && getResponse.StatusCode == gohttp.StatusNoContent {
		return nil
	}
	if err != nil && getResponse != nil && getResponse.StatusCode == gohttp.StatusNotFound {
		// The resource is gone
		o.deletePendingItems(item.typeName, []cloudResource{item})
		o.Logger.Infof("Deleted VPC %q", item.name)
		return nil
	}
	if err != nil && getResponse != nil && getResponse.StatusCode == gohttp.StatusInternalServerError {
		o.Logger.Infof("deleteVPC: internal server error")
		return nil
	}

	deleteOptions := o.vpcSvc.NewDeleteVPCOptions(item.id)
	deleteResponse, err = o.vpcSvc.DeleteVPCWithContext(ctx, deleteOptions)
	o.Logger.Debugf("deleteVPC: DeleteVPCWithContext returns %+v", deleteResponse)

	if err != nil {
		return errors.Wrapf(err, "failed to delete vpc %s", item.name)
	}

	o.Logger.Infof("Deleted VPC %q", item.name)
	o.deletePendingItems(item.typeName, []cloudResource{item})

	return nil
}

// destroyVPCs removes all vpc resources that have a name prefixed
// with the cluster's infra ID.
func (o *ClusterUninstaller) destroyVPCs() error {
	firstPassList, err := o.listVPCs()
	if err != nil {
		return err
	}

	if len(firstPassList.list()) == 0 {
		return nil
	}

	items := o.insertPendingItems(vpcTypeName, firstPassList.list())

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	for _, item := range items {
		select {
		case <-ctx.Done():
			o.Logger.Debugf("destroyVPCs: case <-ctx.Done()")
			return o.Context.Err() // we're cancelled, abort
		default:
		}

		backoff := wait.Backoff{
			Duration: 15 * time.Second,
			Factor:   1.1,
			Cap:      leftInContext(ctx),
			Steps:    math.MaxInt32}
		err = wait.ExponentialBackoffWithContext(ctx, backoff, func() (bool, error) {
			err2 := o.deleteVPC(item)
			if err2 == nil {
				return true, err2
			}
			o.errorTracker.suppressWarning(item.key, err2, o.Logger)
			return false, err2
		})
		if err != nil {
			o.Logger.Fatal("destroyVPCs: ExponentialBackoffWithContext (destroy) returns ", err)
		}
	}

	if items = o.getPendingItems(vpcTypeName); len(items) > 0 {
		for _, item := range items {
			o.Logger.Debugf("destroyVPCs: found %s in pending items", item.name)
		}
		return errors.Errorf("destroyVPCs: %d undeleted items pending", len(items))
	}

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func() (bool, error) {
		secondPassList, err2 := o.listVPCs()
		if err2 != nil {
			return false, err2
		}
		if len(secondPassList) == 0 {
			// We finally don't see any remaining instances!
			return true, nil
		}
		for _, item := range secondPassList {
			o.Logger.Debugf("destroyVPCs: found %s in second pass", item.name)
		}
		return false, nil
	})
	if err != nil {
		o.Logger.Fatal("destroyVPCs: ExponentialBackoffWithContext (list) returns ", err)
	}

	return nil
}
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
