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

const (
	cloudInstanceTypeName = "cloudInstance"
)

// listCloudInstances lists instances in the cloud server.
func (o *ClusterUninstaller) listCloudInstances() (cloudResources, error) {
	o.Logger.Debugf("Listing virtual Cloud service instances")

	ctx, cancel := contextWithTimeout()
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

	ctx, cancel := contextWithTimeout()
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

	if shouldDelete {
	response, err = o.vpcSvc.DeleteInstanceWithContext(ctx, deleteInstanceOptions)
	if err != nil {
		o.Logger.Infof("Error: o.vpcSvc.DeleteInstanceWithContext: %q %q", err, response)
		return err
	}
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
	ctx, cancel := contextWithTimeout()
	defer cancel()
	for _, item := range items {
		select {
		case <-ctx.Done():
			o.Logger.Debugf("destroyCloudInstances: case <-ctx.Done()")
			return ctx.Err() // we're cancelled, abort
		default:
		}

		backoff := wait.Backoff{
			Duration: 15 * time.Second,
			Factor:   1.1,
			Cap:      leftInContext(ctx),
			Steps:    math.MaxInt32}
		err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
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
		return fmt.Errorf("destroyCloudInstances: %d undeleted items pending", len(items))
	}

	if shouldDelete {
	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
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
	}

	return nil
}

const cosTypeName = "cos instance"

// $ ibmcloud catalog service cloud-object-storage --output json | jq -r '.[].id'
// dff97f5c-bc5e-4455-b470-411c3edbe49c.
const cosResourceID = "dff97f5c-bc5e-4455-b470-411c3edbe49c"

// listCOSInstances lists COS service instances.
// ibmcloud resource service-instances --output JSON --service-name cloud-object-storage | jq -r '.[] | select(.name|test("rdr-hamzy.*")) | "\(.name) - \(.id)"'
func (o *ClusterUninstaller) listCOSInstances() (cloudResources, error) {
	o.Logger.Debugf("Listing COS instances")

	ctx, cancel := contextWithTimeout()
	defer cancel()

	var (
		// https://github.com/IBM/platform-services-go-sdk/blob/main/resourcecontrollerv2/resource_controller_v2.go#L3086
		options *resourcecontrollerv2.ListResourceInstancesOptions

		perPage int64 = 64

		// https://github.com/IBM/platform-services-go-sdk/blob/main/resourcecontrollerv2/resource_controller_v2.go#L4525-L4534
		resources *resourcecontrollerv2.ResourceInstancesList

		err error

		foundOne = false
		moreData = true
	)

	options = o.controllerSvc.NewListResourceInstancesOptions()
	options.Limit = &perPage
	options.SetResourceID(cosResourceID)
	options.SetType("service_instance")

	result := []cloudResource{}

	for moreData {
		// https://github.com/IBM/platform-services-go-sdk/blob/main/resourcecontrollerv2/resource_controller_v2.go#L173
		resources, _, err = o.controllerSvc.ListResourceInstancesWithContext(ctx, options)
		if err != nil {
			return nil, fmt.Errorf("failed to list COS instances: %w", err)
		}
		o.Logger.Debugf("listCOSInstances: RowsCount %v", *resources.RowsCount)

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

		if resources.NextURL != nil {
			start, err := resources.GetNextStart()
			if err != nil {
				o.Logger.Debugf("listCOSInstances: err = %v", err)
				return nil, fmt.Errorf("failed to GetNextStart: %w", err)
			}
			if start != nil {
				o.Logger.Debugf("listCOSInstances: start = %v", *start)
				options.SetStart(*start)
			}
		} else {
			o.Logger.Debugf("listCOSInstances: NextURL = nil")
			moreData = false
		}
	}
	if !foundOne {
		options = o.controllerSvc.NewListResourceInstancesOptions()
		options.Limit = &perPage
		options.SetResourceID(cosResourceID)
		options.SetType("service_instance")

		moreData = true
		for moreData {
			// https://github.com/IBM/platform-services-go-sdk/blob/main/resourcecontrollerv2/resource_controller_v2.go#L173
			resources, _, err = o.controllerSvc.ListResourceInstancesWithContext(ctx, options)
			if err != nil {
				return nil, fmt.Errorf("failed to list COS instances: %w", err)
			}
			o.Logger.Debugf("listCOSInstances: RowsCount %v", *resources.RowsCount)
			if resources.NextURL != nil {
				o.Logger.Debugf("listCOSInstances: NextURL   %v", *resources.NextURL)
			}

			o.Logger.Debugf("listCOSInstances: NO matching COS instance against: %s", o.InfraID)
			for _, instance := range resources.Resources {
				o.Logger.Debugf("listCOSInstances: only found COS instance: %s", *instance.Name)
			}

			if resources.NextURL != nil {
				start, err := resources.GetNextStart()
				if err != nil {
					o.Logger.Debugf("listCOSInstances: err = %v", err)
					return nil, fmt.Errorf("failed to GetNextStart: %w", err)
				}
				if start != nil {
					o.Logger.Debugf("listCOSInstances: start = %v", *start)
					options.SetStart(*start)
				}
			} else {
				o.Logger.Debugf("listCOSInstances: NextURL = nil")
				moreData = false
			}
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

	ctx, cancel := contextWithTimeout()
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

	ctx, cancel := contextWithTimeout()
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

	if shouldDelete {
	if err != nil && response != nil && response.StatusCode != gohttp.StatusNotFound {
		return fmt.Errorf("failed to delete COS instance %s: %w", item.name, err)
	}

	var reclamation *resourcecontrollerv2.Reclamation

	cosInstance, reclamation = o.findReclaimedCOSInstance(item)
	if cosInstance != nil {
		var reclamationActionOptions *resourcecontrollerv2.RunReclamationActionOptions

		reclamationActionOptions = o.controllerSvc.NewRunReclamationActionOptions(*reclamation.ID, "reclaim")

		_, response, err = o.controllerSvc.RunReclamationActionWithContext(ctx, reclamationActionOptions)
		if err != nil {
			return fmt.Errorf("failed RunReclamationActionWithContext: %w", err)
		}
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

	ctx, cancel := contextWithTimeout()
	defer cancel()

	for _, item := range items {
		select {
		case <-ctx.Done():
			o.Logger.Debugf("destroyCOSInstances: case <-ctx.Done()")
			return ctx.Err() // we're cancelled, abort
		default:
		}

		backoff := wait.Backoff{
			Duration: 15 * time.Second,
			Factor:   1.1,
			Cap:      leftInContext(ctx),
			Steps:    math.MaxInt32}
		err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
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
		return fmt.Errorf("destroyCOSInstances: %d undeleted items pending", len(items))
	}

	if shouldDelete {
	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
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
		return "", fmt.Errorf("COS instance not found")
	}

	// Locate the installer's COS instance by name.
	for _, instance := range instanceList {
		if instance.name == fmt.Sprintf("%s-cos", o.InfraID) {
			o.cosInstanceID = instance.id
			return instance.id, nil
		}
	}
	return "", fmt.Errorf("COS instance not found")
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

	ctx, cancel := contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("listCloudSSHKeys: case <-ctx.Done()")
		return nil, ctx.Err() // we're cancelled, abort
	default:
	}

	listKeysOptions = o.vpcSvc.NewListKeysOptions()
	listKeysOptions.SetLimit(perPage)

	result := []cloudResource{}

	for moreData {
		sshKeyCollection, detailedResponse, err = o.vpcSvc.ListKeysWithContext(ctx, listKeysOptions)
		if err != nil {
			return nil, fmt.Errorf("failed to list Cloud ssh keys: %w and the response is: %s", err, detailedResponse)
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
			start, err := sshKeyCollection.GetNextStart()
			if err != nil {
				o.Logger.Debugf("listCloudSSHKeys: err = %v", err)
				return nil, fmt.Errorf("listCloudSSHKeys: failed to GetNextStart: %w", err)
			}
			if start != nil {
				o.Logger.Debugf("listCloudSSHKeys: start = %v", *start)
				listKeysOptions.SetStart(*start)
			}
		} else {
			o.Logger.Debugf("listCloudSSHKeys: Next = nil")
			moreData = false
		}
	}
	if !foundOne {
		o.Logger.Debugf("listCloudSSHKeys: NO matching sshKey against: %s", o.InfraID)

		listKeysOptions = o.vpcSvc.NewListKeysOptions()
		listKeysOptions.SetLimit(perPage)
		moreData = true

		for moreData {
			sshKeyCollection, detailedResponse, err = o.vpcSvc.ListKeysWithContext(ctx, listKeysOptions)
			if err != nil {
				return nil, fmt.Errorf("failed to list Cloud ssh keys: %w and the response is: %s", err, detailedResponse)
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
				start, err := sshKeyCollection.GetNextStart()
				if err != nil {
					o.Logger.Debugf("listCloudSSHKeys: err = %v", err)
					return nil, fmt.Errorf("listCloudSSHKeys: failed to GetNextStart: %w", err)
				}
				if start != nil {
					o.Logger.Debugf("listCloudSSHKeys: start = %v", *start)
					listKeysOptions.SetStart(*start)
				}
			} else {
				o.Logger.Debugf("listCloudSSHKeys: Next = nil")
				moreData = false
			}
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

	ctx, cancel := contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("deleteCloudSSHKey: case <-ctx.Done()")
		return ctx.Err() // we're cancelled, abort
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

	if shouldDelete {
	_, err = o.vpcSvc.DeleteKeyWithContext(ctx, deleteKeyOptions)
	if err != nil {
		return fmt.Errorf("failed to delete sshKey %s: %w", item.name, err)
	}
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

	ctx, cancel := contextWithTimeout()
	defer cancel()

	for _, item := range items {
		select {
		case <-ctx.Done():
			o.Logger.Debugf("destroyCloudSSHKeys: case <-ctx.Done()")
			return ctx.Err() // we're cancelled, abort
		default:
		}

		backoff := wait.Backoff{
			Duration: 15 * time.Second,
			Factor:   1.1,
			Cap:      leftInContext(ctx),
			Steps:    math.MaxInt32}
		err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
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
		return fmt.Errorf("destroyCloudSSHKeys: %d undeleted items pending", len(items))
	}

	if shouldDelete {
	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
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
	}

	return nil
}


// listCloudSubnets lists subnets in the VPC cloud.
func (o *ClusterUninstaller) listCloudSubnets() (cloudResources, error) {
	o.Logger.Debugf("Listing virtual Cloud Subnets")

	ctx, cancel := contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("listCloudSubnets: case <-ctx.Done()")
		return nil, ctx.Err() // we're cancelled, abort
	default:
	}

	options := o.vpcSvc.NewListSubnetsOptions()
	subnets, detailedResponse, err := o.vpcSvc.ListSubnets(options)

	if err != nil {
		return nil, fmt.Errorf("failed to list subnets and the response is: %s: %w", detailedResponse, err)
	}

	var foundOne = false

	result := []cloudResource{}
	for _, subnet := range subnets.Subnets {
		if strings.Contains(*subnet.Name, o.InfraID) {
			foundOne = true
			o.Logger.Debugf("listCloudSubnets: FOUND: %s, %s", *subnet.ID, *subnet.Name)
			result = append(result, cloudResource{
				key:      *subnet.ID,
				name:     *subnet.Name,
				status:   "",
				typeName: publicGatewayTypeName,
				id:       *subnet.ID,
			})
		}
	}
	if !foundOne {
		o.Logger.Debugf("listCloudSubnets: NO matching subnet against: %s", o.InfraID)
		for _, subnet := range subnets.Subnets {
			o.Logger.Debugf("listCloudSubnets: subnet: %s", *subnet.Name)
		}
	}

	return cloudResources{}.insert(result...), nil
}

func (o *ClusterUninstaller) deleteCloudSubnet(item cloudResource) error {
	var getOptions *vpcv1.GetSubnetOptions
	var response *core.DetailedResponse
	var err error

	ctx, cancel := contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("deleteCloudSubnet: case <-ctx.Done()")
		return ctx.Err() // we're cancelled, abort
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
		o.Logger.Infof("deleteCloudSubnet: internal server error")
		return nil
	}

	if shouldDelete {
	deleteOptions := o.vpcSvc.NewDeleteSubnetOptions(item.id)
	_, err = o.vpcSvc.DeleteSubnetWithContext(ctx, deleteOptions)
	if err != nil {
		return fmt.Errorf("failed to delete subnet %s: %w", item.name, err)
	}
	}

	o.Logger.Infof("Deleted Subnet %q", item.name)
	o.deletePendingItems(item.typeName, []cloudResource{item})

	return nil
}

// destroyCloudSubnets removes all subnet resources that have a name prefixed
// with the cluster's infra ID.
func (o *ClusterUninstaller) destroyCloudSubnets() error {
	firstPassList, err := o.listCloudSubnets()
	if err != nil {
		return err
	}

	if len(firstPassList.list()) == 0 {
		return nil
	}

	items := o.insertPendingItems(publicGatewayTypeName, firstPassList.list())

	ctx, cancel := contextWithTimeout()
	defer cancel()

	for _, item := range items {
		select {
		case <-ctx.Done():
			o.Logger.Debugf("destroyCloudSubnets: case <-ctx.Done()")
			return ctx.Err() // we're cancelled, abort
		default:
		}

		backoff := wait.Backoff{
			Duration: 15 * time.Second,
			Factor:   1.1,
			Cap:      leftInContext(ctx),
			Steps:    math.MaxInt32}
		err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
			err2 := o.deleteCloudSubnet(item)
			if err2 == nil {
				return true, err2
			}
			o.errorTracker.suppressWarning(item.key, err2, o.Logger)
			return false, err2
		})
		if err != nil {
			o.Logger.Fatal("destroyCloudSubnets: ExponentialBackoffWithContext (destroy) returns ", err)
		}
	}

	if items = o.getPendingItems(publicGatewayTypeName); len(items) > 0 {
		for _, item := range items {
			o.Logger.Debugf("destroyCloudSubnets: found %s in pending items", item.name)
		}
		return fmt.Errorf("destroyCloudSubnets: %d undeleted items pending", len(items))
	}

	if shouldDelete {
	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
		secondPassList, err2 := o.listCloudSubnets()
		if err2 != nil {
			return false, err2
		}
		if len(secondPassList) == 0 {
			// We finally don't see any remaining instances!
			return true, nil
		}
		for _, item := range secondPassList {
			o.Logger.Debugf("destroyCloudSubnets: found %s in second pass", item.name)
		}
		return false, nil
	})
	if err != nil {
		o.Logger.Fatal("destroyCloudSubnets: ExponentialBackoffWithContext (list) returns ", err)
	}
	}

	return nil
}

const (
	transitGatewayTypeName           = "transitGateway"
	transitGatewayConnectionTypeName = "transitGatewayConnection"
)

// listTransitGateways lists Transit Gateways in the IBM Cloud.
func (o *ClusterUninstaller) listTransitGateways() (cloudResources, error) {
	o.Logger.Debugf("Listing Transit Gateways (%s)", o.InfraID)

	var (
		ctx                        context.Context
		cancel                     func()
		listTransitGatewaysOptions *transitgatewayapisv1.ListTransitGatewaysOptions
		gatewayCollection          *transitgatewayapisv1.TransitGatewayCollection
		gateway                    transitgatewayapisv1.TransitGateway
		response                   *core.DetailedResponse
		err                        error
		foundOne                         = false
		perPage                    int64 = 32
		moreData                         = true
	)

	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	listTransitGatewaysOptions = o.tgClient.NewListTransitGatewaysOptions()
	listTransitGatewaysOptions.Limit = &perPage

	result := []cloudResource{}

	for moreData {
		// https://github.com/IBM/networking-go-sdk/blob/master/transitgatewayapisv1/transit_gateway_apis_v1.go#L184
		gatewayCollection, response, err = o.tgClient.ListTransitGatewaysWithContext(ctx, listTransitGatewaysOptions)
		if err != nil {
			return nil, fmt.Errorf("failed to list transit gateways: %w and the respose is: %s", err, response)
		}

		for _, gateway = range gatewayCollection.TransitGateways {
			if strings.Contains(*gateway.Name, o.InfraID) {
				foundOne = true
				o.Logger.Debugf("listTransitGateways: FOUND: %s, %s", *gateway.ID, *gateway.Name)
				result = append(result, cloudResource{
					key:      *gateway.ID,
					name:     *gateway.Name,
					status:   "",
					typeName: transitGatewayTypeName,
					id:       *gateway.ID,
				})
			}
		}

		if gatewayCollection.First != nil {
			o.Logger.Debugf("listTransitGateways: First = %+v", *gatewayCollection.First.Href)
		} else {
			o.Logger.Debugf("listTransitGateways: First = nil")
		}
		if gatewayCollection.Limit != nil {
			o.Logger.Debugf("listTransitGateways: Limit = %v", *gatewayCollection.Limit)
		}
		if gatewayCollection.Next != nil {
			start, err := gatewayCollection.GetNextStart()
			if err != nil {
				o.Logger.Debugf("listTransitGateways: err = %v", err)
				return nil, fmt.Errorf("listTransitGateways: failed to GetNextStart: %w", err)
			}
			if start != nil {
				o.Logger.Debugf("listTransitGateways: start = %v", *start)
				listTransitGatewaysOptions.SetStart(*start)
			}
		} else {
			o.Logger.Debugf("listTransitGateways: Next = nil")
			moreData = false
		}
	}
	if !foundOne {
		o.Logger.Debugf("listTransitGateways: NO matching transit gateway against: %s", o.InfraID)

		listTransitGatewaysOptions = o.tgClient.NewListTransitGatewaysOptions()
		listTransitGatewaysOptions.Limit = &perPage
		moreData = true

		for moreData {
			gatewayCollection, response, err = o.tgClient.ListTransitGatewaysWithContext(ctx, listTransitGatewaysOptions)
			if err != nil {
				return nil, fmt.Errorf("failed to list transit gateways: %w and the respose is: %s", err, response)
			}
			for _, gateway = range gatewayCollection.TransitGateways {
				o.Logger.Debugf("listTransitGateways: FOUND: %s, %s", *gateway.ID, *gateway.Name)
			}
			if gatewayCollection.First != nil {
				o.Logger.Debugf("listTransitGateways: First = %+v", *gatewayCollection.First.Href)
			} else {
				o.Logger.Debugf("listTransitGateways: First = nil")
			}
			if gatewayCollection.Limit != nil {
				o.Logger.Debugf("listTransitGateways: Limit = %v", *gatewayCollection.Limit)
			}
			if gatewayCollection.Next != nil {
				start, err := gatewayCollection.GetNextStart()
				if err != nil {
					o.Logger.Debugf("listTransitGateways: err = %v", err)
					return nil, fmt.Errorf("listTransitGateways: failed to GetNextStart: %w", err)
				}
				if start != nil {
					o.Logger.Debugf("listTransitGateways: start = %v", *start)
					listTransitGatewaysOptions.SetStart(*start)
				}
			} else {
				o.Logger.Debugf("listTransitGateways: Next = nil")
				moreData = false
			}
		}
	}

	return cloudResources{}.insert(result...), nil
}

// Destroy a specified transit gateway.
func (o *ClusterUninstaller) destroyTransitGateway(item cloudResource) error {
	var (
		deleteTransitGatewayOptions *transitgatewayapisv1.DeleteTransitGatewayOptions
		response                    *core.DetailedResponse
		err                         error

		ctx    context.Context
		cancel func()
	)

	ctx, cancel = contextWithTimeout()
	defer cancel()

	err = o.destroyTransitGatewayConnections(item)
	if err != nil {
		return err
	}

	// We can delete the transit gateway now!
	deleteTransitGatewayOptions = o.tgClient.NewDeleteTransitGatewayOptions(item.id)

	if shouldDelete {
	response, err = o.tgClient.DeleteTransitGatewayWithContext(ctx, deleteTransitGatewayOptions)
	if err != nil {
		o.Logger.Fatalf("destroyTransitGateway: DeleteTransitGatewayWithContext returns %v with response %v", err, response)
	}
	}

	o.deletePendingItems(item.typeName, []cloudResource{item})
	o.Logger.Infof("Deleted Transit Gateway %q", item.name)

	return nil
}

// Destroy the connections for a specified transit gateway.
func (o *ClusterUninstaller) destroyTransitGatewayConnections(item cloudResource) error {
	var (
		firstPassList cloudResources

		err error

		items []cloudResource

		ctx    context.Context
		cancel func()

		backoff = wait.Backoff{Duration: 15 * time.Second,
			Factor: 1.5,
			Cap:    10 * time.Minute,
			Steps:  math.MaxInt32}
	)

	firstPassList, err = o.listTransitConnections(item)
	if err != nil {
		return err
	}

	items = o.insertPendingItems(transitGatewayConnectionTypeName, firstPassList.list())

	ctx, cancel = contextWithTimeout()
	defer cancel()

	for _, item := range items {
		select {
		case <-ctx.Done():
			o.Logger.Debugf("destroyTransitGateway: case <-ctx.Done()")
			return ctx.Err() // we're cancelled, abort
		default:
		}

		err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
			err2 := o.destroyTransitConnection(item)
			if err2 == nil {
				return true, err2
			}
			o.errorTracker.suppressWarning(item.key, err2, o.Logger)
			return false, err2
		})
		if err != nil {
			o.Logger.Fatalf("destroyTransitGateway: ExponentialBackoffWithContext (destroy) returns %v", err)
		}
	}

	if items = o.getPendingItems(transitGatewayConnectionTypeName); len(items) > 0 {
		return fmt.Errorf("destroyTransitGateway: %d undeleted items pending", len(items))
	}

	if shouldDelete {
	backoff = wait.Backoff{Duration: 15 * time.Second,
		Factor: 1.5,
		Cap:    10 * time.Minute,
		Steps:  math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
		var (
			secondPassList cloudResources

			err2 error
		)

		secondPassList, err2 = o.listTransitConnections(item)
		if err2 != nil {
			return false, err2
		}
		if len(secondPassList) == 0 {
			// We finally don't see any remaining instances!
			return true, nil
		}
		for _, item := range secondPassList {
			o.Logger.Debugf("destroyTransitGateway: found %s in second pass", item.name)
		}
		return false, nil
	})
	if err != nil {
		o.Logger.Fatalf("destroyTransitGateway: ExponentialBackoffWithContext (list) returns %v", err)
	}
	}

	return err
}

// Destroy a specified transit gateway connection.
func (o *ClusterUninstaller) destroyTransitConnection(item cloudResource) error {
	var (
		ctx    context.Context
		cancel func()

		deleteTransitGatewayConnectionOptions *transitgatewayapisv1.DeleteTransitGatewayConnectionOptions
		response                              *core.DetailedResponse
		err                                   error
	)

	ctx, cancel = contextWithTimeout()
	defer cancel()

	// ...Options(transitGatewayID string, id string)
	// NOTE: item.status is reused as the parent transit gateway id!
	deleteTransitGatewayConnectionOptions = o.tgClient.NewDeleteTransitGatewayConnectionOptions(item.status, item.id)

	if shouldDelete {
	response, err = o.tgClient.DeleteTransitGatewayConnectionWithContext(ctx, deleteTransitGatewayConnectionOptions)
	if err != nil {
		o.Logger.Fatalf("destroyTransitConnection: DeleteTransitGatewayConnectionWithContext returns %v with response %v", err, response)
	}
	}

	o.deletePendingItems(item.typeName, []cloudResource{item})
	o.Logger.Infof("Deleted Transit Gateway Connection %q", item.name)

	return nil
}

// listTransitConnections lists Transit Connections for a Transit Gateway in the IBM Cloud.
func (o *ClusterUninstaller) listTransitConnections(item cloudResource) (cloudResources, error) {
	o.Logger.Debugf("Listing Transit Gateways Connections (%s)", item.name)

	var (
		ctx                          context.Context
		cancel                       func()
		listConnectionsOptions       *transitgatewayapisv1.ListConnectionsOptions
		transitConnectionCollections *transitgatewayapisv1.TransitConnectionCollection
		transitConnection            transitgatewayapisv1.TransitConnection
		response                     *core.DetailedResponse
		err                          error
		foundOne                           = false
		perPage                      int64 = 32
		moreData                           = true
	)

	ctx, cancel = contextWithTimeout()
	defer cancel()

	o.Logger.Debugf("listTransitConnections: searching for ID %s", item.id)

	listConnectionsOptions = o.tgClient.NewListConnectionsOptions()
	listConnectionsOptions.SetLimit(perPage)
	listConnectionsOptions.SetNetworkID("")

	result := []cloudResource{}

	for moreData {
		transitConnectionCollections, response, err = o.tgClient.ListConnectionsWithContext(ctx, listConnectionsOptions)
		if err != nil {
			o.Logger.Debugf("listTransitConnections: ListConnections returns %v and the response is: %s", err, response)
			return nil, err
		}
		for _, transitConnection = range transitConnectionCollections.Connections {
			if *transitConnection.TransitGateway.ID != item.id {
				o.Logger.Debugf("listTransitConnections: SKIP: %s, %s, %s", *transitConnection.ID, *transitConnection.Name, *transitConnection.TransitGateway.Name)
				continue
			}

			foundOne = true
			o.Logger.Debugf("listTransitConnections: FOUND: %s, %s, %s", *transitConnection.ID, *transitConnection.Name, *transitConnection.TransitGateway.Name)
			result = append(result, cloudResource{
				key:      *transitConnection.ID,
				name:     *transitConnection.Name,
				status:   *transitConnection.TransitGateway.ID,
				typeName: transitGatewayConnectionTypeName,
				id:       *transitConnection.ID,
			})
		}

		if transitConnectionCollections.First != nil {
			o.Logger.Debugf("listTransitConnections: First = %+v", *transitConnectionCollections.First)
		} else {
			o.Logger.Debugf("listTransitConnections: First = nil")
		}
		if transitConnectionCollections.Limit != nil {
			o.Logger.Debugf("listTransitConnections: Limit = %v", *transitConnectionCollections.Limit)
		}
		if transitConnectionCollections.Next != nil {
			start, err := transitConnectionCollections.GetNextStart()
			if err != nil {
				o.Logger.Debugf("listTransitConnections: err = %v", err)
				return nil, fmt.Errorf("listTransitConnections: failed to GetNextStart: %w", err)
			}
			if start != nil {
				o.Logger.Debugf("listTransitConnections: start = %v", *start)
				listConnectionsOptions.SetStart(*start)
			}
		} else {
			o.Logger.Debugf("listTransitConnections: Next = nil")
			moreData = false
		}
	}
	if !foundOne {
		o.Logger.Debugf("listTransitConnections: NO matching transit connections against: %s", o.InfraID)

		listConnectionsOptions = o.tgClient.NewListConnectionsOptions()
		listConnectionsOptions.SetLimit(perPage)
		listConnectionsOptions.SetNetworkID("")
		moreData = true

		for moreData {
			transitConnectionCollections, response, err = o.tgClient.ListConnectionsWithContext(ctx, listConnectionsOptions)
			if err != nil {
				o.Logger.Debugf("listTransitConnections: ListConnections returns %v and the response is: %s", err, response)
				return nil, err
			}
			for _, transitConnection = range transitConnectionCollections.Connections {
				o.Logger.Debugf("listTransitConnections: FOUND: %s, %s, %s", *transitConnection.ID, *transitConnection.Name, *transitConnection.TransitGateway.Name)
			}
			if transitConnectionCollections.First != nil {
				o.Logger.Debugf("listTransitConnections: First = %+v", *transitConnectionCollections.First)
			} else {
				o.Logger.Debugf("listTransitConnections: First = nil")
			}
			if transitConnectionCollections.Limit != nil {
				o.Logger.Debugf("listTransitConnections: Limit = %v", *transitConnectionCollections.Limit)
			}
			if transitConnectionCollections.Next != nil {
				start, err := transitConnectionCollections.GetNextStart()
				if err != nil {
					o.Logger.Debugf("listTransitConnections: err = %v", err)
					return nil, fmt.Errorf("listTransitConnections: failed to GetNextStart: %w", err)
				}
				if start != nil {
					o.Logger.Debugf("listTransitConnections: start = %v", *start)
					listConnectionsOptions.SetStart(*start)
				}
			} else {
				o.Logger.Debugf("listTransitConnections: Next = nil")
				moreData = false
			}
		}
	}

	return cloudResources{}.insert(result...), nil
}

// We either deal with an existing TG or destroy TGs matching a name.
func (o *ClusterUninstaller) destroyTransitGateways() error {
	// Old style: delete all TGs matching by name
	if o.TransitGatewayName == "" {
		return o.innerDestroyTransitGateways()
	}

	// New style: leave the TG and its existing connections alone
	o.Logger.Infof("Not cleaning up persistent Transit Gateway since tgName was specified")
	return nil
}

// innerDestroyTransitGateways searches for transit gateways that have a name that starts with
// the cluster's infra ID.
func (o *ClusterUninstaller) innerDestroyTransitGateways() error {
	var (
		firstPassList cloudResources

		err error

		items []cloudResource

		ctx    context.Context
		cancel func()

		backoff = wait.Backoff{Duration: 15 * time.Second,
			Factor: 1.5,
			Cap:    10 * time.Minute,
			Steps:  math.MaxInt32}
	)

	firstPassList, err = o.listTransitGateways()
	if err != nil {
		return err
	}

	items = o.insertPendingItems(transitGatewayTypeName, firstPassList.list())

	ctx, cancel = contextWithTimeout()
	defer cancel()

	for _, item := range items {
		select {
		case <-ctx.Done():
			o.Logger.Debugf("destroyTransitGateways: case <-ctx.Done()")
			return ctx.Err() // we're cancelled, abort
		default:
		}

		err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
			err2 := o.destroyTransitGateway(item)
			if err2 == nil {
				return true, err2
			}
			o.errorTracker.suppressWarning(item.key, err2, o.Logger)
			return false, err2
		})
		if err != nil {
			o.Logger.Fatalf("destroyTransitGateways: ExponentialBackoffWithContext (destroy) returns %v", err)
		}
	}

	if items = o.getPendingItems(transitGatewayTypeName); len(items) > 0 {
		return fmt.Errorf("destroyTransitGateways: %d undeleted items pending", len(items))
	}

	if shouldDelete {
	backoff = wait.Backoff{Duration: 15 * time.Second,
		Factor: 1.5,
		Cap:    10 * time.Minute,
		Steps:  math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
		var (
			secondPassList cloudResources

			err2 error
		)

		secondPassList, err2 = o.listTransitGateways()
		if err2 != nil {
			return false, err2
		}
		if len(secondPassList) == 0 {
			// We finally don't see any remaining instances!
			return true, nil
		}
		for _, item := range secondPassList {
			o.Logger.Debugf("destroyTransitGateways: found %s in second pass", item.name)
		}
		return false, nil
	})
	if err != nil {
		o.Logger.Fatalf("destroyTransitGateways: ExponentialBackoffWithContext (list) returns %v", err)
	}
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

	if o.dhcpClient == nil {
		o.Logger.Infof("Skipping deleting DHCP servers because no service instance was found")
		result := []cloudResource{}
		return cloudResources{}.insert(result...), nil
	}

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
			// https://github.com/IBM-Cloud/power-go-client/blob/master/power/models/p_vm_instance.go#L22
			var instance *models.PVMInstance

			o.Logger.Debugf("listDHCPNetworks: DHCP has empty Network.Name: %s", *dhcpServer.ID)

			instance, err = o.instanceClient.Get(*dhcpServer.ID)
			o.Logger.Debugf("listDHCPNetworks: Getting instance %s %v", *dhcpServer.ID, err)
			if err != nil {
				continue
			}

			if instance.Status == nil {
				continue
			}
			// If there is a backing DHCP VM and it has a status, then check for an ERROR state
			o.Logger.Debugf("listDHCPNetworks: instance.Status: %s", *instance.Status)
			if *instance.Status != "ERROR" {
				continue
			}

			foundOne = true
			result = append(result, cloudResource{
				key:      *dhcpServer.ID,
				name:     *dhcpServer.ID,
				status:   "VM",
				typeName: dhcpTypeName,
				id:       *dhcpServer.ID,
			})
			continue
		}

		if strings.Contains(*dhcpServer.Network.Name, o.InfraID) {
			o.Logger.Debugf("listDHCPNetworks: FOUND: %s (%s)", *dhcpServer.Network.Name, *dhcpServer.ID)
			foundOne = true
			result = append(result, cloudResource{
				key:      *dhcpServer.ID,
				name:     *dhcpServer.Network.Name,
				status:   "DHCP",
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

	if shouldDelete {
	err = o.dhcpClient.Delete(item.id)
	if err != nil {
		o.Logger.Infof("Error: o.dhcpClient.Delete: %q", err)
		return err
	}
	}

	o.deletePendingItems(item.typeName, []cloudResource{item})
	o.Logger.Infof("Deleted DHCP Network %q", item.name)

	return nil
}

func (o *ClusterUninstaller) destroyDHCPVM(item cloudResource) error {
	var err error

	_, err = o.instanceClient.Get(item.id)
	if err != nil {
		o.deletePendingItems(item.typeName, []cloudResource{item})
		o.Logger.Infof("Deleted DHCP VM %q", item.name)
		return nil
	}

	o.Logger.Debugf("Deleting DHCP VM %q", item.name)

	if shouldDelete {
	err = o.instanceClient.Delete(item.id)
	if err != nil {
		o.Logger.Infof("Error: DHCP o.instanceClient.Delete: %q", err)
		return err
	}
	}

	o.deletePendingItems(item.typeName, []cloudResource{item})
	o.Logger.Infof("Deleted DHCP VM %q", item.name)

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

	ctx, cancel := contextWithTimeout()
	defer cancel()

	for _, item := range items {
		select {
		case <-ctx.Done():
			o.Logger.Debugf("destroyDHCPNetworks: case <-ctx.Done()")
			return ctx.Err() // we're cancelled, abort
		default:
		}

		backoff := wait.Backoff{
			Duration: 15 * time.Second,
			Factor:   1.1,
			Cap:      leftInContext(ctx),
			Steps:    math.MaxInt32}
		err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
			var err2 error

			switch item.status {
			case "DHCP":
				err2 = o.destroyDHCPNetwork(item)
			case "VM":
				err2 = o.destroyDHCPVM(item)
			default:
				err2 = fmt.Errorf("unknown DHCP item status %s", item.status)
				return true, err2
			}
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
		return fmt.Errorf("destroyDHCPNetworks: %d undeleted items pending", len(items))
	}

	if shouldDelete {
	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
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
	}

	return nil
}

const (
	cisDNSRecordTypeName = "cis dns record"
)

// listDNSRecords lists DNS records for the cluster.
func (o *ClusterUninstaller) listDNSRecords() (cloudResources, error) {
	o.Logger.Debugf("Listing DNS records")

	ctx, cancel := contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("listDNSRecords: case <-ctx.Done()")
		return nil, ctx.Err() // we're cancelled, abort
	default:
	}

	var (
		foundOne       = false
		perPage  int64 = 20
		page     int64 = 1
		moreData       = true
	)

	dnsRecordsOptions := o.dnsRecordsSvc.NewListAllDnsRecordsOptions()
	dnsRecordsOptions.PerPage = &perPage
	dnsRecordsOptions.Page = &page

	result := []cloudResource{}

	dnsMatcher, err := regexp.Compile(fmt.Sprintf(`.*\Q%s.%s\E$`, o.ClusterName, o.BaseDomain))
	if err != nil {
		return nil, fmt.Errorf("failed to build DNS records matcher: %w", err)
	}

	for moreData {
		dnsResources, detailedResponse, err := o.dnsRecordsSvc.ListAllDnsRecordsWithContext(ctx, dnsRecordsOptions)
		if err != nil {
			return nil, fmt.Errorf("failed to list DNS records: %w and the response is: %s", err, detailedResponse)
		}

		for _, record := range dnsResources.Result {
			// Match all of the cluster's DNS records
			nameMatches := dnsMatcher.Match([]byte(*record.Name))
			contentMatches := dnsMatcher.Match([]byte(*record.Content))
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
				return nil, fmt.Errorf("failed to list DNS records: %w and the response is: %s", err, detailedResponse)
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

	ctx, cancel := contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("destroyDNSRecord: case <-ctx.Done()")
		return ctx.Err() // we're cancelled, abort
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

	if shouldDelete {
	_, _, err = o.dnsRecordsSvc.DeleteDnsRecordWithContext(ctx, deleteOptions)
	if err != nil {
		return fmt.Errorf("failed to delete DNS record %s: %w", item.name, err)
	}
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

	ctx, cancel := contextWithTimeout()
	defer cancel()

	for _, item := range items {
		select {
		case <-ctx.Done():
			o.Logger.Debugf("destroyDNSRecords: case <-ctx.Done()")
			return ctx.Err() // we're cancelled, abort
		default:
		}

		backoff := wait.Backoff{
			Duration: 15 * time.Second,
			Factor:   1.1,
			Cap:      leftInContext(ctx),
			Steps:    math.MaxInt32}
		err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
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
		return fmt.Errorf("destroyDNSRecords: %d undeleted items pending", len(items))
	}

	if shouldDelete {
	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
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
	}

	return nil
}

const (
	ibmDNSRecordTypeName = "ibm dns record"
)

// listResourceRecords lists DNS Resource records for the cluster.
func (o *ClusterUninstaller) listResourceRecords() (cloudResources, error) {
	o.Logger.Debugf("Listing DNS resource records")

	ctx, cancel := contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("listResourceRecords: case <-ctx.Done()")
		return nil, ctx.Err() // we're cancelled, abort
	default:
	}

	result := []cloudResource{}

	dnsCRN, err := crn.Parse(o.DNSInstanceCRN)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DNSInstanceCRN: %w", err)
	}
	records, _, err := o.resourceRecordsSvc.ListResourceRecords(&resourcerecordsv1.ListResourceRecordsOptions{
		InstanceID: &dnsCRN.ServiceInstance,
		DnszoneID:  &o.dnsZoneID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list resource records: %w", err)
	}

	dnsMatcher, err := regexp.Compile(fmt.Sprintf(`.*\Q%s.%s\E$`, o.ClusterName, o.BaseDomain))
	if err != nil {
		return nil, fmt.Errorf("failed to build DNS records matcher: %w", err)
	}

	for _, record := range records.ResourceRecords {
		// Match all of the cluster's DNS records
		nameMatches := dnsMatcher.Match([]byte(*record.Name))
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
		return nil, fmt.Errorf("could not retrieve DNS records: %w", err)
	}
	return cloudResources{}.insert(result...), nil
}

// destroyResourceRecord destroys a Resource Record.
func (o *ClusterUninstaller) destroyResourceRecord(item cloudResource) error {
	var (
		response *core.DetailedResponse
		err      error
	)

	ctx, cancel := contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("destroyResourceRecord: case <-ctx.Done()")
		return ctx.Err() // we're cancelled, abort
	default:
	}

	if err != nil {
		return fmt.Errorf("failed to delete DNS Resource record %s: %w", item.name, err)
	}
	dnsCRN, err := crn.Parse(o.DNSInstanceCRN)
	if err != nil {
		return fmt.Errorf("failed to parse DNSInstanceCRN: %w", err)
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

	if shouldDelete {
	_, err = o.resourceRecordsSvc.DeleteResourceRecord(deleteOptions)
	if err != nil {
		return fmt.Errorf("failed to delete DNS Resource record %s: %w", item.name, err)
	}
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

	ctx, cancel := contextWithTimeout()
	defer cancel()

	for _, item := range items {
		select {
		case <-ctx.Done():
			o.Logger.Debugf("destroyResourceRecords: case <-ctx.Done()")
			return ctx.Err() // we're cancelled, abort
		default:
		}

		backoff := wait.Backoff{
			Duration: 15 * time.Second,
			Factor:   1.1,
			Cap:      leftInContext(ctx),
			Steps:    math.MaxInt32}
		err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
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
		return fmt.Errorf("destroyResourceRecords: %d undeleted items pending", len(items))
	}

	if shouldDelete {
	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
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

	if o.imageClient == nil {
		o.Logger.Infof("Skipping deleting images because no service instance was found")
		result := []cloudResource{}
		return cloudResources{}.insert(result...), nil
	}

	ctx, cancel := contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("listImages: case <-ctx.Done()")
		return nil, ctx.Err() // we're cancelled, abort
	default:
	}

	images, err := o.imageClient.GetAll()
	if err != nil {
		return nil, fmt.Errorf("failed to list images: %w", err)
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

	ctx, cancel := contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("deleteImage: case <-ctx.Done()")
		return ctx.Err() // we're cancelled, abort
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

	if shouldDelete {
	err = o.imageClient.Delete(item.id)
	if err != nil {
		return fmt.Errorf("failed to delete image %s: %w", item.name, err)
	}
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

	ctx, cancel := contextWithTimeout()
	defer cancel()

	for _, item := range items {
		select {
		case <-ctx.Done():
			o.Logger.Debugf("destroyImages: case <-ctx.Done()")
			return ctx.Err() // we're cancelled, abort
		default:
		}

		backoff := wait.Backoff{
			Duration: 15 * time.Second,
			Factor:   1.1,
			Cap:      leftInContext(ctx),
			Steps:    math.MaxInt32}
		err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
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
		return fmt.Errorf("destroyImages: %d undeleted items pending", len(items))
	}

	if shouldDelete {
	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
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

	if o.jobClient == nil {
		result := []cloudResource{}
		return cloudResources{}.insert(result...), nil
	}

	ctx, cancel := contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("listJobs: case <-ctx.Done()")
		return nil, ctx.Err() // we're cancelled, abort
	default:
	}

	jobs, err = o.jobClient.GetAll()
	if err != nil {
		return nil, fmt.Errorf("failed to list jobs: %w", err)
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

	ctx, cancel := contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("deleteJob: case <-ctx.Done()")
		return DeleteJobError, ctx.Err() // we're cancelled, abort
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
		//			return DeleteJobError, fmt.Errorf("failed to delete job %s: %w", item.name, err)
		//		}

		o.deletePendingItems(item.typeName, []cloudResource{item})
		o.Logger.Debugf("Deleting job %q", item.name)

		return DeleteJobSuccess, nil

	case "active":
		o.Logger.Debugf("Waiting for job %q to delete (status is %q)", item.name, *job.Status.State)
		return DeleteJobRunning, nil

	case "failed":
		err = fmt.Errorf("@TODO we cannot query error message inside the job")
		return DeleteJobError, fmt.Errorf("job %v has failed: %w", item.id, err)

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

	ctx, cancel := contextWithTimeout()
	defer cancel()

	for _, item := range items {
		select {
		case <-ctx.Done():
			o.Logger.Debugf("destroyJobs: case <-ctx.Done()")
			return ctx.Err() // we're cancelled, abort
		default:
		}

		backoff := wait.Backoff{
			Duration: 15 * time.Second,
			Factor:   1.1,
			Cap:      leftInContext(ctx),
			Steps:    math.MaxInt32}
		err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
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
				return false, fmt.Errorf("destroyJobs: deleteJob unknown result enum %v", result)
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
		return fmt.Errorf("destroyJobs: %d undeleted items pending", len(items))
	}

	if shouldDelete {
	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
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
	}

	return nil
}

const loadBalancerTypeName = "load balancer"

// listLoadBalancers lists load balancers in the vpc.
func (o *ClusterUninstaller) listLoadBalancers() (cloudResources, error) {
	o.Logger.Debugf("Listing load balancers")

	ctx, cancel := contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("listLoadBalancers: case <-ctx.Done()")
		return nil, ctx.Err() // we're cancelled, abort
	default:
	}

	options := o.vpcSvc.NewListLoadBalancersOptions()

	resources, _, err := o.vpcSvc.ListLoadBalancersWithContext(ctx, options)
	if err != nil {
		return nil, fmt.Errorf("failed to list load balancers: %w", err)
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

	ctx, cancel := contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("deleteLoadBalancer: case <-ctx.Done()")
		return ctx.Err() // we're cancelled, abort
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

	if shouldDelete {
	_, err = o.vpcSvc.DeleteLoadBalancerWithContext(ctx, deleteOptions)
	if err != nil {
		return fmt.Errorf("failed to delete load balancer %s: %w", item.name, err)
	}
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

	ctx, cancel := contextWithTimeout()
	defer cancel()

	for _, item := range items {
		select {
		case <-ctx.Done():
			o.Logger.Debugf("destroyLoadBalancers: case <-ctx.Done()")
			return ctx.Err() // we're cancelled, abort
		default:
		}

		backoff := wait.Backoff{
			Duration: 15 * time.Second,
			Factor:   1.1,
			Cap:      leftInContext(ctx),
			Steps:    math.MaxInt32}
		err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
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
		return fmt.Errorf("destroyLoadBalancers: %d undeleted items pending", len(items))
	}

	if shouldDelete {
	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
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
	}

	return nil
}

const (
	powerInstanceTypeName = "powerInstance"
)

// listPowerInstances lists instances in the power server.
func (o *ClusterUninstaller) listPowerInstances() (cloudResources, error) {
	o.Logger.Debugf("Listing virtual Power service instances (%s)", o.InfraID)

	if o.instanceClient == nil {
		o.Logger.Infof("Skipping deleting Power service instances because no service instance was found")
		result := []cloudResource{}
		return cloudResources{}.insert(result...), nil
	}

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

	if shouldDelete {
	err = o.instanceClient.Delete(item.id)
	if err != nil {
		o.Logger.Infof("Error: o.instanceClient.Delete: %q", err)
		return err
	}
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

	ctx, cancel := contextWithTimeout()
	defer cancel()

	for _, item := range items {
		select {
		case <-ctx.Done():
			o.Logger.Debugf("destroyPowerInstances: case <-ctx.Done()")
			return ctx.Err() // we're cancelled, abort
		default:
		}

		backoff := wait.Backoff{
			Duration: 15 * time.Second,
			Factor:   1.1,
			Cap:      leftInContext(ctx),
			Steps:    math.MaxInt32}
		err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
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
		return fmt.Errorf("destroyPowerInstances: %d undeleted items pending", len(items))
	}

	if shouldDelete {
	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
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
	}

	return nil
}

const powerSSHKeyTypeName = "powerSshKey"

// listPowerSSHKeys lists ssh keys in the Power server.
func (o *ClusterUninstaller) listPowerSSHKeys() (cloudResources, error) {
	o.Logger.Debugf("Listing Power SSHKeys")

	if o.keyClient == nil {
		o.Logger.Infof("Skipping deleting Power sshkeys because no service instance was found")
		result := []cloudResource{}
		return cloudResources{}.insert(result...), nil
	}

	ctx, cancel := contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("listPowerSSHKeys: case <-ctx.Done()")
		return nil, ctx.Err() // we're cancelled, abort
	default:
	}

	var sshKeys *models.SSHKeys
	var err error

	sshKeys, err = o.keyClient.GetAll()
	if err != nil {
		return nil, fmt.Errorf("failed to list Power sshkeys: %w", err)
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

	ctx, cancel := contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("deletePowerSSHKey: case <-ctx.Done()")
		return ctx.Err() // we're cancelled, abort
	default:
	}

	_, err = o.keyClient.Get(item.id)
	if err != nil {
		o.deletePendingItems(item.typeName, []cloudResource{item})
		o.Logger.Infof("Deleted Power SSHKey %q", item.name)
		return nil
	}

	if shouldDelete {
	err = o.keyClient.Delete(item.id)
	if err != nil {
		return fmt.Errorf("failed to delete Power sshKey %s: %w", item.name, err)
	}
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

	ctx, cancel := contextWithTimeout()
	defer cancel()

	for _, item := range items {
		select {
		case <-ctx.Done():
			o.Logger.Debugf("destroyPowerSSHKeys: case <-ctx.Done()")
			return ctx.Err() // we're cancelled, abort
		default:
		}

		backoff := wait.Backoff{
			Duration: 15 * time.Second,
			Factor:   1.1,
			Cap:      leftInContext(ctx),
			Steps:    math.MaxInt32}
		err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
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
		return fmt.Errorf("destroyPowerSSHKeys: %d undeleted items pending", len(items))
	}

	if shouldDelete {
	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
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
	}

	return nil
}

const powerSubnetTypeName = "powerSubnet"

// listPowerSubnets lists subnets in the Power Server.
func (o *ClusterUninstaller) listPowerSubnets() (cloudResources, error) {
	o.Logger.Debugf("Listing Power Server Subnets")

	if o.instanceClient == nil {
		o.Logger.Infof("Skipping deleting Power service subnets because no service instance was found")
		result := []cloudResource{}
		return cloudResources{}.insert(result...), nil
	}

	networks, err := o.networkClient.GetAll()
	if err != nil {
		o.Logger.Warnf("Error networkClient.GetAll: %v", err)
		return nil, err
	}

	result := []cloudResource{}
	for _, network := range networks.Networks {
		if strings.Contains(*network.Name, o.InfraID) {
			o.Logger.Debugf("listPowerSubnets: FOUND: %s, %s", *network.NetworkID, *network.Name)
			result = append(result, cloudResource{
				key:      *network.NetworkID,
				name:     *network.Name,
				status:   "",
				typeName: powerSubnetTypeName,
				id:       *network.NetworkID,
			})
		}
	}
	if len(result) == 0 {
		o.Logger.Debugf("listPowerSubnets: NO matching subnet against: %s", o.InfraID)
		for _, network := range networks.Networks {
			o.Logger.Debugf("listPowerSubnets: network: %s", *network.Name)
		}
	}

	return cloudResources{}.insert(result...), nil
}

func (o *ClusterUninstaller) deletePowerSubnet(item cloudResource) error {
	if _, err := o.networkClient.Get(item.id); err != nil {
		o.deletePendingItems(item.typeName, []cloudResource{item})
		o.Logger.Infof("Deleted Power Network %q", item.name)
		return nil
	}

	o.Logger.Debugf("Deleting Power Network %q", item.name)

	if shouldDelete {
	if err := o.networkClient.Delete(item.id); err != nil {
		o.Logger.Infof("Error: o.networkClient.Delete: %q", err)
		return err
	}
	}

	o.deletePendingItems(item.typeName, []cloudResource{item})
	o.Logger.Infof("Deleted Power Network %q", item.name)

	return nil
}

// destroyPowerSubnets removes all subnet resources that have a name prefixed
// with the cluster's infra ID.
func (o *ClusterUninstaller) destroyPowerSubnets() error {
	firstPassList, err := o.listPowerSubnets()
	if err != nil {
		return err
	}

	if len(firstPassList.list()) == 0 {
		return nil
	}

	items := o.insertPendingItems(powerSubnetTypeName, firstPassList.list())

	ctx, cancel := contextWithTimeout()
	defer cancel()

	for _, item := range items {
		select {
		case <-ctx.Done():
			o.Logger.Debugf("destroyPowerSubnets: case <-ctx.Done()")
			return ctx.Err() // we're cancelled, abort
		default:
		}

		backoff := wait.Backoff{
			Duration: 15 * time.Second,
			Factor:   1.1,
			Cap:      leftInContext(ctx),
			Steps:    math.MaxInt32}
		err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
			err2 := o.deletePowerSubnet(item)
			if err2 == nil {
				return true, err2
			}
			o.errorTracker.suppressWarning(item.key, err2, o.Logger)
			return false, err2
		})
		if err != nil {
			o.Logger.Fatal("destroyPowerSubnets: ExponentialBackoffWithContext (destroy) returns ", err)
		}
	}

	if items = o.getPendingItems(powerSubnetTypeName); len(items) > 0 {
		for _, item := range items {
			o.Logger.Debugf("destroyPowerSubnets: found %s in pending items", item.name)
		}
		return fmt.Errorf("destroyPowerSubnets: %d undeleted items pending", len(items))
	}

	if shouldDelete {
	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
		secondPassList, err2 := o.listPowerSubnets()
		if err2 != nil {
			return false, err2
		}
		if len(secondPassList) == 0 {
			// We finally don't see any remaining instances!
			return true, nil
		}
		for _, item := range secondPassList {
			o.Logger.Debugf("destroyPowerSubnets: found %s in second pass", item.name)
		}
		return false, nil
	})
	if err != nil {
		o.Logger.Fatal("destroyPowerSubnets: ExponentialBackoffWithContext (list) returns ", err)
	}
	}

	return nil
}

const (
	publicGatewayTypeName = "publicGateway"
)

// listAttachedSubnets lists subnets attached to the specified publicGateway.
func (o *ClusterUninstaller) listAttachedSubnets(publicGatewayID string) (cloudResources, error) {
	o.Logger.Debugf("Finding subnets attached to public gateway %s", publicGatewayID)

	ctx, cancel := contextWithTimeout()
	defer cancel()

	options := o.vpcSvc.NewListSubnetsOptions()
	resources, _, err := o.vpcSvc.ListSubnetsWithContext(ctx, options)
	if err != nil {
		return nil, fmt.Errorf("failed to list subnets: %w", err)
	}

	result := []cloudResource{}
	for _, subnet := range resources.Subnets {
		if subnet.PublicGateway != nil && *subnet.PublicGateway.ID == publicGatewayID {
			result = append(result, cloudResource{
				key:      *subnet.ID,
				name:     *subnet.Name,
				status:   *subnet.Status,
				typeName: publicGatewayTypeName,
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

	ctx, cancel := contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("listPublicGateways: case <-ctx.Done()")
		return nil, ctx.Err() // we're cancelled, abort
	default:
	}

	listPublicGatewaysOptions = o.vpcSvc.NewListPublicGatewaysOptions()

	listPublicGatewaysOptions.SetLimit(perPage)

	result := []cloudResource{}

	for moreData {

		publicGatewayCollection, detailedResponse, err = o.vpcSvc.ListPublicGatewaysWithContext(ctx, listPublicGatewaysOptions)
		if err != nil {
			return nil, fmt.Errorf("failed to list publicGateways and the response is: %s: %w", detailedResponse, err)
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
			start, err := publicGatewayCollection.GetNextStart()
			if err != nil {
				o.Logger.Debugf("listPublicGateways: err = %v", err)
				return nil, fmt.Errorf("listPublicGateways: failed to GetNextStart: %w", err)
			}
			if start != nil {
				o.Logger.Debugf("listPublicGateways: start = %v", *start)
				listPublicGatewaysOptions.SetStart(*start)
			}
		} else {
			o.Logger.Debugf("listPublicGateways: Next = nil")
			moreData = false
		}
	}
	if !foundOne {
		o.Logger.Debugf("listPublicGateways: NO matching publicGateway against: %s", o.InfraID)

		listPublicGatewaysOptions = o.vpcSvc.NewListPublicGatewaysOptions()
		listPublicGatewaysOptions.SetLimit(perPage)

		for moreData {
			publicGatewayCollection, detailedResponse, err = o.vpcSvc.ListPublicGatewaysWithContext(ctx, listPublicGatewaysOptions)
			if err != nil {
				return nil, fmt.Errorf("failed to list publicGateways and the response is: %s: %w", detailedResponse, err)
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
				start, err := publicGatewayCollection.GetNextStart()
				if err != nil {
					o.Logger.Debugf("listPublicGateways: err = %v", err)
					return nil, fmt.Errorf("listPublicGateways: failed to GetNextStart: %w", err)
				}
				if start != nil {
					o.Logger.Debugf("listPublicGateways: start = %v", *start)
					listPublicGatewaysOptions.SetStart(*start)
				}
			} else {
				o.Logger.Debugf("listPublicGateways: Next = nil")
				moreData = false
			}
		}
	}

	return cloudResources{}.insert(result...), nil
}

func (o *ClusterUninstaller) deletePublicGateway(item cloudResource) error {
	ctx, cancel := contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("deletePublicGateway: case <-ctx.Done()")
		return ctx.Err() // we're cancelled, abort
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
		return fmt.Errorf("failed to list subnets with gateway %s attached: %w", item.name, err)
	}
	for _, subnet := range subnets {
		unsetSubnetPublicGatewayOptions := o.vpcSvc.NewUnsetSubnetPublicGatewayOptions(subnet.id)

		_, err = o.vpcSvc.UnsetSubnetPublicGatewayWithContext(ctx, unsetSubnetPublicGatewayOptions)
		if err != nil {
			return fmt.Errorf("failed to detach publicGateway %s from subnet %s: %w", item.name, subnet.id, err)
		}
	}

	deletePublicGatewayOptions := o.vpcSvc.NewDeletePublicGatewayOptions(item.id)

	if shouldDelete {
	_, err = o.vpcSvc.DeletePublicGatewayWithContext(ctx, deletePublicGatewayOptions)
	if err != nil {
		return fmt.Errorf("failed to delete publicGateway %s: %w", item.name, err)
	}
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

	ctx, cancel := contextWithTimeout()
	defer cancel()

	for _, item := range items {
		select {
		case <-ctx.Done():
			o.Logger.Debugf("destroyPublicGateways: case <-ctx.Done()")
			return ctx.Err() // we're cancelled, abort
		default:
		}

		backoff := wait.Backoff{
			Duration: 15 * time.Second,
			Factor:   1.1,
			Cap:      leftInContext(ctx),
			Steps:    math.MaxInt32}
		err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
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
		return fmt.Errorf("destroyPublicGateways: %d undeleted items pending", len(items))
	}

	if shouldDelete {
	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
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
	}

	return nil
}

const securityGroupTypeName = "security group"

// listSecurityGroups lists security groups in the vpc.
func (o *ClusterUninstaller) listSecurityGroups() (cloudResources, error) {
	o.Logger.Debugf("Listing security groups")

	ctx, cancel := contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("listSecurityGroups: case <-ctx.Done()")
		return nil, ctx.Err() // we're cancelled, abort
	default:
	}

	options := o.vpcSvc.NewListSecurityGroupsOptions()
	resources, _, err := o.vpcSvc.ListSecurityGroupsWithContext(ctx, options)

	if err != nil {
		return nil, fmt.Errorf("failed to list security groups: %w", err)
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

	ctx, cancel := contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("deleteSecurityGroup: case <-ctx.Done()")
		return ctx.Err() // we're cancelled, abort
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

	if shouldDelete {
	_, err = o.vpcSvc.DeleteSecurityGroupWithContext(ctx, deleteOptions)
	if err != nil {
		return fmt.Errorf("failed to delete security group %s: %w", item.name, err)
	}
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

	ctx, cancel := contextWithTimeout()
	defer cancel()

	for _, item := range items {
		select {
		case <-ctx.Done():
			o.Logger.Debugf("destroySecurityGroups: case <-ctx.Done()")
			return ctx.Err() // we're cancelled, abort
		default:
		}

		backoff := wait.Backoff{
			Duration: 15 * time.Second,
			Factor:   1.1,
			Cap:      leftInContext(ctx),
			Steps:    math.MaxInt32}
		err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
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
		return fmt.Errorf("destroySecurityGroups: %d undeleted items pending", len(items))
	}

	if shouldDelete {
	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
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
	}

	return nil
}


const vpcTypeName = "vpc"

// listVPCs lists VPCs in the cloud.
func (o *ClusterUninstaller) listVPCs() (cloudResources, error) {
	o.Logger.Debugf("Listing VPCs")

	ctx, cancel := contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("listVPCs: case <-ctx.Done()")
		return nil, ctx.Err() // we're cancelled, abort
	default:
	}

	options := o.vpcSvc.NewListVpcsOptions()
	vpcs, _, err := o.vpcSvc.ListVpcs(options)

	if err != nil {
		return nil, fmt.Errorf("failed to list vps: %w", err)
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

	ctx, cancel := contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("deleteVPC: case <-ctx.Done()")
		return ctx.Err() // we're cancelled, abort
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
	if shouldDelete {
	deleteResponse, err = o.vpcSvc.DeleteVPCWithContext(ctx, deleteOptions)
	o.Logger.Debugf("deleteVPC: DeleteVPCWithContext returns %+v", deleteResponse)

	if err != nil {
		return fmt.Errorf("failed to delete vpc %s: %w", item.name, err)
	}
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

	ctx, cancel := contextWithTimeout()
	defer cancel()

	for _, item := range items {
		select {
		case <-ctx.Done():
			o.Logger.Debugf("destroyVPCs: case <-ctx.Done()")
			return ctx.Err() // we're cancelled, abort
		default:
		}

		backoff := wait.Backoff{
			Duration: 15 * time.Second,
			Factor:   1.1,
			Cap:      leftInContext(ctx),
			Steps:    math.MaxInt32}
		err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
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
		return fmt.Errorf("destroyVPCs: %d undeleted items pending", len(items))
	}

	if shouldDelete {
	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
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
	}

	return nil
}

const (
	serviceInstanceTypeName = "service instance"

	// resource ID for Power Systems Virtual Server in the Global catalog.
	virtualServerResourceID = "abd259f0-9990-11e8-acc8-b9f54a8f1661"
)

// convertResourceGroupNameToID converts a resource group name/id to an id.
func (o *ClusterUninstaller) convertResourceGroupNameToID(resourceGroupID string) (string, error) {
	listResourceGroupsOptions := o.managementSvc.NewListResourceGroupsOptions()

	resourceGroups, _, err := o.managementSvc.ListResourceGroups(listResourceGroupsOptions)
	if err != nil {
		return "", err
	}

	for _, resourceGroup := range resourceGroups.Resources {
		if *resourceGroup.Name == resourceGroupID {
			return *resourceGroup.ID, nil
		} else if *resourceGroup.ID == resourceGroupID {
			return resourceGroupID, nil
		}
	}

	return "", fmt.Errorf("failed to find resource group %v", resourceGroupID)
}

// listServiceInstances list service instances for the cluster.
func (o *ClusterUninstaller) listServiceInstances() (cloudResources, error) {
	o.Logger.Debugf("Listing service instances")

	ctx, cancel := contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("listServiceInstances: case <-ctx.Done()")
		return nil, ctx.Err() // we're cancelled, abort
	default:
	}

	var (
		resourceGroupID string
		options         *resourcecontrollerv2.ListResourceInstancesOptions
		resources       *resourcecontrollerv2.ResourceInstancesList
		err             error
		perPage         int64 = 10
		moreData              = true
		nextURL         *string
	)

	resourceGroupID, err = o.convertResourceGroupNameToID(o.resourceGroupID)
	if err != nil {
		return nil, fmt.Errorf("failed to convert resourceGroupID: %w", err)
	}
	o.Logger.Debugf("listServiceInstances: converted %v to %v", o.resourceGroupID, resourceGroupID)

	options = o.controllerSvc.NewListResourceInstancesOptions()
	// options.SetType("resource_instance")
	options.SetResourceGroupID(resourceGroupID)
	options.SetResourceID(virtualServerResourceID)
	options.SetLimit(perPage)

	result := []cloudResource{}

	for moreData {
		if options.Start != nil {
			o.Logger.Debugf("listServiceInstances: options = %+v, options.Limit = %v, options.Start = %v, options.ResourceGroupID = %v", options, *options.Limit, *options.Start, *options.ResourceGroupID)
		} else {
			o.Logger.Debugf("listServiceInstances: options = %+v, options.Limit = %v, options.ResourceGroupID = %v", options, *options.Limit, *options.ResourceGroupID)
		}

		resources, _, err = o.controllerSvc.ListResourceInstancesWithContext(ctx, options)
		if err != nil {
			return nil, fmt.Errorf("failed to list resource instances: %w", err)
		}

		o.Logger.Debugf("listServiceInstances: resources.RowsCount = %v", *resources.RowsCount)

		for _, resource := range resources.Resources {
			var (
				getResourceOptions *resourcecontrollerv2.GetResourceInstanceOptions
				resourceInstance   *resourcecontrollerv2.ResourceInstance
				response           *core.DetailedResponse
			)

			o.Logger.Debugf("listServiceInstances: resource.Name = %s", *resource.Name)

			getResourceOptions = o.controllerSvc.NewGetResourceInstanceOptions(*resource.ID)

			resourceInstance, response, err = o.controllerSvc.GetResourceInstance(getResourceOptions)
			if err != nil {
				return nil, fmt.Errorf("failed to get instance: %s: %w", response, err)
			}
			if response != nil && response.StatusCode == gohttp.StatusNotFound {
				o.Logger.Debugf("listServiceInstances: gohttp.StatusNotFound")
				continue
			} else if response != nil && response.StatusCode == gohttp.StatusInternalServerError {
				o.Logger.Debugf("listServiceInstances: gohttp.StatusInternalServerError")
				continue
			}

			if resourceInstance.Type == nil {
				o.Logger.Debugf("listServiceInstances: type: nil")
			} else {
				o.Logger.Debugf("listServiceInstances: type: %v", *resourceInstance.Type)
			}

			if resourceInstance.Type == nil || resourceInstance.GUID == nil {
				continue
			}
			if *resourceInstance.Type != "service_instance" && *resourceInstance.Type != "composite_instance" {
				continue
			}
			if !strings.Contains(*resource.Name, o.InfraID) {
				continue
			}

			if strings.Contains(*resource.Name, o.InfraID) {
				result = append(result, cloudResource{
					key:      *resource.ID,
					name:     *resource.Name,
					status:   *resource.GUID,
					typeName: serviceInstanceTypeName,
					id:       *resource.ID,
				})
			}
		}

		// Based on: https://cloud.ibm.com/apidocs/resource-controller/resource-controller?code=go#list-resource-instances
		nextURL, err = core.GetQueryParam(resources.NextURL, "start")
		if err != nil {
			return nil, fmt.Errorf("failed to GetQueryParam on start: %w", err)
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

	return cloudResources{}.insert(result...), nil
}

// destroyServiceInstance destroys a service instance.
func (o *ClusterUninstaller) destroyServiceInstance(item cloudResource) error {
	ctx, cancel := contextWithTimeout()
	defer cancel()

	select {
	case <-ctx.Done():
		o.Logger.Debugf("destroyServiceInstance: case <-ctx.Done()")
		return ctx.Err() // we're cancelled, abort
	default:
	}

	o.Logger.Debugf("destroyServiceInstance: Preparing to delete, item.name = %v", item.name)

	var (
		getOptions *resourcecontrollerv2.GetResourceInstanceOptions
		response   *core.DetailedResponse
		err        error
	)

	getOptions = o.controllerSvc.NewGetResourceInstanceOptions(item.id)

	_, response, err = o.controllerSvc.GetResourceInstanceWithContext(ctx, getOptions)

	if err != nil && response != nil && response.StatusCode == gohttp.StatusNotFound {
		// The resource is gone
		o.deletePendingItems(item.typeName, []cloudResource{item})
		o.Logger.Infof("Deleted Service Instance %q", item.name)
		return nil
	}
	if err != nil && response != nil && response.StatusCode == gohttp.StatusInternalServerError {
		o.Logger.Infof("destroyServiceInstance: internal server error")
		return nil
	}

	options := o.controllerSvc.NewDeleteResourceInstanceOptions(item.id)
	options.SetRecursive(true)

	if shouldDelete {
	response, err = o.controllerSvc.DeleteResourceInstanceWithContext(ctx, options)

	if err != nil && response != nil && response.StatusCode != gohttp.StatusNotFound {
		return fmt.Errorf("failed to delete service instance %s: %w", item.name, err)
	}
	}

	o.Logger.Infof("Deleted Service Instance %q", item.name)
	o.deletePendingItems(item.typeName, []cloudResource{item})

	return nil
}

// destroyServiceInstances removes all service instances have a name containing
// the cluster's infra ID.
func (o *ClusterUninstaller) destroyServiceInstances() error {
	firstPassList, err := o.listServiceInstances()
	if err != nil {
		return err
	}

	if len(firstPassList.list()) == 0 {
		return nil
	}

	items := o.insertPendingItems(serviceInstanceTypeName, firstPassList.list())

	ctx, cancel := contextWithTimeout()
	defer cancel()

	for _, item := range items {
		select {
		case <-ctx.Done():
			o.Logger.Debugf("destroyServiceInstances: case <-ctx.Done()")
			return ctx.Err() // we're cancelled, abort
		default:
		}

		backoff := wait.Backoff{
			Duration: 15 * time.Second,
			Factor:   1.1,
			Cap:      leftInContext(ctx),
			Steps:    math.MaxInt32}
		err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
			err2 := o.destroyServiceInstance(item)
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
		return fmt.Errorf("destroyServiceInstances: %d undeleted items pending", len(items))
	}

	if shouldDelete {
	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
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
	}

	return nil
}
