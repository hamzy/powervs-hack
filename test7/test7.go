// Copyright 2021 IBM Corp
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// https://github.com/openshift/installer/commit/b5c77e12acc6841d08378a8a5d45ea0f6aa1dd93

// package vpc1
// https://raw.githubusercontent.com/IBM/vpc-go-sdk/master/vpcv1/vpc_v1.go

// package resourcecontrollerv2
// https://raw.githubusercontent.com/IBM/platform-services-go-sdk/main/resourcecontrollerv2/resource_controller_v2.go

// package resourcemanagerv2
// https://raw.githubusercontent.com/IBM/platform-services-go-sdk/main/resourcemanagerv2/resource_manager_v2.go

// package dnsrecordsv1
// https://raw.githubusercontent.com/IBM/networking-go-sdk/master/dnsrecordsv1/dns_records_v1.go

// How to run:
// (export IBMCLOUD_API_KEY="blah"; if ! ibmcloud iam oauth-tokens 1>/dev/null 2>&1; then ibmcloud login --apikey "${IBMCLOUD_API_KEY}"; fi; go run list-jobs.go -apiKey "${IBMCLOUD_API_KEY}" -search '.*rdr-hamzy-.*' -serviceName powervs-ipi-lon04 -shouldDebug false -shouldDelete false)

package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/IBM-Cloud/bluemix-go"
	"github.com/IBM-Cloud/bluemix-go/api/resource/resourcev2/controllerv2"
	"github.com/IBM-Cloud/bluemix-go/authentication"
	"github.com/IBM-Cloud/bluemix-go/http"
	"github.com/IBM-Cloud/bluemix-go/rest"
	bxsession "github.com/IBM-Cloud/bluemix-go/session"
	"github.com/IBM-Cloud/power-go-client/clients/instance"
	"github.com/IBM-Cloud/power-go-client/ibmpisession"
	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/vpc-go-sdk/vpcv1"
	"github.com/openshift/installer/pkg/version"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"io"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	"math"
	gohttp "net/http"
	"os"
	"strings"
	"time"
)

func (o *ClusterUninstaller) createBug() {
	log.Debugf("createBug")
	_, cancel := o.contextWithTimeout()
	defer cancel()
}

var shouldDebug = false
var shouldDelete = false

var tryCount int = 0

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

const (
	powerInstanceTypeName = "powerInstance"
)

// listPowerInstances lists instances in the power server.
func (o *ClusterUninstaller) listPowerInstances() (cloudResources, error) {
	log.Debugf("Listing virtual Power service instances (%s)", o.InfraID)

	instances, err := o.instanceClient.GetAll()
	if err != nil {
		log.Warnf("Error instanceClient.GetAll: %v", err)
		return nil, err
	}

	var foundOne = false

	result := []cloudResource{}
	for _, instance := range instances.PvmInstances {
		// https://github.com/IBM-Cloud/power-go-client/blob/master/power/models/p_vm_instance.go
		if strings.Contains(*instance.ServerName, o.InfraID) {
			foundOne = true
			log.Debugf("listPowerInstances: FOUND: %s, %s, %s", *instance.PvmInstanceID, *instance.ServerName, *instance.Status)
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
		log.Debugf("listPowerInstances: NO matching virtual instance against: %s", o.InfraID)
		for _, instance := range instances.PvmInstances {
			log.Debugf("listPowerInstances: only found virtual instance: %s", *instance.ServerName)
		}
	}

	return cloudResources{}.insert(result...), nil
}

func (o *ClusterUninstaller) destroyPowerInstance(item cloudResource) error {
	var err error

	_, err = o.instanceClient.Get(item.id)
	if err != nil {
		o.deletePendingItems(item.typeName, []cloudResource{item})
		log.Infof("Deleted Power instance %q", item.name)
		return nil
	}

	if !shouldDelete {
		log.Debugf("Skipping deleting Power instance %q since shouldDelete is false", item.name)
		o.deletePendingItems(item.typeName, []cloudResource{item})
		return nil
	}

	log.Debugf("Deleting Power instance %q", item.name)

	err = o.instanceClient.Delete(item.id)
	if err != nil {
		log.Infof("Error: o.instanceClient.Delete: %q", err)
		return err
	}

	o.deletePendingItems(item.typeName, []cloudResource{item})
	log.Infof("Deleted Power instance %q", item.name)

	return nil
}

// destroyPowerInstances searches for Power instances that have a name that starts with
// the cluster's infra ID.
func (o *ClusterUninstaller) destroyPowerInstances() error {
	var (
		firstPassList cloudResources

		err error

		items []cloudResource

		ctx context.Context

		backoff wait.Backoff = wait.Backoff{Duration: 15 * time.Second,
			Factor: 1.5,
			Cap: 10 * time.Minute,
			Steps: math.MaxInt32}
	)

	firstPassList, err = o.listPowerInstances()
	if err != nil {
		return err
	}

	items = o.insertPendingItems(powerInstanceTypeName, firstPassList.list())

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	for _, item := range items {
		select {
		case <-o.Context.Done():
			log.Debugf("destroyPowerInstances: case <-o.Context.Done()")
			return o.Context.Err() // we're cancelled, abort
		default:
		}

		err = wait.ExponentialBackoffWithContext(ctx, backoff, func() (bool, error) {
			err2 := o.destroyPowerInstance(item)
			if err2 == nil {
				return true, err2
			} else {
				o.errorTracker.suppressWarning(item.key, err2, log)
				return false, err2
			}
		})
		if err != nil {
			log.Fatal("destroyPowerInstances: ExponentialBackoffWithContext (destroy) returns ", err)
		}
	}

	if items = o.getPendingItems(powerInstanceTypeName); len(items) > 0 {
		return errors.Errorf("destroyPowerInstances: %d undeleted items pending", len(items))
	}

	backoff = wait.Backoff{Duration: 15 * time.Second,
		Factor: 1.5,
		Cap: 10 * time.Minute,
		Steps: math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func() (bool, error) {
		var (
			secondPassList cloudResources

			err2 error
		)

		secondPassList, err2 = o.listPowerInstances()
		if err2 != nil {
			return false, err2
		}
		if len(secondPassList) == 0 {
			// We finally don't see any remaining instances!
			return true, nil
		} else {
			for _, item := range secondPassList {
				log.Debugf("destroyPowerInstances: found %s in second pass", item.name)
			}
			return false, nil
		}
	})
	if err != nil {
		log.Fatal("destroyPowerInstances: ExponentialBackoffWithContext (list) returns ", err)
	}

	return nil
}

// ClusterUninstaller holds the various options for the cluster we want to delete.
type ClusterUninstaller struct {
	APIKey         string
	BaseDomain     string
	CISInstanceCRN string
	ClusterName    string
	Context        context.Context
	InfraID        string
	Logger         logrus.FieldLogger
	Region         string
	ServiceGUID    string
	VPCRegion      string
	Zone           string

	vpcSvc                *vpcv1.VpcV1
	piSession             *ibmpisession.IBMPISession
	instanceClient        *instance.IBMPIInstanceClient

	resourceGroupID string
	cosInstanceID   string

	errorTracker
	pendingItemTracker
}

// New returns an IBMCloud destroyer from ClusterMetadata.
func New(log logrus.FieldLogger,
	apiKey string,
	infraID string) (*ClusterUninstaller, error) {

	return &ClusterUninstaller{
		APIKey:             apiKey,
		Context:            context.Background(),
		Logger:             log,
		InfraID:            infraID,
		pendingItemTracker: newPendingItemTracker(),
	}, nil
}

const (
	suppressDuration = time.Minute * 5
)

// errorTracker holds a history of errors.
type errorTracker struct {
	history map[string]time.Time
}

// suppressWarning logs errors WARN once every duration and the rest to DEBUG.
func (o *errorTracker) suppressWarning(identifier string, err error, log logrus.FieldLogger) {
	if o.history == nil {
		o.history = map[string]time.Time{}
	}
	if firstSeen, ok := o.history[identifier]; ok {
		if time.Since(firstSeen) > suppressDuration {
			log.Warn(err)
			o.history[identifier] = time.Now() // reset the clock
		} else {
			log.Debug(err)
		}
	} else { // first error for this identifier
		o.history[identifier] = time.Now()
		log.Debug(err)
	}
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

func leftInContext(ctx context.Context) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return math.MaxInt64
	}

	duration := time.Until(deadline)

	return duration
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
	if !exists {
		lastFound = cloudResources{}
	}
	return lastFound.list()
}

// insertPendingItems adds to the list of resources to be deleted.
func (t pendingItemTracker) insertPendingItems(itemType string, items []cloudResource) []cloudResource {
	lastFound, exists := t.pendingItems[itemType]
	if !exists {
		lastFound = cloudResources{}
	}
	lastFound = lastFound.insert(items...)
	t.pendingItems[itemType] = lastFound
	return lastFound.list()
}

// deletePendingItems removes from the list of resources to be deleted.
func (t pendingItemTracker) deletePendingItems(itemType string, items []cloudResource) []cloudResource {
	lastFound, exists := t.pendingItems[itemType]
	if !exists {
		lastFound = cloudResources{}
	}
	lastFound = lastFound.delete(items...)
	t.pendingItems[itemType] = lastFound
	return lastFound.list()
}

var (
	defaultTimeout = 15 * time.Minute
	stageTimeout   = 5 * time.Minute
)

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

func timeout(ctx context.Context) bool {
	var deadline time.Time
	var ok bool

	deadline, ok = ctx.Deadline()
	if !ok {
		log.Printf("timeout: deadline, ok = %v, %v", deadline, ok)
		return true
	}

	var after bool = time.Now().After(deadline)

	if after {
		// 01/02 03:04:05PM ‘06 -0700
		log.Printf("timeout: after deadline! (%v)", deadline.Format("2006-01-02 03:04:05PM"))
	}

	return after
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

func createPiSession (ptrApiKey *string, ptrServiceName *string) (*ibmpisession.IBMPISession, string, error) {

	var bxSession *bxsession.Session
	var tokenProviderEndpoint string = "https://iam.cloud.ibm.com"
	var err error

	bxSession, err = bxsession.New(&bluemix.Config{
		BluemixAPIKey:         *ptrApiKey,
		TokenProviderEndpoint: &tokenProviderEndpoint,
		Debug:                 false,
	})
	if err != nil {
		return nil, "", fmt.Errorf("Error bxsession.New: %v", err)
	}
	log.Printf("bxSession = %v\n", bxSession)

	tokenRefresher, err := authentication.NewIAMAuthRepository(bxSession.Config, &rest.Client{
		DefaultHeader: gohttp.Header{
			"User-Agent": []string{http.UserAgent()},
		},
	})
	if err != nil {
		return nil, "", fmt.Errorf("Error authentication.NewIAMAuthRepository: %v", err)
	}
	log.Printf("tokenRefresher = %v\n", tokenRefresher)
	err = tokenRefresher.AuthenticateAPIKey(bxSession.Config.BluemixAPIKey)
	if err != nil {
		return nil, "", fmt.Errorf("Error tokenRefresher.AuthenticateAPIKey: %v", err)
	}

	user, err := fetchUserDetails(bxSession, 2)
	if err != nil {
		return nil, "", fmt.Errorf("Error fetchUserDetails: %v", err)
	}

	ctrlv2, err := controllerv2.New(bxSession)
	if err != nil {
		return nil, "", fmt.Errorf("Error controllerv2.New: %v", err)
	}
	log.Printf("ctrlv2 = %v\n", ctrlv2)

	resourceClientV2 := ctrlv2.ResourceServiceInstanceV2()
	if err != nil {
		return nil, "", fmt.Errorf("Error ctrlv2.ResourceServiceInstanceV2: %v", err)
	}
	log.Printf("resourceClientV2 = %v\n", resourceClientV2)

	svcs, err := resourceClientV2.ListInstances(controllerv2.ServiceInstanceQuery{
		Type: "service_instance",
	})
	if err != nil {
		return nil, "", fmt.Errorf("Error resourceClientV2.ListInstances: %v", err)
	}

	var serviceGuid string = ""

	for _, svc := range svcs {
		log.Printf("Guid = %v\n", svc.Guid)
		log.Printf("RegionID = %v\n", svc.RegionID)
		log.Printf("Name = %v\n", svc.Name)
		log.Printf("Crn = %v\n", svc.Crn)
		if svc.Name == *ptrServiceName {
			serviceGuid = svc.Guid
			break
		}
	}
	if serviceGuid == "" {
		return nil, "", fmt.Errorf("%s not found in list of service instances!\n", *ptrServiceName)
	}
	log.Printf("serviceGuid = %v\n", serviceGuid)

	serviceInstance, err := resourceClientV2.GetInstance(serviceGuid)
	if err != nil {
		return nil, "", fmt.Errorf("Error resourceClientV2.GetInstance: %v", err)
	}
	log.Printf("serviceInstance = %v\n", serviceInstance)

	region, err:= GetRegion(serviceInstance.RegionID)
	if err != nil {
		return nil, "", fmt.Errorf("Error GetRegion: %v", err)
	}

	var authenticator core.Authenticator = &core.IamAuthenticator{
		ApiKey:	*ptrApiKey,
	}

	err = authenticator.Validate()
	if err != nil {
		return nil, "", fmt.Errorf("Error: authenticator.Validate: %v", err)
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
	if (err != nil) || (piSession == nil) {
		if err != nil {
			return nil, "", fmt.Errorf("Error: ibmpisession.NewIBMPISession: %v", err)
		}
		return nil, "", fmt.Errorf("Error: piSession is nil")
	}
	log.Printf("piSession = %v\n", piSession)

	return piSession, serviceGuid, nil

}

var log *logrus.Logger

func main() {

	var logMain *logrus.Logger = &logrus.Logger{
		Out: os.Stderr,
		Formatter: new(logrus.TextFormatter),
		Level: logrus.DebugLevel,
	}

	var ptrApiKey *string
	var ptrSearch *string
	var ptrServiceName *string
	var ptrVPCRegion *string
	var ptrShouldDebug *string
	var ptrShouldDelete *string

	ptrApiKey = flag.String("apiKey", "", "Your IBM Cloud API key")
	ptrSearch = flag.String("search", "", "The search string to match for deletes")
	ptrServiceName = flag.String("serviceName", "", "The cloud service to use")
	ptrVPCRegion = flag.String("VPCRegion", "", "The VPC region to use")
	ptrShouldDebug = flag.String("shouldDebug", "false", "Should output debug output")
	ptrShouldDelete = flag.String("shouldDelete", "false", "Should delete matching records")

	flag.Parse()

	if *ptrApiKey == "" {
		logMain.Fatal("Error: No API key set, use --apiKey")
	}

	if *ptrSearch == "" {
		logMain.Fatal("Error: No search term set, use --search")
	}

	if *ptrServiceName == "" {
		logMain.Fatal("Error: No cloud service set, use --serviceName")
	}

	if *ptrVPCRegion == "" {
		logMain.Fatal("Error: No VPC region set, use --VPCRegion")
	}

	switch strings.ToLower(*ptrShouldDebug) {
	case "true":
		shouldDebug = true
	case "false":
		shouldDebug = false
	default:
		logMain.Fatal("Error: shouldDebug is not true/false (%s)\n", *ptrShouldDebug)
	}
	switch strings.ToLower(*ptrShouldDelete) {
	case "true":
		shouldDelete = true
	case "false":
		shouldDelete = false
	default:
		logMain.Fatal("Error: shouldDelete is not true/false (%s)\n", *ptrShouldDelete)
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

	var clusterUninstaller *ClusterUninstaller
	var err error

	clusterUninstaller, err = New (log,
		*ptrApiKey,
		*ptrSearch)
	if err != nil {
		logMain.Fatalf("Error New: %v", err)
	}
	if shouldDebug { logMain.Printf("clusterUninstaller = %+v\n", clusterUninstaller) }

	var piSession *ibmpisession.IBMPISession
	var serviceGuid string

	piSession, serviceGuid, err = createPiSession(ptrApiKey, ptrServiceName)
	if err != nil {
		logMain.Fatal("Error createPiSession: %v\n", err)
	}

	var authenticator core.Authenticator = &core.IamAuthenticator{
		ApiKey:	*ptrApiKey,
	}

	err = authenticator.Validate()

	if err != nil {
		logMain.Fatal("Error authenticator.Validate: %v\n", err)
	}

	var vpcSvc *vpcv1.VpcV1

	// https://raw.githubusercontent.com/IBM/vpc-go-sdk/master/vpcv1/vpc_v1.go
	vpcSvc, err = vpcv1.NewVpcV1(&vpcv1.VpcV1Options{
		Authenticator: authenticator,
		URL:           "https://" + *ptrVPCRegion + ".iaas.cloud.ibm.com/v1",
	})
	if err != nil {
		logMain.Fatal("Error vpcv1.NewVpcV1: %v\n", err)
	}

	userAgentString := fmt.Sprintf("OpenShift/4.x Destroyer/%s", version.Raw)
	vpcSvc.Service.SetUserAgent(userAgentString)

	clusterUninstaller.vpcSvc = vpcSvc

	var instanceClient *instance.IBMPIInstanceClient

	instanceClient = instance.NewIBMPIInstanceClient(context.Background(), piSession, serviceGuid)
	if shouldDebug { logMain.Printf("instanceClient = %v\n", instanceClient) }

	clusterUninstaller.instanceClient = instanceClient

	for i := 0; i < 10; i++ {
		clusterUninstaller.createBug()
	}

	err = clusterUninstaller.destroyCloudInstances()
	if err != nil {
		logMain.Fatal("Error clusterUninstaller.destroyCloudInstances:", err)
	}

	err = clusterUninstaller.destroyPowerInstances()
	if err != nil {
		logMain.Fatal("Error clusterUninstaller.destroyPowerInstances:", err)
	}
}
