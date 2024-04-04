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

package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/platform-services-go-sdk/resourcecontrollerv2"
	"github.com/IBM-Cloud/bluemix-go"
	"github.com/IBM-Cloud/bluemix-go/api/resource/resourcev2/controllerv2"
	"github.com/IBM-Cloud/bluemix-go/authentication"
	"github.com/IBM-Cloud/bluemix-go/http"
	"github.com/IBM-Cloud/bluemix-go/rest"
	bxsession "github.com/IBM-Cloud/bluemix-go/session"
	"github.com/IBM-Cloud/power-go-client/ibmpisession"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"io"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	"math"
	gohttp "net/http"
	"os"
//	"regexp"
	"strings"
	"time"
)

const cosTypeName = "cos instance"

// $ ibmcloud catalog service cloud-object-storage --output json | jq -r '.[].id'
// dff97f5c-bc5e-4455-b470-411c3edbe49c.
const cosResourceID = "dff97f5c-bc5e-4455-b470-411c3edbe49c"

// listCOSInstances lists COS service instances.
// ibmcloud resource service-instances --output JSON --service-name cloud-object-storage | jq -r '.[] | select(.name|test("rdr-hamzy.*")) | "\(.name) - \(.id)"'
func (o *ClusterUninstaller) listCOSInstances() (cloudResources, error) {
	o.Logger.Debugf("Listing COS instances")

	ctx, cancel := o.contextWithTimeout()
	defer cancel()

	// https://github.com/IBM/platform-services-go-sdk/blob/main/resourcecontrollerv2/resource_controller_v2.go#L3086
	var options *resourcecontrollerv2.ListResourceInstancesOptions
	var perPage int64 = 64

	options = o.controllerSvc.NewListResourceInstancesOptions()
	options.Limit = &perPage
	options.SetResourceID(cosResourceID)
	options.SetType("service_instance")

	// https://github.com/IBM/platform-services-go-sdk/blob/main/resourcecontrollerv2/resource_controller_v2.go#L4525-L4534
	var resources *resourcecontrollerv2.ResourceInstancesList
	var err error

	var foundOne = false
	var moreData = true

	result := []cloudResource{}

	for moreData {
		// https://github.com/IBM/platform-services-go-sdk/blob/main/resourcecontrollerv2/resource_controller_v2.go#L173
		resources, _, err = o.controllerSvc.ListResourceInstancesWithContext(ctx, options)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to list COS instances")
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
				if !shouldDelete {
					o.Logger.Infof("listCOSInstances: SKIPPING deleting shouldDelete is false")
					continue
				}
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
				o.Logger.Debugf("listCOSInstances: err = %w", err)
				return nil, errors.Wrapf(err, "failed to GetNextStart")
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
				return nil, errors.Wrapf(err, "failed to list COS instances")
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
					o.Logger.Debugf("listCOSInstances: err = %w", err)
					return nil, errors.Wrapf(err, "failed to GetNextStart")
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
	if !shouldDelete {
		o.Logger.Infof("SKIPPING deleting COS Instance %q because shouldDelete is false", item.name)
		o.deletePendingItems(item.typeName, []cloudResource{item})
		return nil
	}

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
		return errors.Errorf("destroyCOSInstances: %d undeleted items pending", len(items))
	}

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

var shouldDebug = false
var shouldDelete = false

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

	piSession      *ibmpisession.IBMPISession
	controllerSvc  *resourcecontrollerv2.ResourceControllerV2

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
		if shouldDebug {
			log.Printf("timeout: deadline, ok = %v, %v", deadline, ok)
		}
		return true
	}

	var after bool = time.Now().After(deadline)

	if after {
		// 01/02 03:04:05PM ‘06 -0700
		if shouldDebug {
			log.Printf("timeout: after deadline! (%v)", deadline.Format("2006-01-02 03:04:05PM"))
		}
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

func createPiSession(ptrApiKey *string, ptrServiceName *string) (*ibmpisession.IBMPISession, string, error) {

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
	if shouldDebug {
		log.Printf("bxSession = %v\n", bxSession)
	}

	tokenRefresher, err := authentication.NewIAMAuthRepository(bxSession.Config, &rest.Client{
		DefaultHeader: gohttp.Header{
			"User-Agent": []string{http.UserAgent()},
		},
	})
	if err != nil {
		return nil, "", fmt.Errorf("Error authentication.NewIAMAuthRepository: %v", err)
	}
	if shouldDebug {
		log.Printf("tokenRefresher = %v\n", tokenRefresher)
	}
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
	if shouldDebug {
		log.Printf("ctrlv2 = %v\n", ctrlv2)
	}

	resourceClientV2 := ctrlv2.ResourceServiceInstanceV2()
	if err != nil {
		return nil, "", fmt.Errorf("Error ctrlv2.ResourceServiceInstanceV2: %v", err)
	}
	if shouldDebug {
		log.Printf("resourceClientV2 = %v\n", resourceClientV2)
	}

	svcs, err := resourceClientV2.ListInstances(controllerv2.ServiceInstanceQuery{
		Type: "service_instance",
	})
	if err != nil {
		return nil, "", fmt.Errorf("Error resourceClientV2.ListInstances: %v", err)
	}

	var serviceGuid string = ""

	for _, svc := range svcs {
		if shouldDebug {
			log.Printf("Guid = %v\n", svc.Guid)
			log.Printf("RegionID = %v\n", svc.RegionID)
			log.Printf("Name = %v\n", svc.Name)
			log.Printf("Crn = %v\n", svc.Crn)
		}
		if svc.Name == *ptrServiceName {
			serviceGuid = svc.Guid
			break
		}
	}
	if serviceGuid == "" {
		return nil, "", fmt.Errorf("%s not found in list of service instances!\n", *ptrServiceName)
	}
	if shouldDebug {
		log.Printf("serviceGuid = %v\n", serviceGuid)
	}

	serviceInstance, err := resourceClientV2.GetInstance(serviceGuid)
	if err != nil {
		return nil, "", fmt.Errorf("Error resourceClientV2.GetInstance: %v", err)
	}
	if shouldDebug {
		log.Printf("serviceInstance = %v\n", serviceInstance)

	}

	region, err := GetRegion(serviceInstance.RegionID)
	if err != nil {
		return nil, "", fmt.Errorf("Error GetRegion: %v", err)
	}

	var authenticator core.Authenticator = &core.IamAuthenticator{
		ApiKey: *ptrApiKey,
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

	return piSession, serviceGuid, nil
}

func (o *ClusterUninstaller) newAuthenticator(apikey string) (core.Authenticator, error) {
	var (
		authenticator core.Authenticator
		err           error
	)

	if apikey == "" {
		return nil, errors.New("newAuthenticator: apikey is empty")
	}

	authenticator = &core.IamAuthenticator{
		ApiKey: apikey,
	}

	err = authenticator.Validate()
	if err != nil {
		return nil, fmt.Errorf("newAuthenticator: authenticator.Validate: %w", err)
	}

	return authenticator, nil
}

func leftInContext(ctx context.Context) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return math.MaxInt64
	}

	duration := time.Until(deadline)

	return duration
}

var log *logrus.Logger

func main() {

	var logMain *logrus.Logger = &logrus.Logger{
		Out:       os.Stderr,
		Formatter: new(logrus.TextFormatter),
		Level:     logrus.DebugLevel,
	}

	var ptrApiKey *string
	var ptrSearch *string
	var ptrServiceName *string
	var ptrShouldDebug *string
	var ptrShouldDelete *string

	ptrApiKey = flag.String("apiKey", "", "Your IBM Cloud API key")
	ptrSearch = flag.String("search", "", "The search string to match for deletes")
	ptrServiceName = flag.String("serviceName", "", "The cloud service to use")
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
	switch strings.ToLower(*ptrShouldDebug) {
	case "true":
		shouldDebug = true
	case "false":
		shouldDebug = false
	default:
		logMain.Fatalf("Error: shouldDebug is not true/false (%s)\n", *ptrShouldDebug)
	}
	switch strings.ToLower(*ptrShouldDelete) {
	case "true":
		shouldDelete = true
	case "false":
		shouldDelete = false
	default:
		logMain.Fatalf("Error: shouldDelete is not true/false (%s)\n", *ptrShouldDelete)
	}

	var out io.Writer

	if shouldDebug {
		out = os.Stderr
	} else {
		out = io.Discard
	}
	log = &logrus.Logger{
		Out:       out,
		Formatter: new(logrus.TextFormatter),
		Level:     logrus.DebugLevel,
	}

	var clusterUninstaller *ClusterUninstaller
	var err error

	clusterUninstaller, err = New(log,
		*ptrApiKey,
		*ptrSearch)
	if err != nil {
		logMain.Fatalf("Error New: %v", err)
	}
	if shouldDebug {
		logMain.Printf("clusterUninstaller = %+v\n", clusterUninstaller)
	}

	var piSession *ibmpisession.IBMPISession
	var serviceGuid string

	piSession, serviceGuid, err = createPiSession(ptrApiKey, ptrServiceName)
	if err != nil {
		logMain.Fatalf("Error createPiSession: %v\n", err)
	}
	if shouldDebug {
		logMain.Printf("piSession = %v\n", piSession)
	}

	clusterUninstaller.piSession = piSession
	clusterUninstaller.ServiceGUID = serviceGuid

	var authenticator core.Authenticator

	authenticator, err = clusterUninstaller.newAuthenticator(clusterUninstaller.APIKey)
	if err != nil {
		logMain.Fatalf("Error newAuthenticator: %v\n", err)
	}

	// Instantiate the service with an API key based IAM authenticator
	clusterUninstaller.controllerSvc, err = resourcecontrollerv2.NewResourceControllerV2(&resourcecontrollerv2.ResourceControllerV2Options{
		Authenticator: authenticator,
		ServiceName:   "cloud-object-storage",
		URL:           "https://resource-controller.cloud.ibm.com",
	})
	if err != nil {
		logMain.Fatalf("Error creating ControllerV2 Service: %v\n", err)
	}

	err = clusterUninstaller.destroyCOSInstances()
	if err != nil {
		logMain.Fatal("Error clusterUninstaller.destroyCOSInstances:", err)
	}
}
