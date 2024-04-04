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
	"github.com/IBM/platform-services-go-sdk/resourcemanagerv2"
	"github.com/IBM/platform-services-go-sdk/globalsearchv2"
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
	"k8s.io/utils/ptr"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"math"
	gohttp "net/http"
	"os"
	"strings"
	"time"
)

func (o *ClusterUninstaller) search(searchString string, returnedFields []string) (string, error) {
	var (
		authenticator core.Authenticator
		err           error
		moreData      bool   = true
		searchCursor *string = ptr.To("") 
	)

	authenticator, err = o.newAuthenticator(o.APIKey)
	if err != nil {
		log.Fatalf("Error newAuthenticator: %v\n", err)
		return "", err
	}

	// https://github.com/IBM/platform-services-go-sdk/blob/main/globalsearchv2/global_search_v2.go#L64
	globalSearch, err := globalsearchv2.NewGlobalSearchV2UsingExternalConfig(
		&globalsearchv2.GlobalSearchV2Options{
		Authenticator: authenticator,
		},
	)

	// https://github.com/IBM/platform-services-go-sdk/blob/main/globalsearchv2/global_search_v2.go#L395
	searchOptions := globalSearch.NewSearchOptions()
	searchOptions.SetLimit(20)
	searchOptions.SetQuery(searchString)
	searchOptions.SetFields(returnedFields)

	for moreData {
		if *searchCursor != "" {
			searchOptions.SetSearchCursor(*searchCursor)
		}
		log.Printf("searchOptions = %+v\n", searchOptions)

		// https://github.com/IBM/platform-services-go-sdk/blob/main/globalsearchv2/global_search_v2.go#L183
		scanResult, response, err := globalSearch.Search(searchOptions)
		if err != nil {
			log.Fatalf("Error globalSearch.Search: err = %v, response = %v\n", err, response)
			return "", err
		}

		// https://github.com/IBM/platform-services-go-sdk/blob/main/globalsearchv2/global_search_v2.go#L292
		for _, item := range scanResult.Items {
			log.Printf("item.CRN = %v\n", *item.CRN)
			log.Printf("item.GetProperties() = %+v\n", item.GetProperties())
		}

		searchCursor = scanResult.SearchCursor
		moreData = searchCursor != nil
	}

	return "", nil
}

const cosTypeName = "cos instance"

// $ ibmcloud catalog service cloud-object-storage --output json | jq -r '.[].id'
// dff97f5c-bc5e-4455-b470-411c3edbe49c.
const cosResourceID = "dff97f5c-bc5e-4455-b470-411c3edbe49c"

// resource Id for Power Systems Virtual Server in the Global catalog.
const powerIAASResourceID = "abd259f0-9990-11e8-acc8-b9f54a8f1661"

// ServiceInstanceNameToGUID returns the GUID of the matching service instance name which was passed in.
func (o *ClusterUninstaller) ServiceInstanceNameToGUID(ctx context.Context, name string) (string, error) {
	var (
		options   *resourcecontrollerv2.ListResourceInstancesOptions
		resources *resourcecontrollerv2.ResourceInstancesList
		err       error
		perPage   int64 = 10
		moreData        = true
		nextURL   *string
		groupID   = o.resourceGroupID
	)

	log.Printf("groupID = %v\n", groupID)
	// If the user passes in a human readable group id, then we need to convert it to a UUID
	listGroupOptions := o.managementSvc.NewListResourceGroupsOptions()
	groups, _, err := o.managementSvc.ListResourceGroupsWithContext(ctx, listGroupOptions)
	if err != nil {
		return "", fmt.Errorf("failed to list resource groups: %w", err)
	}
	for _, group := range groups.Resources {
		if *group.Name == groupID {
			groupID = *group.ID
		}
	}
	log.Printf("groupID = %v\n", groupID)

	options = o.controllerSvc.NewListResourceInstancesOptions()
	options.SetResourceGroupID(groupID)
	// resource ID for Power Systems Virtual Server in the Global catalog
	options.SetResourceID(powerIAASResourceID)
	options.SetLimit(perPage)

	for moreData {
		resources, _, err = o.controllerSvc.ListResourceInstancesWithContext(ctx, options)
		if err != nil {
			return "", fmt.Errorf("failed to list resource instances: %w", err)
		}
		log.Printf("len(resources.Resources) = %v\n", len(resources.Resources))

		for _, resource := range resources.Resources {
			var (
				getResourceOptions *resourcecontrollerv2.GetResourceInstanceOptions
				resourceInstance   *resourcecontrollerv2.ResourceInstance
				response           *core.DetailedResponse
			)

			getResourceOptions = o.controllerSvc.NewGetResourceInstanceOptions(*resource.ID)

			resourceInstance, response, err = o.controllerSvc.GetResourceInstance(getResourceOptions)
			if err != nil {
				return "", fmt.Errorf("failed to get instance: %w", err)
			}
			if response != nil && response.StatusCode == gohttp.StatusNotFound || response.StatusCode == gohttp.StatusInternalServerError {
				return "", fmt.Errorf("failed to get instance, response is: %v", response)
			}

			if resourceInstance.Type == nil {
				log.Printf("resourceInstance.Type = nil\n")
			} else {
				log.Printf("resourceInstance.Type = %v\n", *resourceInstance.Type)
			}
			log.Printf("resourceInstance.Name = %v\n", *resourceInstance.Name)
			if resourceInstance.GUID == nil {
				log.Printf("resourceInstance.GUID = nil\n")
			} else {
				log.Printf("resourceInstance.GUID = %v\n", *resourceInstance.GUID)
			}

			if resourceInstance.Type == nil || resourceInstance.GUID == nil {
				continue
			}
			if *resourceInstance.Type != "service_instance" && *resourceInstance.Type != "composite_instance" {
				continue
			}
			if *resourceInstance.Name != name {
				continue
			}
			return *resourceInstance.GUID, nil
		}

		// Based on: https://cloud.ibm.com/apidocs/resource-controller/resource-controller?code=go#list-resource-instances
		nextURL, err = core.GetQueryParam(resources.NextURL, "start")
		if err != nil {
			return "", fmt.Errorf("failed to GetQueryParam on start: %w", err)
		}
		if nextURL == nil {
			options.SetStart("")
		} else {
			options.SetStart(*nextURL)
		}

		moreData = *resources.RowsCount == perPage
	}

	return "", nil
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
	managementSvc  *resourcemanagerv2.ResourceManagerV2
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
//		Type: "service_instance",
		Type: "resource_instance",
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
	var ptrResourceGroup *string
	var ptrShouldDebug *string
	var ptrShouldDelete *string

	ptrApiKey = flag.String("apiKey", "", "Your IBM Cloud API key")
	ptrSearch = flag.String("search", "", "The search string to match for deletes")
	ptrServiceName = flag.String("serviceName", "", "The Power Server Service to use")
	ptrResourceGroup = flag.String("resourceGroup", "", "The resource group to use")
	ptrShouldDebug = flag.String("shouldDebug", "false", "Should output debug output")
	ptrShouldDelete = flag.String("shouldDelete", "false", "Should delete matching records")

	flag.Parse()

	if *ptrApiKey == "" {
		logMain.Fatal("Error: No API key set, use --apiKey")
	}

//	if *ptrSearch == "" {
//		logMain.Fatal("Error: No search term set, use --search")
//	}

//	if *ptrServiceName == "" {
//		logMain.Fatal("Error: No cloud service set, use --serviceName")
//	}

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

	clusterUninstaller.resourceGroupID = *ptrResourceGroup

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

	authenticator, err = clusterUninstaller.newAuthenticator(clusterUninstaller.APIKey)
	if err != nil {
		logMain.Fatalf("Error newAuthenticator: %v\n", err)
	}

	// Instantiate the service with an API key based IAM authenticator
	clusterUninstaller.managementSvc, err = resourcemanagerv2.NewResourceManagerV2(&resourcemanagerv2.ResourceManagerV2Options{
		Authenticator: authenticator,
	})
	if err != nil {
		logMain.Fatalf("loadSDKServices: creating ResourceManagerV2 Service: %w\n", err)
	}

	_, err = clusterUninstaller.search("name: *mjturek*", []string{"name", "crn", "region", "resource_id"})
	if err != nil {
		logMain.Fatal("Error clusterUninstaller.search:", err)
	}

	ctx, cancel := clusterUninstaller.contextWithTimeout()
	defer cancel()

	ServiceGUID, err := clusterUninstaller.ServiceInstanceNameToGUID(ctx, *ptrServiceName)
	if err != nil {
		logMain.Fatal("Error clusterUninstaller.ServiceInstanceNameToGUID:", err)
	}

	logMain.Printf("ServiceGUID = %v\n", ServiceGUID)
}

func main2() {
	var logMain *logrus.Logger = &logrus.Logger{
		Out:       os.Stderr,
		Formatter: new(logrus.TextFormatter),
		Level:     logrus.DebugLevel,
	}

	var ptrApiKey *string
	var ptrServiceName *string
	var clusterUninstaller *ClusterUninstaller
	var err error
// Above is just to get the moved section to compile

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
}
