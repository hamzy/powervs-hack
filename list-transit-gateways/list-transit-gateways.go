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

// package vpc1
// https://raw.githubusercontent.com/IBM/vpc-go-sdk/master/vpcv1/vpc_v1.go

// package resourcecontrollerv2
// https://raw.githubusercontent.com/IBM/platform-services-go-sdk/main/resourcecontrollerv2/resource_controller_v2.go

// package resourcemanagerv2
// https://raw.githubusercontent.com/IBM/platform-services-go-sdk/main/resourcemanagerv2/resource_manager_v2.go

// package dnsrecordsv1
// https://raw.githubusercontent.com/IBM/networking-go-sdk/master/dnsrecordsv1/dns_records_v1.go

// How to run:
// (export IBMCLOUD_API_KEY="blah"; if ! ibmcloud iam oauth-tokens 1>/dev/null 2>&1; then ibmcloud login --apikey "${IBMCLOUD_API_KEY}"; fi; go run list-transit-gateways.go -apiKey "${IBMCLOUD_API_KEY}" -search '.*rdr-hamzy-.*' -serviceName powervs-ipi-lon04 -shouldDebug false -shouldDelete false)

package main

import (
	"flag"
	"fmt"
	"io"
	gohttp "net/http"
	"os"

	"github.com/IBM-Cloud/bluemix-go"
	"github.com/IBM-Cloud/bluemix-go/api/resource/resourcev2/controllerv2"
	"github.com/IBM-Cloud/bluemix-go/authentication"
	"github.com/IBM-Cloud/bluemix-go/http"
	"github.com/IBM-Cloud/bluemix-go/rest"
	bxsession "github.com/IBM-Cloud/bluemix-go/session"
	"github.com/IBM-Cloud/power-go-client/ibmpisession"
	"github.com/golang-jwt/jwt"
	"github.com/sirupsen/logrus"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
)

// Above imports are for the glue code, below is just for destroy code
//package powervs

import (
	"context"
	"math"
	"strings"
	"time"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/networking-go-sdk/transitgatewayapisv1"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/util/wait"
)

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
			return nil, errors.Wrapf(err, "failed to list transit gateways: %v and the respose is: %s", err, response)
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
			o.Logger.Debugf("listTransitGateways: Next = %+v", *gatewayCollection.Next)
			listTransitGatewaysOptions.SetStart(*gatewayCollection.Next.Start)
		} else {
			o.Logger.Debugf("listTransitGateways: Next = nil")
		}

		moreData = gatewayCollection.Next != nil
		o.Logger.Debugf("listTransitGateways: moreData = %v", moreData)
	}
	if !foundOne {
		o.Logger.Debugf("listTransitGateways: NO matching transit gateway against: %s", o.InfraID)

		listTransitGatewaysOptions = o.tgClient.NewListTransitGatewaysOptions()
		listTransitGatewaysOptions.Limit = &perPage
		moreData = true

		for moreData {
			gatewayCollection, response, err = o.tgClient.ListTransitGatewaysWithContext(ctx, listTransitGatewaysOptions)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to list transit gateways: %v and the respose is: %s", err, response)
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
				o.Logger.Debugf("listTransitGateways: Next = %+v", *gatewayCollection.Next)
				listTransitGatewaysOptions.SetStart(*gatewayCollection.Next.Start)
			} else {
				o.Logger.Debugf("listTransitGateways: Next = nil")
			}
			moreData = gatewayCollection.Next != nil
			o.Logger.Debugf("listTransitGateways: moreData = %v", moreData)
		}
	}

	return cloudResources{}.insert(result...), nil
}

// Destroy a specified transit gateway.
func (o *ClusterUninstaller) destroyTransitGateway(item cloudResource) error {

	var (
		firstPassList cloudResources

		err error

		items []cloudResource

		ctx    context.Context
		cancel func()

		backoff wait.Backoff = wait.Backoff{Duration: 15 * time.Second,
			Factor: 1.5,
			Cap:    10 * time.Minute,
			Steps:  math.MaxInt32}

		deleteTransitGatewayOptions *transitgatewayapisv1.DeleteTransitGatewayOptions
		response                    *core.DetailedResponse
	)

	firstPassList, err = o.listTransitConnections(item)
	if err != nil {
		return err
	}

	items = o.insertPendingItems(transitGatewayConnectionTypeName, firstPassList.list())

	ctx, cancel = o.contextWithTimeout()
	defer cancel()

	for _, item := range items {
		select {
		case <-o.Context.Done():
			o.Logger.Debugf("destroyTransitGateway: case <-o.Context.Done()")
			return o.Context.Err() // we're cancelled, abort
		default:
		}

		err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
			err2 := o.destroyTransitConnection(item)
			if err2 == nil {
				return true, err2
			} else {
				o.errorTracker.suppressWarning(item.key, err2, o.Logger)
				return false, err2
			}
		})
		if err != nil {
			o.Logger.Fatalf("destroyTransitGateway: ExponentialBackoffWithContext (destroy) returns %v", err)
		}
	}

	if items = o.getPendingItems(transitGatewayTypeName); len(items) > 0 {
		if !shouldDelete {
			return nil
		}
		return errors.Errorf("destroyTransitGateway: %d undeleted items pending", len(items))
	}

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
		} else {
			for _, item := range secondPassList {
				o.Logger.Debugf("destroyTransitGateway: found %s in second pass", item.name)
			}
			return false, nil
		}
	})
	if err != nil {
		o.Logger.Fatalf("destroyTransitGateway: ExponentialBackoffWithContext (list) returns %v", err)
	}

	// We can delete the transit gateway now!
	if !shouldDelete {
		return nil
	}

	deleteTransitGatewayOptions = o.tgClient.NewDeleteTransitGatewayOptions(item.id)

	response, err = o.tgClient.DeleteTransitGatewayWithContext(ctx, deleteTransitGatewayOptions)
	if err != nil {
		o.Logger.Fatalf("destroyTransitGateway: DeleteTransitGatewayWithContext returns %v with response %v", err, response)
	}

	return nil
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

	if !shouldDelete {
		return nil
	}

	ctx, cancel = o.contextWithTimeout()
	defer cancel()

	// ...Options(transitGatewayID string, id string)
	// NOTE: item.status is reused as the parent transit gateway id!
	deleteTransitGatewayConnectionOptions = o.tgClient.NewDeleteTransitGatewayConnectionOptions(item.status, item.id)

	response, err = o.tgClient.DeleteTransitGatewayConnectionWithContext(ctx, deleteTransitGatewayConnectionOptions)
	if err != nil {
		o.Logger.Fatalf("destroyTransitConnection: DeleteTransitGatewayConnectionWithContext returns %v with response %v", err, response)
	}

	return nil
}

// listTransitGateways lists Transit Connections for a Transit Gateway in the IBM Cloud.
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
		perPage                      int64 = 32
		moreData                           = true
	)

	ctx, cancel = o.contextWithTimeout()
	defer cancel()

	listConnectionsOptions = o.tgClient.NewListConnectionsOptions()
	listConnectionsOptions.SetLimit(perPage)
	listConnectionsOptions.SetNetworkID("")

	result := []cloudResource{}

	for moreData {
		transitConnectionCollections, response, err = o.tgClient.ListConnectionsWithContext(ctx, listConnectionsOptions)
		if err != nil {
			o.Logger.Debugf("destroyTransitGateway: ListConnections returns %v and the response is: %s", err, response)
			return nil, err
		}
		for _, transitConnection = range transitConnectionCollections.Connections {
			if !strings.Contains(*transitConnection.TransitGateway.Name, o.InfraID) {
				continue
			}

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
			o.Logger.Debugf("destroyTransitGateway: First = %+v", *transitConnectionCollections.First)
		} else {
			o.Logger.Debugf("destroyTransitGateway: First = nil")
		}
		if transitConnectionCollections.Limit != nil {
			o.Logger.Debugf("destroyTransitGateway: Limit = %v", *transitConnectionCollections.Limit)
		}
		if transitConnectionCollections.Next != nil {
			o.Logger.Debugf("destroyTransitGateway: Next = %+v", *transitConnectionCollections.Next)
			listConnectionsOptions.SetStart(*transitConnectionCollections.Next.Start)
		} else {
			o.Logger.Debugf("destroyTransitGateway: Next = nil")
		}

		moreData = transitConnectionCollections.Next != nil
		o.Logger.Debugf("destroyTransitGateway: moreData = %v", moreData)
	}

	return cloudResources{}.insert(result...), nil
}

// destroyTransitGateways searches for transit gateways that have a name that starts with
// the cluster's infra ID.
func (o *ClusterUninstaller) destroyTransitGateways() error {
	var (
		firstPassList cloudResources

		err error

		items []cloudResource

		ctx    context.Context
		cancel func()

		backoff wait.Backoff = wait.Backoff{Duration: 15 * time.Second,
			Factor: 1.5,
			Cap:    10 * time.Minute,
			Steps:  math.MaxInt32}
	)

	firstPassList, err = o.listTransitGateways()
	if err != nil {
		return err
	}

	items = o.insertPendingItems(transitGatewayTypeName, firstPassList.list())

	ctx, cancel = o.contextWithTimeout()
	defer cancel()

	for _, item := range items {
		select {
		case <-o.Context.Done():
			o.Logger.Debugf("destroyTransitGateways: case <-o.Context.Done()")
			return o.Context.Err() // we're cancelled, abort
		default:
		}

		err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
			err2 := o.destroyTransitGateway(item)
			if err2 == nil {
				return true, err2
			} else {
				o.errorTracker.suppressWarning(item.key, err2, o.Logger)
				return false, err2
			}
		})
		if err != nil {
			o.Logger.Fatalf("destroyTransitGateways: ExponentialBackoffWithContext (destroy) returns %v", err)
		}
	}

	if items = o.getPendingItems(transitGatewayTypeName); len(items) > 0 {
		if !shouldDelete {
			return nil
		}
		return errors.Errorf("destroyTransitGateways: %d undeleted items pending", len(items))
	}

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
		} else {
			for _, item := range secondPassList {
				o.Logger.Debugf("destroyTransitGateways: found %s in second pass", item.name)
			}
			return false, nil
		}
	})
	if err != nil {
		o.Logger.Fatalf("destroyTransitGateways: ExponentialBackoffWithContext (list) returns %v", err)
	}

	return nil
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

	piSession *ibmpisession.IBMPISession
	tgClient  *transitgatewayapisv1.TransitGatewayApisV1

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

	var (
		authenticator core.Authenticator = &core.IamAuthenticator{
			ApiKey: *ptrApiKey,
		}
		versionDate string = "2023-07-04"
		tgClient    *transitgatewayapisv1.TransitGatewayApisV1
		tgOptions   *transitgatewayapisv1.TransitGatewayApisV1Options = &transitgatewayapisv1.TransitGatewayApisV1Options{
			Authenticator: authenticator,
			Version:       &versionDate,
		}
	)

	tgClient, err = transitgatewayapisv1.NewTransitGatewayApisV1(tgOptions)
	if err != nil {
		logMain.Fatalf("NewTransitGatewayApisV1 failed: %v", err)
	}

	clusterUninstaller.tgClient = tgClient

	err = clusterUninstaller.destroyTransitGateways()
	if err != nil {
		logMain.Fatal("Error clusterUninstaller.destroyTransitGateways:", err)
	}
}
