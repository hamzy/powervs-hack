//
// (cd destroy-cluster2/; go build; ./destroy-cluster2 -apiKey "${IBMCLOUD_API_KEY}" -baseDomain "scnl-ibm.com" -clusterName "rdr-hamzy-test" -infraID "rdr-hamzy-test" -CISInstanceCRN $(ibmcloud cis instances --output json | jq -r '.[] | select (.name|test("'${CIS_INSTANCE}'")) | .crn') -region "${POWERVS_REGION}" -zone "${POWERVS_ZONE}" -serviceInstanceGUID $(ibmcloud resource service-instance ${SERVICE_INSTANCE} --output json | jq -r '.[].guid') -resourceGroupID "powervs-ipi-resource-group" -shouldDebug true -shouldDelete true
//
// $ (cd destroy-cluster3/; ./create-destroy-cluster3.sh > destroy-cluster3.go 2>&1)
//
// $ (cd destroy-cluster3/; echo "vet:"; go vet || exit 1; echo "build:"; go build *.go || exit 1)
//
// $ (cd destroy-cluster3/; echo "vet:"; go vet || exit 1; echo "build:"; go build *.go || exit 1; ./destroy-cluster3 --apiKey "${IBMCLOUD_API_KEY}" --metadata metadata.json --shouldDebug true -shouldDelete false)

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
	"github.com/IBM-Cloud/bluemix-go/rest"
	bxsession "github.com/IBM-Cloud/bluemix-go/session"
	"github.com/IBM-Cloud/power-go-client/clients/instance"
	"github.com/IBM-Cloud/power-go-client/ibmpisession"
	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/networking-go-sdk/dnsrecordsv1"
	"github.com/IBM/networking-go-sdk/dnszonesv1"
	"github.com/IBM/networking-go-sdk/resourcerecordsv1"
	"github.com/IBM/networking-go-sdk/transitgatewayapisv1"
	"github.com/IBM/networking-go-sdk/zonesv1"
	"github.com/IBM/platform-services-go-sdk/resourcecontrollerv2"
	"github.com/IBM/platform-services-go-sdk/resourcemanagerv2"
	"github.com/IBM/vpc-go-sdk/vpcv1"
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
	"strings"
	"sync"
	"time"
)

var (
	Raw = "was not built correctly"
	log *logrus.Logger = nil
	shouldDelete       = false
	shouldDeleteDHCP   = false
	shouldDebug        = false
)

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

func contextWithTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), defaultTimeout)
}

var (
	defaultTimeout = 15 * time.Minute
	stageTimeout   = 15 * time.Minute
)

const (
	// resource Id for Power Systems Virtual Server in the Global catalog.
	powerIAASResourceID = "abd259f0-9990-11e8-acc8-b9f54a8f1661"

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

func authenticateAPIKey(apikey string) (string, error) {
	a, err := core.NewIamAuthenticatorBuilder().SetApiKey(apikey).Build()
	if err != nil {
		return "", err
	}
	token, err := a.GetToken()
	if err != nil {
		return "", err
	}
	return token, nil
}

// FetchUserDetails returns User details from the given API key.
func FetchUserDetails(apikey string) (*User, error) {
	user := User{}
	var bluemixToken string

	iamToken, err := authenticateAPIKey(apikey)
	if err != nil {
		return &user, err
	}

	if strings.HasPrefix(iamToken, "Bearer ") {
		bluemixToken = iamToken[len("Bearer "):]
	} else {
		bluemixToken = iamToken
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
	APIKey             string
	BaseDomain         string
	CISInstanceCRN     string
	ClusterName        string
	DNSInstanceCRN     string
	DNSZone            string
	InfraID            string
	Logger             logrus.FieldLogger
	Region             string
	ServiceGUID        string
	VPCRegion          string
	Zone               string
	TransitGatewayName string

	managementSvc      *resourcemanagerv2.ResourceManagerV2
	controllerSvc      *resourcecontrollerv2.ResourceControllerV2
	vpcSvc             *vpcv1.VpcV1
	zonesSvc           *zonesv1.ZonesV1
	dnsRecordsSvc      *dnsrecordsv1.DnsRecordsV1
	dnsZonesSvc        *dnszonesv1.DnsZonesV1
	resourceRecordsSvc *resourcerecordsv1.ResourceRecordsV1
	piSession          *ibmpisession.IBMPISession
	instanceClient     *instance.IBMPIInstanceClient
	imageClient        *instance.IBMPIImageClient
	jobClient          *instance.IBMPIJobClient
	keyClient          *instance.IBMPIKeyClient
	dhcpClient         *instance.IBMPIDhcpClient
	networkClient      *instance.IBMPINetworkClient
	tgClient           *transitgatewayapisv1.TransitGatewayApisV1

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
	resourceGroupID string,
	transitGatewayName string) (*ClusterUninstaller, error) {

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
		Logger:             log,
		InfraID:            infraID,
		CISInstanceCRN:     cisInstanceCRN,
		DNSInstanceCRN:     dnsInstanceCRN,
		Region:             region,
		ServiceGUID:        serviceInstanceGUID,
		TransitGatewayName: transitGatewayName,
		VPCRegion:          vpcRegion,
		Zone:               zone,
		pendingItemTracker: newPendingItemTracker(),
		resourceGroupID:    resourceGroupID,
	}, nil
}

// Run is the entrypoint to start the uninstall process.
func (o *ClusterUninstaller) Run() error {
	o.Logger.Debugf("powervs.Run")

	var ctx context.Context
	var deadline time.Time
	var ok bool
	var err error

	ctx, cancel := contextWithTimeout()
	defer cancel()

	if ctx == nil {
		return fmt.Errorf("powervs.Run: contextWithTimeout returns nil: %w", err)
	}

	deadline, ok = ctx.Deadline()
	if !ok {
		return fmt.Errorf("powervs.Run: failed to call ctx.Deadline: %w", err)
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
		return false, fmt.Errorf("failed to destroy cluster: %w", err)
	}

	return true, nil
}

func (o *ClusterUninstaller) destroyCluster() error {
	stagedFuncs := [][]struct {
		name    string
		execute func() error
	}{{
		{name: "Transit Gateways", execute: o.destroyTransitGateways},
	}, {
		{name: "Cloud Instances", execute: o.destroyCloudInstances},
	}, {
		{name: "Power Instances", execute: o.destroyPowerInstances},
	}, {
		{name: "Load Balancers", execute: o.destroyLoadBalancers},
	}, {
		{name: "Cloud Subnets", execute: o.destroyCloudSubnets},
	}, {
		{name: "Public Gateways", execute: o.destroyPublicGateways},
	}, {
		{name: "DHCPs", execute: o.destroyDHCPNetworks},
	}, {
		{name: "Power Subnets", execute: o.destroyPowerSubnets},
		{name: "Images", execute: o.destroyImages},
		{name: "VPCs", execute: o.destroyVPCs},
	}, {
		{name: "Security Groups", execute: o.destroySecurityGroups},
	}, {
		{name: "Cloud Object Storage Instances", execute: o.destroyCOSInstances},
		{name: "Cloud SSH Keys", execute: o.destroyCloudSSHKeys},
		{name: "Power SSH Keys", execute: o.destroyPowerSSHKeys},
	}, {
		{name: "DNS Records", execute: o.destroyDNSRecords},
		{name: "DNS Resource Records", execute: o.destroyResourceRecords},
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

	ctx, cancel := contextWithTimeout()
	defer cancel()

	if ctx == nil {
		return fmt.Errorf("executeStageFunction contextWithTimeout returns nil: %w", err)
	}

	deadline, ok = ctx.Deadline()
	if !ok {
		return fmt.Errorf("executeStageFunction failed to call ctx.Deadline: %w", err)
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

func (o *ClusterUninstaller) loadSDKServices() error {
	var (
		err           error
		authenticator core.Authenticator
		versionDate   = "2023-07-04"
		tgOptions     *transitgatewayapisv1.TransitGatewayApisV1Options
		serviceName   string
	)

	defer func() {
		o.Logger.Debugf("loadSDKServices: o.ServiceGUID = %v", o.ServiceGUID)
		o.Logger.Debugf("loadSDKServices: o.piSession = %v", o.piSession)
		o.Logger.Debugf("loadSDKServices: o.instanceClient = %v", o.instanceClient)
		o.Logger.Debugf("loadSDKServices: o.imageClient = %v", o.imageClient)
		o.Logger.Debugf("loadSDKServices: o.jobClient = %v", o.jobClient)
		o.Logger.Debugf("loadSDKServices: o.keyClient = %v", o.keyClient)
		o.Logger.Debugf("loadSDKServices: o.dhcpClient = %v", o.dhcpClient)
		o.Logger.Debugf("loadSDKServices: o.networkClient = %v", o.networkClient)
		o.Logger.Debugf("loadSDKServices: o.tgClient = %v", o.tgClient)
		o.Logger.Debugf("loadSDKServices: o.vpcSvc = %v", o.vpcSvc)
		o.Logger.Debugf("loadSDKServices: o.managementSvc = %v", o.managementSvc)
		o.Logger.Debugf("loadSDKServices: o.controllerSvc = %v", o.controllerSvc)
	}()

	if o.APIKey == "" {
		return fmt.Errorf("loadSDKServices: missing APIKey in metadata.json")
	}

	user, err := FetchUserDetails(o.APIKey)
	if err != nil {
		return fmt.Errorf("loadSDKServices: fetchUserDetails: %w", err)
	}

	authenticator, err = o.newAuthenticator(o.APIKey)
	if err != nil {
		return err
	}

	var options *ibmpisession.IBMPIOptions = &ibmpisession.IBMPIOptions{
		Authenticator: authenticator,
		Debug:         false,
		UserAccount:   user.Account,
		Zone:          o.Zone,
	}

	o.piSession, err = ibmpisession.NewIBMPISession(options)
	if (err != nil) || (o.piSession == nil) {
		if err != nil {
			return fmt.Errorf("loadSDKServices: ibmpisession.New: %w", err)
		}
		return fmt.Errorf("loadSDKServices: o.piSession is nil")
	}

	authenticator, err = o.newAuthenticator(o.APIKey)
	if err != nil {
		return err
	}

	// https://raw.githubusercontent.com/IBM/vpc-go-sdk/master/vpcv1/vpc_v1.go
	o.vpcSvc, err = vpcv1.NewVpcV1(&vpcv1.VpcV1Options{
		Authenticator: authenticator,
		URL:           "https://" + o.VPCRegion + ".iaas.cloud.ibm.com/v1",
	})
	if err != nil {
		return fmt.Errorf("loadSDKServices: vpcv1.NewVpcV1: %w", err)
	}

	userAgentString := fmt.Sprintf("OpenShift/4.x Destroyer/%s", Raw)
	o.vpcSvc.Service.SetUserAgent(userAgentString)

	authenticator, err = o.newAuthenticator(o.APIKey)
	if err != nil {
		return err
	}

	// Instantiate the service with an API key based IAM authenticator
	o.managementSvc, err = resourcemanagerv2.NewResourceManagerV2(&resourcemanagerv2.ResourceManagerV2Options{
		Authenticator: authenticator,
	})
	if err != nil {
		return fmt.Errorf("loadSDKServices: creating ResourceManagerV2 Service: %w", err)
	}

	authenticator, err = o.newAuthenticator(o.APIKey)
	if err != nil {
		return err
	}

	// Instantiate the service with an API key based IAM authenticator
	o.controllerSvc, err = resourcecontrollerv2.NewResourceControllerV2(&resourcecontrollerv2.ResourceControllerV2Options{
		Authenticator: authenticator,
		ServiceName:   "cloud-object-storage",
		URL:           "https://resource-controller.cloud.ibm.com",
	})
	if err != nil {
		return fmt.Errorf("loadSDKServices: creating ControllerV2 Service: %w", err)
	}

	authenticator, err = o.newAuthenticator(o.APIKey)
	if err != nil {
		return err
	}

	tgOptions = &transitgatewayapisv1.TransitGatewayApisV1Options{
		Authenticator: authenticator,
		Version:       &versionDate,
	}

	o.tgClient, err = transitgatewayapisv1.NewTransitGatewayApisV1(tgOptions)
	if err != nil {
		return fmt.Errorf("loadSDKServices: NewTransitGatewayApisV1: %w", err)
	}

	ctx, cancel := contextWithTimeout()
	defer cancel()

	// Either CISInstanceCRN is set or DNSInstanceCRN is set. Both should not be set at the same time,
	// but check both just to be safe.
	if len(o.CISInstanceCRN) > 0 {
		authenticator, err = o.newAuthenticator(o.APIKey)
		if err != nil {
			return err
		}

		o.zonesSvc, err = zonesv1.NewZonesV1(&zonesv1.ZonesV1Options{
			Authenticator: authenticator,
			Crn:           &o.CISInstanceCRN,
		})
		if err != nil {
			return fmt.Errorf("loadSDKServices: creating zonesSvc: %w", err)
		}

		// Get the Zone ID
		zoneOptions := o.zonesSvc.NewListZonesOptions()
		zoneResources, detailedResponse, err := o.zonesSvc.ListZonesWithContext(ctx, zoneOptions)
		if err != nil {
			return fmt.Errorf("loadSDKServices: Failed to list Zones: %w and the response is: %s", err, detailedResponse)
		}

		for _, zone := range zoneResources.Result {
			o.Logger.Debugf("loadSDKServices: Zone: %v", *zone.Name)
			if strings.Contains(o.BaseDomain, *zone.Name) {
				o.dnsZoneID = *zone.ID
			}
		}

		authenticator, err = o.newAuthenticator(o.APIKey)
		if err != nil {
			return err
		}

		o.dnsRecordsSvc, err = dnsrecordsv1.NewDnsRecordsV1(&dnsrecordsv1.DnsRecordsV1Options{
			Authenticator:  authenticator,
			Crn:            &o.CISInstanceCRN,
			ZoneIdentifier: &o.dnsZoneID,
		})
		if err != nil {
			return fmt.Errorf("loadSDKServices: Failed to instantiate dnsRecordsSvc: %w", err)
		}
	}

	if len(o.DNSInstanceCRN) > 0 {
		authenticator, err = o.newAuthenticator(o.APIKey)
		if err != nil {
			return err
		}

		o.dnsZonesSvc, err = dnszonesv1.NewDnsZonesV1(&dnszonesv1.DnsZonesV1Options{
			Authenticator: authenticator,
		})
		if err != nil {
			return fmt.Errorf("loadSDKServices: creating zonesSvc: %w", err)
		}

		// Get the Zone ID
		dnsCRN, err := crn.Parse(o.DNSInstanceCRN)
		if err != nil {
			return fmt.Errorf("failed to parse DNSInstanceCRN: %w", err)
		}
		options := o.dnsZonesSvc.NewListDnszonesOptions(dnsCRN.ServiceInstance)
		listZonesResponse, detailedResponse, err := o.dnsZonesSvc.ListDnszones(options)
		if err != nil {
			return fmt.Errorf("loadSDKServices: Failed to list Zones: %w and the response is: %s", err, detailedResponse)
		}

		for _, zone := range listZonesResponse.Dnszones {
			o.Logger.Debugf("loadSDKServices: Zone: %v", *zone.Name)
			if strings.Contains(o.BaseDomain, *zone.Name) {
				o.dnsZoneID = *zone.ID
			}
		}

		authenticator, err = o.newAuthenticator(o.APIKey)
		if err != nil {
			return err
		}

		o.resourceRecordsSvc, err = resourcerecordsv1.NewResourceRecordsV1(&resourcerecordsv1.ResourceRecordsV1Options{
			Authenticator: authenticator,
		})
		if err != nil {
			return fmt.Errorf("loadSDKServices: Failed to instantiate resourceRecordsSvc: %w", err)
		}
	}

	o.Logger.Debugf("loadSDKServices: o.resourceGroupID = %s", o.resourceGroupID)
	// If the user passes in a human readable resource group id, then we need to convert it to a UUID
	listGroupOptions := o.managementSvc.NewListResourceGroupsOptions()
	groups, _, err := o.managementSvc.ListResourceGroupsWithContext(ctx, listGroupOptions)
	if err != nil {
		return fmt.Errorf("loadSDKServices: Failed to list resource groups: %w", err)
	}
	for _, group := range groups.Resources {
		if *group.Name == o.resourceGroupID {
			o.Logger.Debugf("loadSDKServices: resource FOUND: %s %s", *group.Name, *group.ID)
			o.resourceGroupID = *group.ID
		} else {
			o.Logger.Debugf("loadSDKServices: resource SKIP:  %s %s", *group.Name, *group.ID)
		}
	}
	o.Logger.Debugf("loadSDKServices: o.resourceGroupID = %s", o.resourceGroupID)

	// If we should have created a service instance dynamically
	if o.ServiceGUID == "" {
		serviceName = fmt.Sprintf("%s-power-iaas", o.InfraID)
		o.Logger.Debugf("loadSDKServices: serviceName = %v", serviceName)

		o.ServiceGUID, err = o.ServiceInstanceNameToGUID(context.Background(), serviceName)
		if err != nil {
			return fmt.Errorf("loadSDKServices: ServiceInstanceNameToGUID: %w", err)
		}
	}
	if o.ServiceGUID == "" {
		// The rest of this function relies on o.ServiceGUID, so finish now!
		return nil
	}

	o.instanceClient = instance.NewIBMPIInstanceClient(context.Background(), o.piSession, o.ServiceGUID)
	if o.instanceClient == nil {
		return fmt.Errorf("loadSDKServices: o.instanceClient is nil")
	}

	o.imageClient = instance.NewIBMPIImageClient(context.Background(), o.piSession, o.ServiceGUID)
	if o.imageClient == nil {
		return fmt.Errorf("loadSDKServices: o.imageClient is nil")
	}

	o.jobClient = instance.NewIBMPIJobClient(context.Background(), o.piSession, o.ServiceGUID)
	if o.jobClient == nil {
		return fmt.Errorf("loadSDKServices: o.jobClient is nil")
	}

	o.keyClient = instance.NewIBMPIKeyClient(context.Background(), o.piSession, o.ServiceGUID)
	if o.keyClient == nil {
		return fmt.Errorf("loadSDKServices: o.keyClient is nil")
	}

	o.dhcpClient = instance.NewIBMPIDhcpClient(context.Background(), o.piSession, o.ServiceGUID)
	if o.dhcpClient == nil {
		return fmt.Errorf("loadSDKServices: o.dhcpClient is nil")
	}

	o.networkClient = instance.NewIBMPINetworkClient(context.Background(), o.piSession, o.ServiceGUID)
	if o.networkClient == nil {
		return fmt.Errorf("loadSDKServices: o.networkClient is nil")
	}

	return nil
}

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

	o.Logger.Debugf("ServiceInstanceNameToGUID: groupID = %s", groupID)
	// If the user passes in a human readable group id, then we need to convert it to a UUID
	listGroupOptions := o.managementSvc.NewListResourceGroupsOptions()
	groups, _, err := o.managementSvc.ListResourceGroupsWithContext(ctx, listGroupOptions)
	if err != nil {
		return "", fmt.Errorf("failed to list resource groups: %w", err)
	}
	for _, group := range groups.Resources {
		o.Logger.Debugf("ServiceInstanceNameToGUID: group.Name = %s", *group.Name)
		if *group.Name == groupID {
			groupID = *group.ID
		}
	}
	o.Logger.Debugf("ServiceInstanceNameToGUID: groupID = %s", groupID)

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

		for _, resource := range resources.Resources {
			var (
				getResourceOptions *resourcecontrollerv2.GetResourceInstanceOptions
				resourceInstance   *resourcecontrollerv2.ResourceInstance
				response           *core.DetailedResponse
			)

			o.Logger.Debugf("ServiceInstanceNameToGUID: resource.Name = %s", *resource.Name)

			getResourceOptions = o.controllerSvc.NewGetResourceInstanceOptions(*resource.ID)

			resourceInstance, response, err = o.controllerSvc.GetResourceInstance(getResourceOptions)
			if err != nil {
				return "", fmt.Errorf("failed to get instance: %w", err)
			}
			if response != nil && response.StatusCode == gohttp.StatusNotFound || response.StatusCode == gohttp.StatusInternalServerError {
				return "", fmt.Errorf("failed to get instance, response is: %v", response)
			}

			if resourceInstance.Type == nil {
				o.Logger.Debugf("ServiceInstanceNameToGUID: type: nil")
				continue
			}
			o.Logger.Debugf("ServiceInstanceNameToGUID: type: %v", *resourceInstance.Type)
			if resourceInstance.GUID == nil {
				o.Logger.Debugf("ServiceInstanceNameToGUID: GUID: nil")
				continue
			}
			if *resourceInstance.Type != "service_instance" && *resourceInstance.Type != "composite_instance" {
				continue
			}
			if *resourceInstance.Name != name {
				continue
			}

			o.Logger.Debugf("ServiceInstanceNameToGUID: Found match!")

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
		return fmt.Errorf("%d items pending", pending[0])
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
	COSRegion   string
	Zones       map[string]Zone
	VPCZones    []string
}

// Zone holds the sysTypes for a zone in a IBM Power VS region.
type Zone struct {
	SysTypes []string
}

// Regions holds the regions for IBM Power VS, and descriptions used during the survey.
var Regions = map[string]Region{
	"dal": {
		Description: "Dallas, USA",
		VPCRegion:   "us-south",
		COSRegion:   "us-south",
		Zones: map[string]Zone{
			"dal10": {
				SysTypes: []string{"s922", "s1022", "e980", "e1080"},
			},
			"dal12": {
				SysTypes: []string{"s922", "e980"},
			},
		},
		VPCZones: []string{"us-south-1", "us-south-2", "us-south-3"},
	},
	"eu-de": {
		Description: "Frankfurt, Germany",
		VPCRegion:   "eu-de",
		COSRegion:   "eu-de",
		Zones: map[string]Zone{
			"eu-de-1": {
				SysTypes: []string{"s922", "s1022", "e980"},
			},
			"eu-de-2": {
				SysTypes: []string{"s922", "e980"},
			},
		},
		VPCZones: []string{"eu-de-1", "eu-de-2", "eu-de-3"},
	},
	"lon": {
		Description: "London, UK",
		VPCRegion:   "eu-gb",
		COSRegion:   "eu-gb",
		Zones: map[string]Zone{
			"lon06": {
				SysTypes: []string{"s922", "e980"},
			},
		},
		VPCZones: []string{"eu-gb-1", "eu-gb-2", "eu-gb-3"},
	},
	"mad": {
		Description: "Madrid, Spain",
		VPCRegion:   "eu-es",
		COSRegion:   "eu-de", // @HACK - PowerVS says COS not supported in this region
		Zones: map[string]Zone{
			"mad02": {
				SysTypes: []string{"s922", "s1022", "e980"},
			},
			"mad04": {
				SysTypes: []string{"s1022", "e980", "e1080"},
			},
		},
		VPCZones: []string{"eu-es-1", "eu-es-2"},
	},
	"osa": {
		Description: "Osaka, Japan",
		VPCRegion:   "jp-osa",
		COSRegion:   "jp-osa",
		Zones: map[string]Zone{
			"osa21": {
				SysTypes: []string{"s922", "s1022", "e980"},
			},
		},
		VPCZones: []string{"jp-osa-1", "jp-osa-2", "jp-osa-3"},
	},
	"sao": {
		Description: "São Paulo, Brazil",
		VPCRegion:   "br-sao",
		COSRegion:   "br-sao",
		Zones: map[string]Zone{
			"sao01": {
				SysTypes: []string{"s922", "e980"},
			},
			"sao04": {
				SysTypes: []string{"s922", "e980"},
			},
		},
		VPCZones: []string{"br-sao-1", "br-sao-2", "br-sao-3"},
	},
	"syd": {
		Description: "Sydney, Australia",
		VPCRegion:   "au-syd",
		COSRegion:   "au-syd",
		Zones: map[string]Zone{
			"syd04": {
				SysTypes: []string{"s922", "e980"},
			},
			"syd05": {
				SysTypes: []string{"s922", "e980"},
			},
		},
		VPCZones: []string{"au-syd-1", "au-syd-2", "au-syd-3"},
	},
	"tor": {
		Description: "Toronto, Canada",
		VPCRegion:   "ca-tor",
		COSRegion:   "ca-tor",
		Zones: map[string]Zone{
			"tor01": {
				SysTypes: []string{"s922", "e980"},
			},
		},
		VPCZones: []string{"ca-tor-1", "ca-tor-2", "ca-tor-3"},
	},
	"us-east": {
		Description: "Washington DC, USA",
		VPCRegion:   "us-east",
		COSRegion:   "us-east",
		Zones: map[string]Zone{
			"us-east": {
				SysTypes: []string{"s922", "e980"},
			},
		},
		VPCZones: []string{"us-east-1", "us-east-2", "us-east-3"},
	},
	"us-south": {
		Description: "Dallas, USA",
		VPCRegion:   "us-south",
		COSRegion:   "us-south",
		Zones: map[string]Zone{
			"us-south": {
				SysTypes: []string{"s922", "e980"},
			},
		},
		VPCZones: []string{"us-south-1", "us-south-2", "us-south-3"},
	},
	"wdc": {
		Description: "Washington DC, USA",
		VPCRegion:   "us-east",
		COSRegion:   "us-east",
		Zones: map[string]Zone{
			"wdc06": {
				SysTypes: []string{"s922", "e980"},
			},
			"wdc07": {
				SysTypes: []string{"s922", "s1022", "e980", "e1080"},
			},
		},
		VPCZones: []string{"us-east-1", "us-east-2", "us-east-3"},
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
		for currentZone, _ := range currentRegion.Zones {
			if currentZone == zone {
				return currentRegion.VPCRegion, nil
			}
		}
	}

	return "", fmt.Errorf("VPC region corresponding to a PowerVS zone %s not found ", zone)
}

type PowerVSStruct struct {
	BaseDomain           string                            `json:"BaseDomain"`
	CISInstanceCRN       string                            `json:"cisInstanceCRN"`
	DNSInstanceCRN       string                            `json:"dnsInstanceCRN"`
	PowerVSResourceGroup string                            `json:"powerVSResourceGroup"`
	Region               string                            `json:"region"`
	VPCRegion            string                            `json:"vpcRegion"`
	Zone                 string                            `json:"zone"`
	ServiceInstanceGUID  string                            `json:"serviceInstanceGUID"`
//	ServiceEndpoints     []configv1.PowerVSServiceEndpoint `json:"serviceEndpoints,omitempty"`
	TransitGatewayName   string                            `json:"transitGatewayName"`
}

type Metadata struct {
	ClusterName string `json:"ClusterName"`
	ClusterID   string `json:"ClusterID"`
	InfraID     string `json:"InfraID"`
	PowerVS *PowerVSStruct
}

func readMetadata(fileName string) (*Metadata, error) {

	var (
		data = Metadata{}
		err error
	)

	file, err := ioutil.ReadFile(fileName)
	if err != nil {
		return &data, fmt.Errorf("Error: ReadFile returns %v", err)
	}

	err = json.Unmarshal([]byte(file), &data)
	if err != nil {
		return &data, fmt.Errorf("Error: Unmarshal returns %v", err)
	}
	if shouldDebug {
		log.Printf("data = %+v", data)
		log.Printf("data.PowerVS = %+v", data.PowerVS)
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

func (o *ClusterUninstaller) resourceNameToID(resourceGroupName string) (string, error) {

	var (
		listResourceGroupsOptions *resourcemanagerv2.ListResourceGroupsOptions
		resourceGroups            *resourcemanagerv2.ResourceGroupList
		resourceGroup             resourcemanagerv2.ResourceGroup
		resourceGroupID           string
		response                  *core.DetailedResponse
		err                       error
	)

	user, err := FetchUserDetails(o.APIKey)
	if err != nil {
		return "", fmt.Errorf("resourceNameToID: fetchUserDetails: %w", err)
	}

	listResourceGroupsOptions = o.managementSvc.NewListResourceGroupsOptions()
	listResourceGroupsOptions.SetAccountID(user.Account)
	log.Debugf("resourceNameToID: listResourceGroupsOptions = %+v", listResourceGroupsOptions)
	log.Debugf("resourceNameToID: listResourceGroupsOptions.AccountID = %s", *listResourceGroupsOptions.AccountID)

	resourceGroups, response, err = o.managementSvc.ListResourceGroups(listResourceGroupsOptions)
	if err != nil {
		return "", fmt.Errorf("resourceNameToID: ListResourceGroups: err = %v, response = %s", err, response)
	}

	for _, resourceGroup = range resourceGroups.Resources {
		if *resourceGroup.Name == resourceGroupName {
			log.Debugf("resourceNameToID: resourceGroup FOUND: %s %s", *resourceGroup.ID, *resourceGroup.Name)
			resourceGroupID = *resourceGroup.ID
		} else {
			log.Debugf("resourceNameToID: resourceGroup SKIP:  %s %s", *resourceGroup.ID, *resourceGroup.Name)
		}
	}

	return resourceGroupID, err
}

func main() {

	var (
		logMain *logrus.Logger = &logrus.Logger{
			Out: os.Stderr,
			Formatter: new(logrus.TextFormatter),
			Level: logrus.DebugLevel,
		}

		out  io.Writer

		data *Metadata = nil
		err  error

		// CLI parameters:
		ptrMetadaFilename *string
		ptrShouldDebug *string
		ptrShouldDelete *string
		ptrShouldDeleteDHCP *string
		ptrApiKey *string
		ptrBaseDomain *string
		ptrServiceInstanceGUID *string
		ptrClusterName *string			// In metadata.json
		ptrInfraID *string			// In metadata.json
		ptrCISInstanceCRN *string		// In metadata.json
		ptrDNSInstanceCRN *string		// In metadata.json
		ptrRegion *string			// In metadata.json
		ptrZone *string				// In metadata.json
		ptrResourceGroupID *string
		ptrTransitGateway *string		// In metadata.json

		needAPIKey              = true
		needBaseDomain          = true
		needServiceInstanceGUID = true
		needClusterName         = true
		needInfraID             = true
		needCISInstanceCRN      = true
		needDNSInstanceCRN      = true
		needRegion              = true
		needZone                = true
		needResourceGroupID     = true
		needTransitGateway      = true

		clusterUninstaller *ClusterUninstaller
	)

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
	ptrTransitGateway = flag.String("transitGateway", "", "The transit gateway to use")

	flag.Parse()

	switch strings.ToLower(*ptrShouldDebug) {
	case "true":
		shouldDebug = true
	case "false":
		shouldDebug = false
	default:
		logMain.Fatalf("Error: shouldDebug is not true/false (%s)", *ptrShouldDebug)
	}

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
		log.Printf("ptrMetadaFilename      = %v", *ptrMetadaFilename)
		log.Printf("ptrShouldDebug         = %v", *ptrShouldDebug)
		log.Printf("ptrShouldDelete        = %v", *ptrShouldDelete)
		log.Printf("ptrShouldDeleteDHCP    = %v", *ptrShouldDeleteDHCP)
		log.Printf("ptrApiKey              = %v", *ptrApiKey)
		log.Printf("ptrBaseDomain          = %v", *ptrBaseDomain)
		log.Printf("ptrServiceInstanceGUID = %v", *ptrServiceInstanceGUID)
		log.Printf("ptrClusterName         = %v", *ptrClusterName)
		log.Printf("ptrInfraID             = %v", *ptrInfraID)
		log.Printf("ptrCISInstanceCRN      = %v", *ptrCISInstanceCRN)
		log.Printf("ptrDNSInstanceCRN      = %v", *ptrDNSInstanceCRN)
		log.Printf("ptrRegion              = %v", *ptrRegion)
		log.Printf("ptrZone                = %v", *ptrZone)
		log.Printf("ptrResourceGroupID     = %v", *ptrResourceGroupID)
		log.Printf("ptrTransitGateway      = %v", *ptrTransitGateway)
	}

	switch strings.ToLower(*ptrShouldDeleteDHCP) {
	case "true":
		shouldDeleteDHCP = true
	case "false":
		shouldDeleteDHCP = false
	default:
		log.Fatalf("Error: shouldDeleteDHCP is not true/false (%s)", *ptrShouldDeleteDHCP)
	}

	if *ptrMetadaFilename != "" {
		if shouldDebug { log.Printf("ptrMetadaFilename = %v", *ptrMetadaFilename) }

		data, err = readMetadata(*ptrMetadaFilename)
		if err != nil {
			log.Fatal(err)
		}

		if shouldDebug {
			log.Printf("ClusterName          = %v", data.ClusterName)
			log.Printf("ClusterID            = %v", data.ClusterID)
			log.Printf("InfraID              = %v", data.InfraID)
			log.Printf("BaseDomain           = %v", data.PowerVS.BaseDomain)
			log.Printf("CISInstanceCRN       = %v", data.PowerVS.CISInstanceCRN)
			log.Printf("DNSInstanceCRN       = %v", data.PowerVS.DNSInstanceCRN)
			log.Printf("PowerVSResourceGroup = %v", data.PowerVS.PowerVSResourceGroup)
			log.Printf("Region               = %v", data.PowerVS.Region)
			log.Printf("VPCRegion            = %v", data.PowerVS.VPCRegion)
			log.Printf("Zone                 = %v", data.PowerVS.Zone)
			log.Printf("ServiceInstanceGUID  = %v", data.PowerVS.ServiceInstanceGUID)
			log.Printf("TransitGatewayName   = %v", data.PowerVS.TransitGatewayName)
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

		ptrClusterName = &data.ClusterName
		needClusterName = false

		ptrInfraID = &data.InfraID
		needInfraID = false

		ptrBaseDomain = &data.PowerVS.BaseDomain
		needBaseDomain = false

		ptrCISInstanceCRN = &data.PowerVS.CISInstanceCRN
		needCISInstanceCRN = false

		ptrDNSInstanceCRN = &data.PowerVS.DNSInstanceCRN
		needDNSInstanceCRN = false

		ptrResourceGroupID = &data.PowerVS.PowerVSResourceGroup
		needResourceGroupID = false

		ptrRegion = &data.PowerVS.Region
		needRegion = false

		ptrZone = &data.PowerVS.Zone
		needZone = false

		ptrServiceInstanceGUID = &data.PowerVS.ServiceInstanceGUID
		needServiceInstanceGUID = false

		ptrTransitGateway = &data.PowerVS.TransitGatewayName
		needTransitGateway = false
	}
	if needAPIKey && *ptrApiKey == "" {
		log.Fatal("Error: No API key set, use -apiKey")
	}
	if needBaseDomain && *ptrBaseDomain == "" {
		log.Fatal("Error: No base domain set, use -baseDomain")
	}
	if needServiceInstanceGUID && *ptrServiceInstanceGUID == "" {
		log.Fatal("Error: No service instance GUID set, use -serviceInstanceGUID")
	}
	if needClusterName && *ptrClusterName == "" {
		log.Fatal("Error: No cluster name set, use -clusterName")
	}
	if needInfraID && *ptrInfraID == "" {
		log.Fatal("Error: No Infra ID set, use -infraID")
	}
	if *ptrCISInstanceCRN != "" {
		needDNSInstanceCRN = false
	}
	if *ptrDNSInstanceCRN != "" {
		needCISInstanceCRN = false
	}
	if needCISInstanceCRN && *ptrCISInstanceCRN == "" {
		log.Fatal("Error: No CISInstanceCRN set, use -CISInstanceCRN")
	}
	if needDNSInstanceCRN && *ptrDNSInstanceCRN == "" {
		log.Fatal("Error: No DNSInstanceCRN set, use -DNSInstanceCRN")
	}
	if needRegion && *ptrRegion == "" {
		log.Fatal("Error: No region set, use -region")
	}
	if needZone && *ptrZone == "" {
		log.Fatal("Error: No zone set, use -zone")
	}
	if needResourceGroupID && *ptrResourceGroupID == "" {
		log.Fatal("Error: No resource group ID set, use -resourceGroupID")
	}
	if needTransitGateway && *ptrTransitGateway == "" {
		log.Fatal("Error: No transit gateway set, use -transitGateway")
	}
	switch strings.ToLower(*ptrShouldDelete) {
	case "true":
		shouldDelete = true
	case "false":
		shouldDelete = false
	default:
		log.Fatalf("Error: shouldDelete is not true/false (%s)", *ptrShouldDelete)
	}

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
		*ptrResourceGroupID,
		*ptrTransitGateway)
	if err != nil {
		log.Fatalf("Error New: %v", err)
	}
	if shouldDebug { log.Printf("clusterUninstaller = %+v", clusterUninstaller) }

	err = clusterUninstaller.Run ()
	if err != nil {
		log.Fatalf("Error clusterUninstaller.Run: %v", err)
	}

}
