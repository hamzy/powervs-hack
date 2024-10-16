// Copyright 2024 IBM Corp
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
	"fmt"
	"math"
	gohttp "net/http"
	"strings"
	"time"

	"github.com/IBM-Cloud/bluemix-go"
	"github.com/IBM-Cloud/bluemix-go/authentication"
	"github.com/IBM-Cloud/bluemix-go/http"
	"github.com/IBM-Cloud/bluemix-go/rest"
	bxsession "github.com/IBM-Cloud/bluemix-go/session"
	"github.com/IBM-Cloud/power-go-client/clients/instance"
	"github.com/IBM-Cloud/power-go-client/ibmpisession"
	"github.com/IBM-Cloud/power-go-client/power/models"
	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/platform-services-go-sdk/resourcecontrollerv2"
	"github.com/IBM/platform-services-go-sdk/resourcemanagerv2"
	"github.com/golang-jwt/jwt"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/ptr"
)

const (
	// resource ID for Power Systems Virtual Server in the Global catalog.
	virtualServerResourceID = "f165dd34-3a40-423b-9d95-e90a23f724dd"
)

// ServiceInstanceState describes the state of a service instance.
type ServiceInstanceState string

var (
	// ServiceInstanceStateActive is the string representing a service instance in an active state.
	ServiceInstanceStateActive = ServiceInstanceState("active")

	// ServiceInstanceStateProvisioning is the string representing a service instance in a provisioning state.
	ServiceInstanceStateProvisioning = ServiceInstanceState("provisioning")

	// ServiceInstanceStateFailed is the string representing a service instance in a failed state.
	ServiceInstanceStateFailed = ServiceInstanceState("failed")

	// ServiceInstanceStateRemoved is the string representing a service instance in a removed state.
	ServiceInstanceStateRemoved = ServiceInstanceState("removed")
)

type ServiceInstanceOptions struct {
	Mode    Mode
	ApiKey  string
	Region  string
	Zone    string
	Name    string
	GroupID string
	CIDR    string
	SshKey  string
	Number  int
}

type ServiceInstance struct {
	options ServiceInstanceOptions

	controllerSvc *resourcecontrollerv2.ResourceControllerV2

	ctx context.Context

	innerSi *resourcecontrollerv2.ResourceInstance

	siName string

	networkName string

	dhcpName string

	sshKeyName string

	pvmInstanceName string

	resourceGroupID string

	piSession *ibmpisession.IBMPISession

	networkClient *instance.IBMPINetworkClient

	innerNetwork *models.Network

	keyClient *instance.IBMPIKeyClient

	innerSshKey *models.SSHKey

	imageClient *instance.IBMPIImageClient

	stockImageId string

	rhcosImageId string

	dhcpClient *instance.IBMPIDhcpClient

	dhcpServer *models.DHCPServerDetail

	instanceClient *instance.IBMPIInstanceClient

	jobClient *instance.IBMPIJobClient
}

type ImageImportOptions struct {
	ImageName           string
	BucketName          string
	BucketAccess        string
	BucketImageFileName string
	BucketRegion        string
	StorageType         string
}

func initServiceInstance(options ServiceInstanceOptions) (*resourcecontrollerv2.ResourceControllerV2, error) {

	var (
		authenticator core.Authenticator = &core.IamAuthenticator{
			ApiKey: options.ApiKey,
		}

		controllerSvc *resourcecontrollerv2.ResourceControllerV2

		err error
	)

	// Instantiate the service with an API key based IAM authenticator
	controllerSvc, err = resourcecontrollerv2.NewResourceControllerV2(&resourcecontrollerv2.ResourceControllerV2Options{
		Authenticator: authenticator,
		ServiceName:   "cloud-object-storage",
		URL:           "https://resource-controller.cloud.ibm.com",
	})
	if err != nil {
		log.Fatalf("Error: resourcecontrollerv2.NewResourceControllerV2 returns %v", err)
		return nil, err
	}

	return controllerSvc, nil
}

// convertResourceGroupNameToID converts a resource group name/id to an id.
func convertResourceGroupNameToID(options ServiceInstanceOptions) (string, error) {

	var (
		authenticator core.Authenticator = &core.IamAuthenticator{
			ApiKey: options.ApiKey,
		}
		managementSvc *resourcemanagerv2.ResourceManagerV2
		err           error
	)

	// Instantiate the service with an API key based IAM authenticator
	managementSvc, err = resourcemanagerv2.NewResourceManagerV2(&resourcemanagerv2.ResourceManagerV2Options{
		Authenticator: authenticator,
	})
	if err != nil {
		return "", fmt.Errorf("Error: resourcemanagerv2.NewResourceManagerV2 returns %w", err)
	}

	listResourceGroupsOptions := managementSvc.NewListResourceGroupsOptions()

	resourceGroups, _, err := managementSvc.ListResourceGroups(listResourceGroupsOptions)
	if err != nil {
		return "", err
	}

	for _, resourceGroup := range resourceGroups.Resources {
		if *resourceGroup.Name == options.GroupID {
			log.Debugf("convertResourceGroupNameToID: FOUND NAME = %s, id = %s", *resourceGroup.Name, *resourceGroup.ID)

			return *resourceGroup.ID, nil
		} else if *resourceGroup.ID == options.GroupID {
			log.Debugf("convertResourceGroupNameToID: FOUND name = %s, ID = %s", *resourceGroup.Name, *resourceGroup.ID)

			return *resourceGroup.ID, nil
		}

		log.Debugf("convertResourceGroupNameToID: SKIP Name = %s, Id = %s", *resourceGroup.Name, *resourceGroup.ID)
	}

	return "", fmt.Errorf("failed to find resource group %v", options.GroupID)
}

func leftInContext(ctx context.Context) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return math.MaxInt64
	}

	duration := time.Until(deadline)

	return duration
}

func NewServiceInstance(siOptions ServiceInstanceOptions) (*ServiceInstance, error) {

	var (
		siName string

		networkName string

		dhcpName string

		sshKeyName string

		pvmInstanceName string

		controllerSvc *resourcecontrollerv2.ResourceControllerV2

		ctx context.Context

		resourceGroupID string

		err error
	)

	log.Debugf("NewServiceInstance: siOptions = %+v", siOptions)

	// @HACK
	switch siOptions.Number {
	case 1:
		siName = fmt.Sprintf("%s-power-iaas", siOptions.Name)
	case 2:
		siName = fmt.Sprintf("%s-power2-iaas", siOptions.Name)
	case 3:
		siName = fmt.Sprintf("%s-power3-iaas", siOptions.Name)
	}

	networkName = fmt.Sprintf("%s-si-network", siOptions.Name)
	dhcpName = fmt.Sprintf("%s", siOptions.Name)
	sshKeyName = fmt.Sprintf("%s-si-sshkey", siOptions.Name)
	pvmInstanceName = fmt.Sprintf("%s-si-instance", siOptions.Name)

	controllerSvc, err = initServiceInstance(siOptions)
	log.Debugf("NewServiceInstance: controllerSvc = %v", controllerSvc)
	if err != nil {
		log.Fatalf("Error: NewServiceInstance: initServiceInstance returns %v", err)
		return nil, err
	}

	ctx = context.Background()
	log.Debugf("NewServiceInstance: ctx = %v", ctx)

	resourceGroupID, err = convertResourceGroupNameToID(siOptions)
	if err != nil {
		log.Fatalf("Error: convertResourceGroupNameToID returns %v", err)
		return nil, err
	}

	return &ServiceInstance{
		options:         siOptions,
		controllerSvc:   controllerSvc,
		ctx:             ctx,
		innerSi:         nil,
		siName:          siName,
		networkName:     networkName,
		dhcpName:        dhcpName,
		sshKeyName:      sshKeyName,
		pvmInstanceName: pvmInstanceName,
		resourceGroupID: resourceGroupID,
	}, nil
}

func (si *ServiceInstance) Run() error {

	var (
		foundSi *resourcecontrollerv2.ResourceInstance

		err error
	)

	// Does it already exist?
	if si.innerSi == nil {
		foundSi, err = si.findServiceInstance()
		if err != nil {
			log.Fatalf("Error: findServiceInstance returns %v", err)
			return err
		} else {
			log.Debugf("Run: foundSi = %v", foundSi)
			si.innerSi = foundSi
		}
	}

	switch si.options.Mode {
	case ModeCreate:
		err = si.createServiceInstance()
	case ModeDelete:
		err = si.deleteServiceInstance()
	default:
		return fmt.Errorf("ServiceInstance options must be either Create or Delete (%d)", si.options.Mode)
	}

	return err
}

func (si *ServiceInstance) CRN() (string, error) {

	if si.innerSi == nil {
		return "", fmt.Errorf("ServiceInstance does not exist to have a CRN")
	}

	return *si.innerSi.CRN, nil
}

func (si *ServiceInstance) Name() (string, error) {

	if si.innerSi == nil {
		return "", fmt.Errorf("ServiceInstance does not exist to have a Name")
	}

	return *si.innerSi.Name, nil
}

func (si *ServiceInstance) Valid() bool {

	if si.innerSi == nil {
		return false
	}
	return true
}

func (si *ServiceInstance) GetStockImageId() string {

	return si.stockImageId
}

func (si *ServiceInstance) GetRhcosImageId() string {

	return si.rhcosImageId
}

func (si *ServiceInstance) GetNetworkID() (*string, error) {

	if si.innerSi == nil {
		return ptr.To(""), fmt.Errorf("GetNetworkID innerSi is nil")
	}
	if si.innerNetwork != nil {
		return si.innerNetwork.NetworkID, nil
	} else if si.dhcpServer != nil {
		return si.dhcpServer.Network.ID, nil
	} else {
		return ptr.To(""), fmt.Errorf("GetNetworkID innerNetwork and dhcpServer is nil")
	}
}

func (si *ServiceInstance) GetDhcpServerID() (*string, error) {

	if si.innerSi == nil {
		return ptr.To(""), fmt.Errorf("GetDhcpServerID innerSi is nil")
	}
	if si.dhcpServer == nil {
		return ptr.To(""), fmt.Errorf("GetDhcpServerID dhcpServer is nil")
	}

	return si.dhcpServer.Network.ID, nil
}

func (si *ServiceInstance) GetNumber() (int, error) {

	if si.innerSi == nil {
		return 0, fmt.Errorf("GetNumber innerSi is nil")
	}

	return si.options.Number, nil
}

func (si *ServiceInstance) findServiceInstance() (*resourcecontrollerv2.ResourceInstance, error) {

	var (
		options   *resourcecontrollerv2.ListResourceInstancesOptions
		resources *resourcecontrollerv2.ResourceInstancesList
		err       error
		perPage   int64 = 64
		moreData        = true
		nextURL   *string
	)

	options = si.controllerSvc.NewListResourceInstancesOptions()
	// options.SetType("resource_instance")
	options.SetResourceGroupID(si.resourceGroupID)
	options.SetResourcePlanID(virtualServerResourceID)
	options.SetLimit(perPage)

	for moreData {
		if options.Start != nil {
			log.Debugf("findServiceInstance: options = %+v, options.Limit = %v, options.Start = %v, options.ResourceGroupID = %v", options, *options.Limit, *options.Start, *options.ResourceGroupID)
		} else {
			log.Debugf("findServiceInstance: options = %+v, options.Limit = %v, options.ResourceGroupID = %v", options, *options.Limit, *options.ResourceGroupID)
		}

		resources, _, err = si.controllerSvc.ListResourceInstancesWithContext(si.ctx, options)
		if err != nil {
			log.Fatalf("Error: ListResourceInstancesWithContext returns %v", err)
			return nil, err
		}

		log.Debugf("findServiceInstance: resources.RowsCount = %v", *resources.RowsCount)

		for _, resource := range resources.Resources {
			var (
				getResourceOptions *resourcecontrollerv2.GetResourceInstanceOptions
				resourceInstance   *resourcecontrollerv2.ResourceInstance
				response           *core.DetailedResponse
			)

			getResourceOptions = si.controllerSvc.NewGetResourceInstanceOptions(*resource.ID)

			resourceInstance, response, err = si.controllerSvc.GetResourceInstance(getResourceOptions)
			if err != nil {
				log.Fatalf("Error: GetResourceInstance returns %v", err)
				return nil, err
			}
			if response != nil && response.StatusCode == gohttp.StatusNotFound {
				log.Debugf("findServiceInstance: gohttp.StatusNotFound")
				continue
			} else if response != nil && response.StatusCode == gohttp.StatusInternalServerError {
				log.Debugf("findServiceInstance: gohttp.StatusInternalServerError")
				continue
			}

			if resourceInstance.Type == nil || resourceInstance.GUID == nil {
				continue
			}
			if *resourceInstance.Type != "service_instance" && *resourceInstance.Type != "composite_instance" {
				continue
			}

			if strings.Contains(*resource.Name, si.siName) {
				var (
					getOptions *resourcecontrollerv2.GetResourceInstanceOptions

					foundSi *resourcecontrollerv2.ResourceInstance
				)

				log.Debugf("listServiceInstances: FOUND Name = %s", *resource.Name)

				getOptions = si.controllerSvc.NewGetResourceInstanceOptions(*resource.ID)

				foundSi, response, err = si.controllerSvc.GetResourceInstanceWithContext(si.ctx, getOptions)
				if err != nil {
					log.Fatalf("Error: GetResourceInstanceWithContext: response = %v, err = %v", response, err)
					return nil, err
				}

				return foundSi, nil
			} else {
				log.Debugf("listServiceInstances: SKIP Name = %s", *resource.Name)
			}
		}

		// Based on: https://cloud.ibm.com/apidocs/resource-controller/resource-controller?code=go#list-resource-instances
		nextURL, err = core.GetQueryParam(resources.NextURL, "start")
		if err != nil {
			log.Fatalf("Error: GetQueryParam returns %v", err)
			return nil, err
		}
		if nextURL == nil {
			// log.Debugf("nextURL = nil")
			options.SetStart("")
		} else {
			// log.Debugf("nextURL = %v", *nextURL)
			options.SetStart(*nextURL)
		}

		moreData = *resources.RowsCount == perPage
	}

	return nil, nil
}

func (si *ServiceInstance) createServiceInstance() error {

	var (
		options *resourcecontrollerv2.CreateResourceInstanceOptions

		importOptions ImageImportOptions

		response *core.DetailedResponse

		err error
	)

	if si.innerSi == nil {
		options = si.controllerSvc.NewCreateResourceInstanceOptions(si.siName, // name string
			si.options.Zone,         // target string
			si.resourceGroupID,      // resourceGroup string
			virtualServerResourceID) // resourcePlanID string

		log.Debugf("createServiceInstance: si.siName               = %+v", si.siName)
		log.Debugf("createServiceInstance: si.options.Zone         = %+v", si.options.Zone)
		log.Debugf("createServiceInstance: si.resourceGroupID      = %+v", si.resourceGroupID)
		log.Debugf("createServiceInstance: virtualServerResourceID = %+v", virtualServerResourceID)

		si.innerSi, response, err = si.controllerSvc.CreateResourceInstanceWithContext(si.ctx, options)
		if err != nil {
			log.Fatalf("Error: CreateResourceInstanceWithContext: response = %v, err = %v", response, err)
			return err
		}

		err = si.waitForServiceInstanceReady()
		if err != nil {
			log.Fatalf("Error: waitForServiceInstanceReady returns %v", err)
			return err
		}
	}
	if si.innerSi == nil {
		return fmt.Errorf("Error: createServiceInstance has a nil ServiceInstance!")
	}

	err = si.createClients()
	if err != nil {
		log.Fatalf("Error: createClients returns %v", err)
		return err
	}

	// @HACK
	if false {
		err = si.addNetwork()
		if err != nil {
			log.Fatalf("Error: addNetwork returns %v", err)
			return err
		}
	} else {
		err = si.addDhcpServer()
		if err != nil {
			log.Fatalf("Error: addDhcpServer returns %v", err)
			return err
		}
	}

	err = si.addSshKey()
	if err != nil {
		log.Fatalf("Error: addSshKey returns %v", err)
		return err
	}

	err = si.addStockImage("CentOS-Stream-9")
	if err != nil {
		log.Fatalf("Error: addStockImage returns %v", err)
		return err
	}

	importOptions = ImageImportOptions {
		ImageName:           fmt.Sprintf("rhcos-%s", si.options.Name),
		BucketName:          fmt.Sprintf("rhcos-powervs-images-%s", si.options.Region),
		BucketAccess:        "public",
		BucketImageFileName: "rhcos-417-94-202407010929-0-ppc64le-powervs.ova.gz",	// @TODO
		BucketRegion:        si.options.Region,
		StorageType:         "tier3",
	}

	err = si.addRHCOSImage(importOptions)
	if err != nil {
		log.Fatalf("Error: addRHCOSImage returns %v", err)
		return err
	}

	return nil
}

func (si *ServiceInstance) createClients() error {

	var (
		piSession *ibmpisession.IBMPISession

		err error
	)

	if si.piSession == nil {
		piSession, err = si.createPiSession()
		if err != nil {
			log.Fatalf("Error: createPiSession returns %v", err)
			return err
		}
		log.Debugf("createServiceInstance: piSession = %+v", piSession)
		si.piSession = piSession
	}
	if si.piSession == nil {
		return fmt.Errorf("Error: createServiceInstance has a nil piSession!")
	}

	if si.networkClient == nil {
		si.networkClient = instance.NewIBMPINetworkClient(si.ctx, si.piSession, *si.innerSi.GUID)
		log.Debugf("createServiceInstance: networkClient = %v", si.networkClient)
	}
	if si.networkClient == nil {
		return fmt.Errorf("Error: createServiceInstance has a nil networkClient!")
	}

	if si.keyClient == nil {
		si.keyClient = instance.NewIBMPIKeyClient(si.ctx, si.piSession, *si.innerSi.GUID)
		log.Debugf("createServiceInstance: keyClient = %v", si.keyClient)
	}
	if si.keyClient == nil {
		return fmt.Errorf("Error: createServiceInstance has a nil keyClient!")
	}

	if si.imageClient == nil {
		si.imageClient = instance.NewIBMPIImageClient(si.ctx, si.piSession, *si.innerSi.GUID)
		log.Debugf("createServiceInstance: imageClient = %v", si.imageClient)
	}
	if si.imageClient == nil {
		return fmt.Errorf("Error: createServiceInstance has a nil imageClient!")
	}

	if si.dhcpClient == nil {
		si.dhcpClient = instance.NewIBMPIDhcpClient(si.ctx, si.piSession, *si.innerSi.GUID)
		log.Debugf("createServiceInstance: dhcpClient = %v", si.dhcpClient)
	}
	if si.dhcpClient == nil {
		return fmt.Errorf("Error: createServiceInstance has a nil dhcpClient!")
	}

	if si.instanceClient == nil {
		si.instanceClient = instance.NewIBMPIInstanceClient(si.ctx, si.piSession, *si.innerSi.GUID)
		log.Debugf("createServiceInstance: instanceClient = %v", si.instanceClient)
	}
	if si.instanceClient == nil {
		return fmt.Errorf("Error: createServiceInstance has a nil instanceClient!")
	}

	if si.jobClient == nil {
		si.jobClient = instance.NewIBMPIJobClient(si.ctx, si.piSession, *si.innerSi.GUID)
		log.Debugf("createServiceInstance: jobClient = %v", si.jobClient)
	}
	if si.jobClient == nil {
		return fmt.Errorf("Error: createServiceInstance has a nil jobClient!")
	}

	return nil
}

func (si *ServiceInstance) waitForServiceInstanceReady() error {

	var (
		getOptions *resourcecontrollerv2.GetResourceInstanceOptions

		foundSi *resourcecontrollerv2.ResourceInstance

		response *core.DetailedResponse

		err error
	)

	if si.innerSi == nil {
		return fmt.Errorf("waitForServiceInstanceReady innerSi is nil")
	}

	getOptions = si.controllerSvc.NewGetResourceInstanceOptions(*si.innerSi.ID)

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(si.ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(si.ctx, backoff, func(context.Context) (bool, error) {
		var err2 error

		foundSi, response, err2 = si.controllerSvc.GetResourceInstanceWithContext(si.ctx, getOptions)
		if err2 != nil {
			log.Fatalf("Error: Wait GetResourceInstanceWithContext: response = %v, err = %v", response, err2)
			return false, err2
		}
		log.Debugf("waitForServiceInstanceReady: State = %s", *foundSi.State)
		switch ServiceInstanceState(*foundSi.State) {
		case ServiceInstanceStateActive:
			return true, nil
		case ServiceInstanceStateProvisioning:
			return false, nil
		case ServiceInstanceStateFailed:
			return true, fmt.Errorf("waitForServiceInstanceReady: failed state")
		case ServiceInstanceStateRemoved:
			return true, fmt.Errorf("waitForServiceInstanceReady: removed state")
		default:
			return true, fmt.Errorf("waitForServiceInstanceReady: unknown state: %s", *foundSi.State)
		}
	})
	if err != nil {
		log.Fatalf("Error: ExponentialBackoffWithContext returns %v", err)
		return err
	}

	return nil
}

func (si *ServiceInstance) deleteServiceInstance() error {

	var (
		options *resourcecontrollerv2.DeleteResourceInstanceOptions

		response *core.DetailedResponse

		err error
	)

	log.Debugf("deleteServiceInstance: si.options.Name = %s", si.options.Name);

	if si.innerSi == nil {
		return nil
	}

	err = si.createClients()
	if err != nil {
			log.Fatalf("Error: createClients returns %v", err)
		return err
	}

	if si.keyClient == nil {
		return fmt.Errorf("Error: deleteServiceInstance called on nil keyClient")
	}
	si.innerSshKey, err = si.findSshKey()
	log.Debugf("deleteServiceInstance: innerSshKey = %+v", si.innerSshKey)
	if err != nil {
		return fmt.Errorf("Error: findSshKey returns %v", err)
	}
	if si.innerSshKey != nil {
		err = si.keyClient.Delete(*si.innerSshKey.Name)
		if err != nil {
			log.Fatalf("Error: si.keyClient.Delete(%s) returns %v", *si.innerSshKey.Name, err)
			return err
		}
		si.innerSshKey = nil
	}

	if si.networkClient == nil {
		return fmt.Errorf("Error: deleteServiceInstance called on nil networkClient")
	}
	si.innerNetwork, err = si.findNetwork()
	log.Debugf("deleteServiceInstance: innerNetwork = %+v", si.innerNetwork)
	if err != nil {
		return fmt.Errorf("Error: findNetwork returns %v", err)
	}
	if si.innerNetwork != nil {
		err = si.networkClient.Delete(*si.innerNetwork.NetworkID)
		if err != nil {
			log.Fatalf("Error: si.networkClient.Delete(%s) returns %v", *si.innerNetwork.NetworkID, err)
			return err
		}
		si.innerNetwork = nil
	}

	if si.dhcpClient == nil {
		return fmt.Errorf("Error: deleteServiceInstance called on nil dhcpClient")
	}
	si.dhcpServer, err = si.findDhcpServer()
	log.Debugf("deleteServiceInstance: dhcpServer = %+v", si.dhcpServer)
	if err != nil {
		return fmt.Errorf("Error: findDhcpServer returns %v", err)
	}
	if si.dhcpServer != nil {
		err = si.dhcpClient.Delete(*si.dhcpServer.ID)
		if err != nil {
			return fmt.Errorf("Error: si.dhcpClient.Delete returns %v", err)
		}
		err = si.waitForDhcpServerDelete(*si.dhcpServer.ID)
		if err != nil {
			log.Fatalf("Error: waitForDhcpServerDelete returns %v", err)
			return err
		}
	}

	if si.imageClient == nil {
		return fmt.Errorf("Error: deleteServiceInstance called on nil imageClient")
	}

	if si.instanceClient == nil {
		return fmt.Errorf("Error: deleteServiceInstance called on nil instanceClient")
	}
	err = si.deleteInstance()
	if err != nil {
		log.Fatalf("Error: deleteServiceInstance: deleteInstance returns %v", err)
		return err
	}

	options = si.controllerSvc.NewDeleteResourceInstanceOptions(*si.innerSi.ID)

	response, err = si.controllerSvc.DeleteResourceInstanceWithContext(si.ctx, options)
	if err != nil {
		log.Fatalf("Error: DeleteResourceInstanceWithContext: response = %v, err = %v", response, err)
		return err
	}

	err = si.waitForServiceInstanceReady()
	if err != nil {
		log.Fatalf("Error: deleteServiceInstance: waitForServiceInstanceReady returns %v", err)
		return err
	}

	si.innerSi = nil
	si.keyClient = nil
	si.networkClient = nil

	return nil
}

func (si *ServiceInstance) addNetwork() error {

	var (
		networkCreate *models.NetworkCreate

		err error
	)

	if si.innerSi == nil {
		return fmt.Errorf("Error: addNetwork called on nil ServiceInstance")
	}
	if si.networkClient == nil {
		return fmt.Errorf("Error: addNetwork called on nil networkClient")
	}

	if si.innerNetwork == nil {
		si.innerNetwork, err = si.findNetwork()
		log.Debugf("addNetwork: innerNetwork = %+v", si.innerNetwork)
		if err != nil {
			return fmt.Errorf("Error: findNetwork returns %v", err)
		}
	}

	if si.innerNetwork == nil {
		networkCreate = &models.NetworkCreate{
			/*
				AccessConfig:    AccessConfig
				DNSServers:      []string
				Gateway:         string
				IPAddressRanges: []*IPAddressRange
				Jumbo:           bool
				Mtu:             *int64
			*/
			Cidr: si.options.CIDR,
			Name: si.networkName,
			Type: ptr.To("vlan"),
		}

		log.Debugf("addNetwork: networkCreate = %+v", networkCreate)
		si.innerNetwork, err = si.networkClient.Create(networkCreate)
		if err != nil {
			return fmt.Errorf("Error: si.networkClient.Create returns %v", err)
		}
		log.Debugf("addNetwork: si.innerNetwork = %+v", si.innerNetwork)
	}

	return nil
}

func (si *ServiceInstance) findNetwork() (*models.Network, error) {

	var (
		networks *models.Networks

		networkRef *models.NetworkReference

		network *models.Network

		err error
	)

	if si.innerSi == nil {
		return nil, fmt.Errorf("Error: findNetwork called on nil ServiceInstance")
	}
	if si.networkClient == nil {
		return nil, fmt.Errorf("Error: findNetwork has nil networkClient")
	}

	log.Debugf("findNetwork: si.networkName = %s", si.networkName)

	networks, err = si.networkClient.GetAll()
	if err != nil {
		return nil, fmt.Errorf("Error: si.networkClient.GetAll returns %v", err)
	}

	for _, networkRef = range networks.Networks {
		if strings.Contains(*networkRef.Name, si.networkName) {
			log.Debugf("findNetwork: FOUND: %s, %s", *networkRef.NetworkID, *networkRef.Name)

			network, err = si.networkClient.Get(*networkRef.NetworkID)
			if err != nil {
				return nil, fmt.Errorf("Error: si.networkClient.Get(%s) returns %v", *networkRef.NetworkID, err)
			}

			return network, nil
		} else {
			log.Debugf("findNetwork: SKIP: %s, %s", *networkRef.NetworkID, *networkRef.Name)
		}
	}

	return nil, nil
}

func (si *ServiceInstance) addSshKey() error {

	var (
		keyIn *models.SSHKey

		err error
	)

	if si.innerSi == nil {
		return fmt.Errorf("Error: addSshKey called on nil ServiceInstance")
	}
	if si.keyClient == nil {
		return fmt.Errorf("Error: addSshKey called on nil keyClient")
	}

	if si.innerSshKey == nil {
		si.innerSshKey, err = si.findSshKey()
		log.Debugf("addSshKey: innerSshKey = %+v", si.innerSshKey)
		if err != nil {
			return fmt.Errorf("Error: findSshKey returns %v", err)
		}
	}

	if si.innerSshKey == nil {
		keyIn = &models.SSHKey{
			Name:   ptr.To(si.sshKeyName),
			SSHKey: ptr.To(si.options.SshKey),
		}

		si.innerSshKey, err = si.keyClient.Create(keyIn)
		if err != nil {
			return fmt.Errorf("Error: si.keyClient.Create returns %v", err)
		}
		log.Debugf("addSshKey: si.innerSshKey = %+v", si.innerSshKey)
	}

	return nil
}

func (si *ServiceInstance) findSshKey() (*models.SSHKey, error) {

	var (
		keys *models.SSHKeys
		key  *models.SSHKey
		err  error
	)

	if si.innerSi == nil {
		return nil, fmt.Errorf("Error: findSshKey called on nil ServiceInstance")
	}
	if si.keyClient == nil {
		return nil, fmt.Errorf("Error: findSshKey has nil keyClient")
	}

	log.Debugf("findSshKey: si.sshKeyName = %s", si.sshKeyName)

	keys, err = si.keyClient.GetAll()
	if err != nil {
		return nil, fmt.Errorf("Error: si.keyClient.GetAll returns %v", err)
	}

	for _, key = range keys.SSHKeys {
		if strings.Contains(*key.Name, si.sshKeyName) {
			log.Debugf("findSshKey: FOUND: %s", *key.Name)

			key, err = si.keyClient.Get(*key.Name)
			if err != nil {
				return nil, fmt.Errorf("Error: si.keyClient.Get(%s) returns %v", *key.Name, err)
			}

			return key, nil
		} else {
			log.Debugf("findSshKey: SKIP: %s", *key.Name)
		}
	}

	return nil, nil
}

func (si *ServiceInstance) addStockImage(imageName string) error {

	var (
		imageRef    *models.ImageReference
		createImage models.CreateImage
		image       *models.Image
		err         error
	)

	if si.innerSi == nil {
		return fmt.Errorf("Error: addStockImage called on nil ServiceInstance")
	}
	if si.imageClient == nil {
		return fmt.Errorf("Error: addStockImage has nil imageClient")
	}

	// Does it already exist?
	imageRef, err = si.findImage(imageName)
	if err != nil {
		log.Fatalf("Error: addStockImage: findImage returns %v", err)
		return err
	}
	if imageRef != nil {
		si.stockImageId = *imageRef.ImageID
		log.Debugf("addStockImage: imageRef.ImageID = %s", *imageRef.ImageID)
		return nil
	}

	// Find the stock image.
	imageRef, err = si.findStockImage(imageName)
	if err != nil {
		log.Fatalf("Error: addStockImage: findStockImage returns %v", err)
		return err
	}
	if imageRef == nil {
		return fmt.Errorf("Error: findStockImage(%s) returns no image found", imageName)
	}
	log.Debugf("addStockImage: findStockImage: imageRef.ImageID = %s", *imageRef.ImageID)

	// Import it!
	createImage = models.CreateImage{
		ImageID: *imageRef.ImageID,
	}

	image, err = si.imageClient.Create(&createImage)
	if err != nil {
		log.Fatalf("Error: addStockImage: CreateImage returns %v", err)
		return err
	}
	log.Debugf("addStockImage: image = %+v", image)

	si.stockImageId = *image.ImageID
	log.Debugf("addStockImage: si.stockImageId = %s", si.stockImageId)

	return nil
}

func (si *ServiceInstance) addRHCOSImage(importOptions ImageImportOptions) error {

	var (
		imageRef  *models.ImageReference
		importJob *models.CreateCosImageImportJob
		imageJob  *models.JobReference
		err       error
	)

	if si.innerSi == nil {
		return fmt.Errorf("Error: addRHCOSImage called on nil ServiceInstance")
	}
	if si.imageClient == nil {
		return fmt.Errorf("Error: addRHCOSImage has nil imageClient")
	}

	// Does it already exist?
	imageRef, err = si.findImage(importOptions.ImageName)
	if err != nil {
		log.Fatalf("Error: addRHCOSImage: findImage(1) returns %v", err)
		return err
	}
	if imageRef != nil {
		si.rhcosImageId = *imageRef.ImageID
		log.Debugf("addRHCOSImage: FOUND EXISTING %s", *imageRef.ImageID)
		return nil
	}

	// Import it!
	importJob = &models.CreateCosImageImportJob{
		ImageName:     &importOptions.ImageName,
		BucketName:    &importOptions.BucketName,
		BucketAccess:  &importOptions.BucketAccess,
		ImageFilename: &importOptions.BucketImageFileName,
		Region:        &importOptions.BucketRegion,
		StorageType:   importOptions.StorageType,		// Weird it's not a pointer
	}

	imageJob, err = si.imageClient.CreateCosImage(importJob)
	if err != nil {
		log.Fatalf("Error: addRHCOSImage: CreateCosImage returns %v", err)
		return err
	}
	log.Debugf("addRHCOSImage: imageJob = %+v", imageJob)

	err = si.waitForCosImage(imageJob)

	// Should now exist
	imageRef, err = si.findImage(importOptions.ImageName)
	if err != nil {
		log.Fatalf("Error: addRHCOSImage: findImage(2) returns %v", err)
		return err
	}
	if imageRef != nil {
		si.rhcosImageId = *imageRef.ImageID
		log.Debugf("addRHCOSImage: FOUND EXISTING %s", *imageRef.ImageID)
		return nil
	}

	return fmt.Errorf("Error: Should have found RHCOS image by now")
}

func (si *ServiceInstance) waitForCosImage(imageJob *models.JobReference) error {

	var (
		err error
	)

	if si.innerSi == nil {
		return fmt.Errorf("waitForCosImage innerSi is nil")
	}

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(si.ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(si.ctx, backoff, func(context.Context) (bool, error) {
		var (
			job *models.Job

			err2 error
		)

		job, err2 = si.jobClient.Get(*imageJob.ID)
		if err2 != nil {
			log.Fatalf("Error: Wait jobClient.Get: returns = %v", err2)
			return false, err2
		}
		log.Debugf("waitForCosImage: Status.State = %s", *job.Status.State)
		switch *job.Status.State {
		case "completed":
			return true, nil
		case "queued":
			return false, nil
		case "running":
			return false, nil
		case "error":
			return true, fmt.Errorf("waitForCosImage: error state")
		default:
			return true, fmt.Errorf("waitForCosImage: unknown state: %s", *job.Status.State)
		}
	})
	if err != nil {
		log.Fatalf("Error: waitForCosImage: ExponentialBackoffWithContext returns %v", err)
		return err
	}

	return nil
}

func (si *ServiceInstance) findImage(imageName string) (*models.ImageReference, error) {

	var (
		images   *models.Images
		imageRef *models.ImageReference
		err      error
	)

	images, err = si.imageClient.GetAll()
	if err != nil {
		log.Fatalf("Error: findImage: GetAll returns %v", err)
		return nil, err
	}

	for _, imageRef = range images.Images {
		if *imageRef.Name != imageName || *imageRef.State != "active" {
			log.Debugf("findImage: SKIP EXISTING %s %s", *imageRef.Name, *imageRef.State)
			continue
		}

		if *imageRef.Name == imageName && *imageRef.State == "active" {
			log.Debugf("findImage: FOUND EXISTING %s %s", *imageRef.Name, *imageRef.State)
			return imageRef, nil
		}
	}

	return nil, nil
}

func (si *ServiceInstance) findStockImage(imageName string) (*models.ImageReference, error) {

	var (
		images   *models.Images
		imageRef *models.ImageReference
		err      error
	)

	images, err = si.imageClient.GetAllStockImages(false, false)
	if err != nil {
		log.Fatalf("Error: findStockImage: GetAllStockImages returns %v", err)
		return nil, err
	}

	for _, imageRef = range images.Images {
		if *imageRef.Name != imageName || *imageRef.State != "active" {
			log.Debugf("findStockImage: SKIP STOCK %s %s", *imageRef.Name, *imageRef.State)
			continue
		}

		if *imageRef.Name == imageName && *imageRef.State == "active" {
			log.Debugf("findStockImage: FOUND STOCK %s %s %s", *imageRef.Name, *imageRef.State, *imageRef.ImageID)
			return imageRef, nil
		}
	}

	return nil, nil
}

func (si *ServiceInstance) addDhcpServer() error {

	var (
		createOptions *models.DHCPServerCreate
		dhcpServer    *models.DHCPServer
		err           error
	)

	if si.innerSi == nil {
		return fmt.Errorf("Error: addDhcpServer called on nil ServiceInstance")
	}
	if si.dhcpClient == nil {
		return fmt.Errorf("Error: addDhcpServer called on nil dhcpClient")
	}

	if si.dhcpServer == nil {
		si.dhcpServer, err = si.findDhcpServer()
		log.Debugf("addDhcpServer: dhcpServer = %+v", si.dhcpServer)
		if err != nil {
			return fmt.Errorf("Error: findDhcpServer returns %v", err)
		}
	}

	if si.dhcpServer == nil {
		createOptions = &models.DHCPServerCreate{
			Cidr:              &si.options.CIDR,
//			CloudConnectionID: si.innerSi.GUID,
			Name:              &si.dhcpName,
			SnatEnabled:       ptr.To(true),
		}
		log.Debugf("addDhcpServer: createOptions = %+v", createOptions)

		dhcpServer, err = si.dhcpClient.Create(createOptions)
		if err != nil {
			return fmt.Errorf("Error: si.dhcpClient.Create returns %v", err)
		}

		// NOTE: Create returns a *models.DHCPServer but we store a *models.DHCPServerDetail
		log.Debugf("addDhcpServer: dhcpServer = %+v", dhcpServer)

		err = si.waitForDhcpServerCreate(*dhcpServer.ID)
		if err != nil {
			return fmt.Errorf("Error: waitForDhcpServerCreate returns %v", err)
		}

		si.dhcpServer, err = si.dhcpClient.Get(*dhcpServer.ID)
		if err != nil {
			return fmt.Errorf("Error: si.dhcpClient.Get returns %v", err)
		}
		log.Debugf("addDhcpServer: si.dhcpServer = %+v", si.dhcpServer)
	}

	return nil
}

func (si *ServiceInstance) findDhcpServer() (*models.DHCPServerDetail, error) {

	var (
		dhcpServers      models.DHCPServers
		dhcpServer       *models.DHCPServer
		dhcpServerDetail *models.DHCPServerDetail
		err              error
	)

	log.Debugf("findDhcpServer: findDhcpServer si.dhcpName = %s", si.dhcpName)

	dhcpServers, err = si.dhcpClient.GetAll()
	if err != nil {
		return nil, fmt.Errorf("Error: si.dhcpClient.GetAll returns %v", err)
	}

	for _, dhcpServer = range dhcpServers {
		if dhcpServer.ID == nil {
			log.Debugf("findDhcpServer: SKIP nil(ID)")
			continue
		}
		if dhcpServer.Network == nil {
			log.Debugf("findDhcpServer: SKIP %s nil(Network)", *dhcpServer.ID)
			continue
		}
		if strings.Contains(*dhcpServer.Network.Name, si.dhcpName) {
			log.Debugf("findDhcpServer: FOUND %s %s", *dhcpServer.ID, *dhcpServer.Network.Name)

			dhcpServerDetail, err = si.dhcpClient.Get(*dhcpServer.ID)
			if err != nil {
				return nil, fmt.Errorf("Error: si.dhcpClient.Get returns %v", err)
			}

			return dhcpServerDetail, nil
		}
		log.Debugf("findDhcpServer: SKIP %s %s", *dhcpServer.ID, *dhcpServer.Network.Name)
	}

	return nil, nil
}

func (si *ServiceInstance) waitForDhcpServerCreate(id string) error {

	var (
		err error
	)

	if si.innerSi == nil {
		return fmt.Errorf("waitForDhcpServerCreate innerSi is nil")
	}

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(si.ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(si.ctx, backoff, func(context.Context) (bool, error) {
		var (
			detail *models.DHCPServerDetail

			err2 error
		)

		detail, err2 = si.dhcpClient.Get(id)
		if err2 != nil {
			log.Fatalf("Error: Wait dhcpClient.Get: returns = %v", err2)
			return false, err2
		}
		log.Debugf("waitForDhcpServerCreate: Status = %s", *detail.Status)
		switch *detail.Status {
		case "ACTIVE":
			return true, nil
		case "BUILD":
			return false, nil
		default:
			return true, fmt.Errorf("waitForDhcpServerCreate: unknown state: %s", *detail.Status)
		}
	})
	if err != nil {
		log.Fatalf("Error: waitForDhcpServerCreate: ExponentialBackoffWithContext returns %v", err)
		return err
	}

	return nil
}

func (si *ServiceInstance) waitForDhcpServerDelete(id string) error {

	var (
		err error
	)

	if si.innerSi == nil {
		return fmt.Errorf("waitForDhcpServerDelete innerSi is nil")
	}

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(si.ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(si.ctx, backoff, func(context.Context) (bool, error) {
		var (
			detail *models.DHCPServerDetail

			err2 error
		)

		detail, err2 = si.dhcpClient.Get(id)
		if err2 != nil {
			log.Fatalf("Error: Wait dhcpClient.Get: returns = %v", err2)
			return false, err2
		}
		log.Debugf("waitForDhcpServerDelete: Status = %s", *detail.Status)
		switch *detail.Status {
		case "ACTIVE":
			return false, nil
		case "BUILD":
			return false, nil
		default:
			return true, fmt.Errorf("waitForDhcpServerDelete: unknown state: %s", *detail.Status)
		}
	})
	if err != nil {
		log.Fatalf("Error: waitForDhcpServerDelete: ExponentialBackoffWithContext returns %v", err)
		return err
	}

	return nil
}

func (si *ServiceInstance) getDhcpLeases() ([]*models.DHCPServerLeases, error) {

	var (
		dhcpDetail *models.DHCPServerDetail
		err        error
		err2       error
	)

	if si.innerSi == nil {
		return nil, fmt.Errorf("getDhcpLeases innerSi is nil")
	}
	if si.dhcpServer == nil {
		return nil, fmt.Errorf("getDhcpLeases dhcpServer is nil")
	}

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(si.ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(si.ctx, backoff, func(context.Context) (bool, error) {

		dhcpDetail, err2 = si.dhcpClient.Get(*si.dhcpServer.ID)
		if err2 != nil {
			log.Fatalf("Error: Wait dhcpClient.Get: returns = %v", err2)
			return false, err2
		}
		log.Debugf("getDhcpLeases: len(dhcpDetail.Leases) = %d", len(dhcpDetail.Leases))
		if len(dhcpDetail.Leases) > 0 {
			return true, nil
		} else {
			return false, nil
		}
	})
	if err != nil {
		log.Fatalf("Error: getDhcpLeases: ExponentialBackoffWithContext returns %v", err)
		return nil, err
	}

	return dhcpDetail.Leases, nil
}

// # for the password_hash line
// $ podman run -ti --rm quay.io/coreos/mkpasswd --method=yescrypt
// # Generate the ignition file
// $ (FILE1=$(mktemp); FILE2=$(mktemp); trap "/bin/rm -rf ${FILE1} ${FILE2}" EXIT; cat << '___EOF___' > ${FILE1}; podman run --interactive --rm quay.io/coreos/butane:release --pretty --strict < ${FILE1} > ${FILE2}; cat ${FILE2})
// variant: fcos
// version: 1.5.0
// passwd:
// users:
// - name: core
// password_hash: ...
// ssh_authorized_keys:
// - ssh-rsa ...
// ___EOF___
func (si *ServiceInstance) testIgnitionUserData() string {
	return `{
  "ignition": {
    "version": "3.4.0"
  },
  "passwd": {
    "users": [
      {
        "name": "core",
        "passwordHash": "$y$j9T$nh8y1vKCnaxrUGNupnaQQ0$iGsZmNX1g.szjZ4qU.zFOW1i0Kfb8mK9uzcJ2d4PVAB",
        "sshAuthorizedKeys": [
          "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCfrxxUx9MKdEWDStyVVkVTnxPQRHjQU7Gnu+USEbGCq3gb1t4Hs863mkJ3cgH9h4TsXxY7SofDu1MNw3QMt+S2BiUN6RlaQbkhJ41bzdCvy4tg3NiJdiUY0EtiLV5rXR+/wQbEIlkThhXCYEXxOcBA+0GMkAGuyAM2zZekpWh9xmkex1KQy0A8FEgS+gC8d0ok3u1ozZ85hlGxrKT2pxWhS9P2KdAx5Vrt5lsCZyif6HucAjp5EYoZbaJLHmOP3F7f+Rbf+yIxXTCZfcOQN/nf6wz5L4VPCvSjmV4GauVLcbOZCADdRDdE71ky8owHSxoxfjr6ukkU8btecF/JLJeZoaQWGCd6XrkvCjFTS6n2PEckR80UF4j7TGthSmZcI1ach5GROyyb9Oajeciwq6zJeNvDJAcvXLi5fQYbvAOhjTEkqYtlLvcyNCwp8vexPA5G8n381t/3F5kxkrrRYcbQf+N21Mo10CecaO86peV+sIpPPsYCgbE9QVG07okY1XrKkfBrtOoMwn12n1DX/UJbYeiqY3sI+QikbDgL+kDRP4tn4VYLs9uNDaKlBNDrRNwniWO8YKOZQGsonG1JeuU2UMbNfDnR7BzVUkAjMKFfZKA/yfOuIC09BoxmkQ7wDMwb10QNZ7/Y5XDRAKN6o0SFqsBq4FnBQ31+wPd3HBSpGw== hamzy@li-3d08e84c-2e1c-11b2-a85c-e2db7bb078fc.ibm.com"
        ]
      }
    ]
  }
}`
}

func (si *ServiceInstance) testCloudinitUserData() string {
	return `#cloud-config
users:
  - default
  - name: core
    passwd: "$y$j9T$nh8y1vKCnaxrUGNupnaQQ0$iGsZmNX1g.szjZ4qU.zFOW1i0Kfb8mK9uzcJ2d4PVAB"
    shell: /bin/bash
    lock-passwd: false
    ssh_pwauth: True
    chpasswd: { expire: False }
    sudo: ALL=(ALL) NOPASSWD:ALL
    groups: users, admin
    ssh_authorized_keys:
     - ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCfrxxUx9MKdEWDStyVVkVTnxPQRHjQU7Gnu+USEbGCq3gb1t4Hs863mkJ3cgH9h4TsXxY7SofDu1MNw3QMt+S2BiUN6RlaQbkhJ41bzdCvy4tg3NiJdiUY0EtiLV5rXR+/wQbEIlkThhXCYEXxOcBA+0GMkAGuyAM2zZekpWh9xmkex1KQy0A8FEgS+gC8d0ok3u1ozZ85hlGxrKT2pxWhS9P2KdAx5Vrt5lsCZyif6HucAjp5EYoZbaJLHmOP3F7f+Rbf+yIxXTCZfcOQN/nf6wz5L4VPCvSjmV4GauVLcbOZCADdRDdE71ky8owHSxoxfjr6ukkU8btecF/JLJeZoaQWGCd6XrkvCjFTS6n2PEckR80UF4j7TGthSmZcI1ach5GROyyb9Oajeciwq6zJeNvDJAcvXLi5fQYbvAOhjTEkqYtlLvcyNCwp8vexPA5G8n381t/3F5kxkrrRYcbQf+N21Mo10CecaO86peV+sIpPPsYCgbE9QVG07okY1XrKkfBrtOoMwn12n1DX/UJbYeiqY3sI+QikbDgL+kDRP4tn4VYLs9uNDaKlBNDrRNwniWO8YKOZQGsonG1JeuU2UMbNfDnR7BzVUkAjMKFfZKA/yfOuIC09BoxmkQ7wDMwb10QNZ7/Y5XDRAKN6o0SFqsBq4FnBQ31+wPd3HBSpGw== hamzy@li-3d08e84c-2e1c-11b2-a85c-e2db7bb078fc.ibm.com"`
}

func (si *ServiceInstance) findPVMInstance(pvmInstanceName string) (*models.PVMInstance, error) {

	var (
		instances   *models.PVMInstances
		instanceRef *models.PVMInstanceReference
		instance    *models.PVMInstance
		err         error
	)

	instances, err = si.instanceClient.GetAll()
	if err != nil {
		log.Fatalf("Error: findPVMInstance: GetAll returns %v", err)
		return nil, err
	}

	for _, instanceRef = range instances.PvmInstances {
		if pvmInstanceName == *instanceRef.ServerName {
			log.Debugf("findPVMInstance: FOUND %s", *instanceRef.ServerName)

			instance, err = si.instanceClient.Get(*instanceRef.PvmInstanceID)
			if err != nil {
				log.Fatalf("Error: findPVMInstance: GetAll returns %v", err)
				return nil, err
			}

			return instance, nil
		}

		log.Debugf("findPVMInstance: SKIP %s", *instanceRef.ServerName)
	}

	return nil, nil
}

/*
	var (
		networks       []models.PVMInstanceAddNetwork
		createNetworks []*models.PVMInstanceAddNetwork
	)
	networks = make([]models.PVMInstanceAddNetwork, 1)
	networks = append(networks, models.PVMInstanceAddNetwork{
		NetworkID: ptr.To("@TODO"),
	})
	createNetworks = make([]*models.PVMInstanceAddNetwork, 1)
	for _, n := range networks {
		createNetworks = append(createNetworks, &n)
	}
*/
func (si *ServiceInstance) createPVMInstance(createOptions models.PVMInstanceCreate) (*models.PVMInstance, error) {

	var (
		instance     *models.PVMInstance
		instanceList *models.PVMInstanceList
		err          error
	)

	if si.innerSi == nil {
		return nil, fmt.Errorf("Error: createPVMInstance called on nil ServiceInstance")
	}
	if si.instanceClient == nil {
		return nil, fmt.Errorf("Error: createPVMInstance has nil instanceClient")
	}

	log.Debugf("createPVMInstance: createOptions = %+v", createOptions)

	instanceList, err = si.instanceClient.Create(&createOptions)
	if err != nil {
		log.Fatalf("Error: createPVMInstance: Create returns %v", err)
		return nil, err
	}
	log.Debugf("createPVMInstance: instanceList = %+v", instanceList)

	if instanceList == nil {
		log.Fatalf("Error: createPVMInstance: instanceList is nil")
		return nil, fmt.Errorf("Error: createPVMInstance instanceList is nil")
	}

	log.Debugf("createPVMInstance: len(instanceList) = %d", len(*instanceList))
	for _, inst := range *instanceList {
		log.Debugf("createPVMInstance: inst = %+v", inst)

		err = si.waitForPVMInstanceReady(*inst.PvmInstanceID)
		if err != nil {
			log.Fatalf("Error: createPVMInstance: waitForPVMInstanceReady returns %v", err)
			return nil, err
		}

		instance, err = si.instanceClient.Get(*inst.PvmInstanceID)
		if err != nil {
			log.Fatalf("Error: createPVMInstance Get returns %v", err)
			return nil, err
		}
	}

	return instance, nil
}

func (si *ServiceInstance) waitForPVMInstanceReady(pvmInstanceId string) error {

	var (
		instance *models.PVMInstance

		err error
	)

	if si.innerSi == nil {
		return fmt.Errorf("waitForPVMInstanceReady innerSi is nil")
	}

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(si.ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(si.ctx, backoff, func(context.Context) (bool, error) {

		instance, err = si.instanceClient.Get(pvmInstanceId)
		if err != nil {
			if strings.Contains(err.Error(), "unable to get attached volumes") {
				log.Debugf("Error: Wait instanceClient.Get: SKIPPING err = %v", err)
				return false, nil
			}
			log.Fatalf("Error: Wait instanceClient.Get: err = %v", err)
			return false, err
		}
		log.Debugf("waitForPVMInstanceReady: Status = %s", *instance.Status)
		switch *instance.Status {
		case "ACTIVE":
			return true, nil
		case "BUILD":
			return false, nil
		default:
			return true, fmt.Errorf("waitForPVMInstanceReady: unknown state: %s", *instance.Status)
		}
	})
	if err != nil {
		log.Fatalf("Error: ExponentialBackoffWithContext returns %v", err)
		return err
	}

	return nil
}

func (si *ServiceInstance) deleteInstance() error {

	var (
		instance *models.PVMInstance
		err      error
	)

	if si.innerSi == nil {
		return fmt.Errorf("Error: deleteInstance called on nil ServiceInstance")
	}
	if si.instanceClient == nil {
		return fmt.Errorf("Error: deleteInstance called on nil instanceClient")
	}

	instance, err = si.findPVMInstance(si.pvmInstanceName)
	if err != nil {
		log.Fatalf("Error: deleteInstance: findPVMInstance returns %v", err)
		return err
	}
	log.Debugf("deleteInstance: instance = %+v", instance)
	if instance == nil {
		return nil
	}

	err = si.instanceClient.Delete(*instance.PvmInstanceID)
	if err != nil {
		log.Fatalf("Error: deleteInstance: Delete returns %v", err)
		return err
	}

	return nil
}

func (si *ServiceInstance) GetInstanceIP() (string, error) {

	var (
		instance *models.PVMInstance
		network  *models.PVMInstanceNetwork
		err      error
	)

	if si.innerSi == nil {
		return "", fmt.Errorf("Error: GetInstanceIP called on nil ServiceInstance")
	}
	if si.instanceClient == nil {
		return "", fmt.Errorf("Error: GetInstanceIP has nil instanceClient")
	}

	instance, err = si.findPVMInstance(si.pvmInstanceName)
	if err != nil {
		log.Fatalf("Error: GetInstanceIP: findPVMInstance returns %v", err)
		return "", err
	}
	log.Debugf("GetInstanceIP: instance = %+v", instance)
	if instance == nil {
		return "", fmt.Errorf("Error: GetInstanceIP instance is nil")
	}

	for _, network = range instance.Networks {
		log.Debugf("GetInstanceIP: IPAddress = %s", network.IPAddress)

		return network.IPAddress, nil
	}

	return "", fmt.Errorf("Error: GetInstanceIP couldn't find IPAddress")
}

type User struct {
	ID         string
	Email      string
	Account    string
	cloudName  string
	cloudType  string
	generation int
}

func fetchUserDetails(bxSession *bxsession.Session, generation int) (*User, error) {

	var bluemixToken string

	config := bxSession.Config
	user := User{}

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

	log.Debugf("user.ID         = %v", user.ID)
	log.Debugf("user.Email      = %v", user.Email)
	log.Debugf("user.Account    = %v", user.Account)
	log.Debugf("user.cloudType  = %v", user.cloudType)
	log.Debugf("user.generation = %v", user.generation)

	return &user, nil
}

func (si *ServiceInstance) createPiSession() (*ibmpisession.IBMPISession, error) {

	var bxSession *bxsession.Session
	var tokenProviderEndpoint string = "https://iam.cloud.ibm.com"
	var err error

	bxSession, err = bxsession.New(&bluemix.Config{
		BluemixAPIKey:         si.options.ApiKey,
		TokenProviderEndpoint: &tokenProviderEndpoint,
		Debug:                 false,
	})
	if err != nil {
		return nil, fmt.Errorf("Error bxsession.New: %v", err)
	}
	log.Printf("bxSession = %v", bxSession)

	tokenRefresher, err := authentication.NewIAMAuthRepository(bxSession.Config, &rest.Client{
		DefaultHeader: gohttp.Header{
			"User-Agent": []string{http.UserAgent()},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("Error authentication.NewIAMAuthRepository: %v", err)
	}
	log.Printf("tokenRefresher = %v", tokenRefresher)
	err = tokenRefresher.AuthenticateAPIKey(bxSession.Config.BluemixAPIKey)
	if err != nil {
		return nil, fmt.Errorf("Error tokenRefresher.AuthenticateAPIKey: %v", err)
	}

	user, err := fetchUserDetails(bxSession, 2)
	if err != nil {
		return nil, fmt.Errorf("Error fetchUserDetails: %v", err)
	}

	var authenticator = &core.IamAuthenticator{
		ApiKey: si.options.ApiKey,
	}
	var piOptions = &ibmpisession.IBMPIOptions{
		Authenticator: authenticator,
		Debug:         false,
		Region:        si.options.Region,
		URL:           fmt.Sprintf("https://%s.power-iaas.cloud.ibm.com", si.options.Region),
		UserAccount:   user.Account,
		Zone:          si.options.Zone,
	}
	var piSession *ibmpisession.IBMPISession

	piSession, err = ibmpisession.NewIBMPISession(piOptions)
	if err != nil {
		return nil, fmt.Errorf("Error ibmpisession.New: %v", err)
	}
	log.Printf("piSession = %v", piSession)

	return piSession, nil
}
