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
	"strings"
	"time"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/vpc-go-sdk/vpcv1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/ptr"
)

type VPCOptions struct {
	Mode    Mode
	ApiKey  string
	Region  string
	Name    string
	GroupID string
}

type VPC struct {
	options VPCOptions

	// type VpcV1 struct
	vpcSvc *vpcv1.VpcV1

	// type VPC struct
	innerVpc *vpcv1.VPC

	ctx context.Context
}

type SubnetOptions struct {
	Name    string
	Zone    string
	GroupID string
	CIDR    string
}

type AddressPrefixOptions struct {
	Zone string
	CIDR string
}

func initVPCService(options VPCOptions) (*vpcv1.VpcV1, error) {

	var (
		authenticator core.Authenticator = &core.IamAuthenticator{
			ApiKey: options.ApiKey,
		}

		// type VpcV1 struct
		vpcSvc *vpcv1.VpcV1

		err error
	)

	// https://raw.githubusercontent.com/IBM/vpc-go-sdk/master/vpcv1/vpc_v1.go
	vpcSvc, err = vpcv1.NewVpcV1(&vpcv1.VpcV1Options{
		Authenticator: authenticator,
		URL:           "https://" + options.Region + ".iaas.cloud.ibm.com/v1",
	})
	log.Debugf("initVPCService: vpc.vpcSvc = %v", vpcSvc)
	if err != nil {
		log.Fatalf("Error: vpcv1.NewVpcV1 returns %v", err)
		return nil, err
	}
	if vpcSvc == nil {
		panic(fmt.Errorf("Error: vpcSvc is empty?"))
	}

	return vpcSvc, nil
}

func NewVPC(vpcOptions VPCOptions) (*VPC, error) {

	var (
		vpcSvc *vpcv1.VpcV1
		ctx    context.Context
		err    error
	)
	log.Debugf("NewVPC: vpcOptions = %+v", vpcOptions)

	vpcSvc, err = initVPCService(vpcOptions)
	log.Debugf("NewVPC: vpcSvc = %v", vpcSvc)
	if err != nil {
		log.Fatalf("Error: NewVPC: initVPCService returns %v", err)
		return nil, err
	}

	ctx = context.Background()
	log.Debugf("NewVPC: ctx = %v", ctx)

	return &VPC{
		options:  vpcOptions,
		vpcSvc:   vpcSvc,
		innerVpc: nil,
		ctx:      ctx,
	}, nil
}

func (vpc *VPC) Run() error {

	var (
		foundVpc *vpcv1.VPC

		err error
	)

	// Does it already exist?
	if vpc.innerVpc == nil {
		foundVpc, err = vpc.findVPC()
		if err != nil {
			log.Fatalf("Error: findVPC returns %v", err)
			return err
		} else {
			log.Debugf("Run: foundVpc = %v", foundVpc)
			vpc.innerVpc = foundVpc
		}
	}

	switch vpc.options.Mode {
	case ModeCreate:
		err = vpc.createVPC()
	case ModeDelete:
		err = vpc.deleteVPC()
	default:
		return fmt.Errorf("VPC options must be either Create or Delete (%d)", vpc.options.Mode)
	}

	return err
}

func (vpc *VPC) CRN() (string, error) {

	if vpc.innerVpc == nil {
		return "", fmt.Errorf("VPC does not exist to have a CRN")
	}

	return *vpc.innerVpc.CRN, nil
}

func (vpc *VPC) createVPC() error {

	var (
		// type CreateVPCOptions struct
		options *vpcv1.CreateVPCOptions

		resourceGroupIdent vpcv1.ResourceGroupIdentity

		response *core.DetailedResponse

		err error
	)

	if vpc.innerVpc == nil {
		// https://raw.githubusercontent.com/IBM/vpc-go-sdk/master/vpcv1/vpc_v1.go
		options = vpc.vpcSvc.NewCreateVPCOptions()
		// options.SetClassicAccess()
		// options.SetDns()
		options.SetAddressPrefixManagement("manual")
		options.SetName(vpc.options.Name)
		resourceGroupIdent.ID = ptr.To(vpc.options.GroupID)
		options.SetResourceGroup(&resourceGroupIdent)

		log.Debug("createVPC")
		log.Debugf("options = %+v", options)

		vpc.innerVpc, response, err = vpc.vpcSvc.CreateVPCWithContext(vpc.ctx, options)
		if err != nil {
			log.Fatalf("Error: CreateVPCWithContext: response = %v, err = %v", response, err)
			return err
		}
	}

	return nil
}

func (vpc *VPC) addAddressPrefixVPC(addressPrefixOptions AddressPrefixOptions) error {

	var (
		// type ZoneIdentity
		zoneIdent vpcv1.ZoneIdentity

		// type ListVPCAddressPrefixesOptions
		listOptions *vpcv1.ListVPCAddressPrefixesOptions

		// type VPCAddressPrefixesPager
		pager *vpcv1.VPCAddressPrefixesPager

		// type AddressPrefix
		nextPage []vpcv1.AddressPrefix

		// type AddressPrefix
		page vpcv1.AddressPrefix

		found = false

		// type CreateVPCAddressPrefixOptions
		createOptions *vpcv1.CreateVPCAddressPrefixOptions

		response *core.DetailedResponse

		err error
	)

	log.Debugf("addAddressPrefixVPC: addressPrefixOptions = %+v", addressPrefixOptions)

	if vpc.innerVpc == nil {
		return fmt.Errorf("addAddressPrefixVPC called on nil vpc")
	}

	listOptions = vpc.vpcSvc.NewListVPCAddressPrefixesOptions(*vpc.innerVpc.ID)

	pager, err = vpc.vpcSvc.NewVPCAddressPrefixesPager(listOptions)
	if err != nil {
		log.Fatalf("Error: addAddressPrefixVPC: NewVPCAddressPrefixesPager returns %v", err)
		return err
	}

	for pager.HasNext() {
		nextPage, err = pager.GetNextWithContext(vpc.ctx)
		if err != nil {
			log.Fatalf("Error: addAddressPrefixVPC: GetNextWithContext returns %v", err)
			return err
		}

		for _, page = range nextPage {
			if strings.Contains(*page.CIDR, addressPrefixOptions.CIDR) {
				log.Debugf("addAddressPrefixVPC: FOUND ID = %s, CIDR = %s", *page.ID, *page.CIDR)
				found = true
			} else {
				log.Debugf("addAddressPrefixVPC: SKIP ID = %s, CIDR = %s", *page.ID, *page.CIDR)
			}
		}
	}

	if !found {
		zoneIdent.Name = &addressPrefixOptions.Zone

		createOptions = vpc.vpcSvc.NewCreateVPCAddressPrefixOptions(*vpc.innerVpc.ID, addressPrefixOptions.CIDR, &zoneIdent)

		_, response, err = vpc.vpcSvc.CreateVPCAddressPrefix(createOptions)
		if err != nil {
			log.Fatalf("Error: addAddressPrefixVPC: CreateVPCAddressPrefix: response = %v, err = %v", response, err)
			return err
		}
	}

	return nil
}

func (vpc *VPC) addSubnet(createSubnetOptions SubnetOptions) error {

	var (
		// type Subnet
		subnet *vpcv1.Subnet

		createOptions *vpcv1.CreateSubnetOptions

		// type VPCIdentityByID
		vpcIdent vpcv1.VPCIdentityByID

		// type ZoneIdentity
		zoneIdent vpcv1.ZoneIdentity

		resourceGroupIdent vpcv1.ResourceGroupIdentity

		subnetOptions vpcv1.SubnetPrototypeSubnetByCIDR

		response *core.DetailedResponse

		err error
	)

	log.Debugf("addSubnet: createSubnetOptions = %+v", createSubnetOptions)

	if vpc.innerVpc == nil {
		return fmt.Errorf("addSubnet called on nil vpc")
	}

	log.Debugf("addSubnet: name = %s", createSubnetOptions.Name)

	subnet, err = vpc.findSubnet(createSubnetOptions.Name)
	if err != nil {
		log.Fatalf("Error: findSubet returns %v", err)
		return err
	}
	if subnet != nil {
		return nil
	}

	vpcIdent.ID = vpc.innerVpc.ID
	log.Debugf("addSubnet: vpcIdent.ID = %s", *vpcIdent.ID)

	zoneIdent.Name = &createSubnetOptions.Zone

	subnetOptions.Name = &createSubnetOptions.Name
	resourceGroupIdent.ID = ptr.To(vpc.options.GroupID)
	subnetOptions.ResourceGroup = &resourceGroupIdent
	subnetOptions.VPC = &vpcIdent
	subnetOptions.Zone = &zoneIdent
	subnetOptions.Ipv4CIDRBlock = &createSubnetOptions.CIDR
	log.Debugf("addSubnet: subnetOptions = {Name: %s, ResourceGroup: %s, VPC: %s, Zone: %s, CIDR: %s}",
		createSubnetOptions.Name,
		vpc.options.GroupID,
		*vpc.innerVpc.ID,
		createSubnetOptions.Zone,
		createSubnetOptions.CIDR,
	)

	createOptions = vpc.vpcSvc.NewCreateSubnetOptions(&subnetOptions)

	subnet, response, err = vpc.vpcSvc.CreateSubnetWithContext(vpc.ctx, createOptions)
	if err != nil {
		log.Fatalf("Error: addSubnet: CreateSubnetWithContext: response = %v, err = %v", response, err)
		return err
	}

	log.Debugf("addSubnet: subnet = %+v", subnet)

	return nil
}

func (vpc *VPC) addPublicGateway(zone string) error {

	var (
		name string

		vpcIdent vpcv1.VPCIdentity

		zoneIdent vpcv1.ZoneIdentity

		resourceGroupIdent vpcv1.ResourceGroupIdentity

		createOptions *vpcv1.CreatePublicGatewayOptions

		response *core.DetailedResponse

		pg *vpcv1.PublicGateway

		err error
	)

	log.Debugf("addPublicGateway: zone = %s", zone)

	if vpc.innerVpc == nil {
		return fmt.Errorf("addPublicGateway called on nil vpc")
	}

	name = fmt.Sprintf("%s-%s-pg", vpc.options.Name, zone)
	log.Debugf("addPublicGateway: name = %s", name)

	pg, err = vpc.findPublicGateway(name)
	if err != nil {
		log.Fatalf("Error: findPublicGateway returns %v", err)
		return err
	}
	if pg != nil {
		return nil
	}

	zoneIdent.Name = ptr.To(zone)
	vpcIdent.ID = vpc.innerVpc.ID
	resourceGroupIdent.ID = ptr.To(vpc.options.GroupID)

	createOptions = vpc.vpcSvc.NewCreatePublicGatewayOptions(&vpcIdent, &zoneIdent)
	createOptions.SetName(name)
	createOptions.SetResourceGroup(&resourceGroupIdent)

	pg, response, err = vpc.vpcSvc.CreatePublicGatewayWithContext(vpc.ctx, createOptions)
	if err != nil {
		log.Fatalf("Error: addPublicGateway: CreatePublicGatewayWithContext: response = %v, err = %v", response, err)
		return err
	}

	log.Debugf("addPublicGateway: pg = %+v", pg)

	return err
}

func (vpc *VPC) setSubnetPublicGateway(zone string) error {

	var (
		subnetName string

		publicGatewayName string

		pg *vpcv1.PublicGateway

		subnet *vpcv1.Subnet

		pgIdent vpcv1.PublicGatewayIdentity

		setOptions *vpcv1.SetSubnetPublicGatewayOptions

		response *core.DetailedResponse

		err error
	)

	log.Debugf("setSubnetPublicGateway: zone = %s", zone)

	if vpc.innerVpc == nil {
		return fmt.Errorf("setSubnetPublicGateway innerVpc is nil")
	}

	subnetName = fmt.Sprintf("%s-%s-subnet", vpc.options.Name, zone)
	log.Debugf("setSubnetPublicGateway: subnetName = %s", subnetName)

	publicGatewayName = fmt.Sprintf("%s-%s-pg", vpc.options.Name, zone)
	log.Debugf("setSubnetPublicGateway: publicGatewayName = %s", publicGatewayName)

	subnet, err = vpc.findSubnet(subnetName)
	if err != nil {
		log.Fatalf("Error: findSubnet returns %v", err)
		return err
	}
	if subnet != nil {
		log.Fatalf("Error: findSubnet returns nil Subnet")
		return nil
	}

	pg, err = vpc.findPublicGateway(publicGatewayName)
	if err != nil {
		log.Fatalf("Error: findPublicGateway returns %v", err)
		return err
	}
	if pg == nil {
		log.Fatalf("Error: findPublicGateway returns nil PublicGateway")
		return err
	}

	pgIdent.ID = pg.ID

	setOptions = vpc.vpcSvc.NewSetSubnetPublicGatewayOptions(*subnet.ID, &pgIdent)

	pg, response, err = vpc.vpcSvc.SetSubnetPublicGatewayWithContext(vpc.ctx, setOptions)
	if err != nil {
		log.Fatalf("Error: setSubnetPublicGateway: SetSubnetPublicGatewayWithContext: response = %v, err = %v", response, err)
		return err
	}

	log.Debugf("setSubnetPublicGateway: pg = %v", pg)

	return nil
}

func (vpc *VPC) findSubnet(name string) (*vpcv1.Subnet, error) {

	var (
		listOptions *vpcv1.ListSubnetsOptions

		perPage int64 = 64

		moreData = true

		subnets *vpcv1.SubnetCollection

		response *core.DetailedResponse

		err error
	)

	if vpc.innerVpc == nil {
		return nil, fmt.Errorf("findSubnet innerVpc is nil")
	}

	listOptions = vpc.vpcSvc.NewListSubnetsOptions()
	listOptions.SetLimit(perPage)
	listOptions.SetResourceGroupID(vpc.options.GroupID)

	for moreData {
		subnets, response, err = vpc.vpcSvc.ListSubnetsWithContext(vpc.ctx, listOptions)
		if err != nil {
			log.Fatalf("Error: findSubnet: ListSubnets: response = %v, err = %v", response, err)
			return nil, err
		}

		for _, subnet := range subnets.Subnets {

			if strings.Contains(*subnet.Name, name) {
				log.Debugf("findSubnet: FOUND Name = %s, Ipv4CIDRBlock = %s", *subnet.Name, *subnet.Ipv4CIDRBlock)

				return &subnet, nil
			} else {
				log.Debugf("findSubnet: SKIP Name = %s, Ipv4CIDRBlock = %s", *subnet.Name, *subnet.Ipv4CIDRBlock)
			}
		}

		if subnets.Next != nil {
			log.Debugf("findSubnet: Next = %+v", *subnets.Next)
			start, err := subnets.GetNextStart()
			if err != nil {
				log.Fatalf("Error: findSubnet: GetNextStart returns %v", err)
				return nil, err
			}
			log.Debugf("findSubnet: start = %+v", *start)
			listOptions.SetStart(*start)
		} else {
			log.Debugf("findSubnet: Next = nil")
			moreData = false
		}
	}

	return nil, nil
}

func (vpc *VPC) deleteSubnets() error {

	var (
		listOptions *vpcv1.ListSubnetsOptions

		perPage int64 = 64

		moreData = true

		subnets *vpcv1.SubnetCollection

		deleteSubnetOptions *vpcv1.DeleteSubnetOptions

		response *core.DetailedResponse

		err error
	)

	if vpc.innerVpc == nil {
		return fmt.Errorf("deleteSubnets innerVpc is nil")
	}

	listOptions = vpc.vpcSvc.NewListSubnetsOptions()
	listOptions.SetLimit(perPage)
	listOptions.SetResourceGroupID(vpc.options.GroupID)

	for moreData {
		subnets, response, err = vpc.vpcSvc.ListSubnetsWithContext(vpc.ctx, listOptions)
		if err != nil {
			log.Fatalf("Error: deleteSubnets: ListSubnets: response = %v, err = %v", response, err)
			return err
		}

		for _, subnet := range subnets.Subnets {
			if strings.Contains(*subnet.Name, vpc.options.Name) {
				log.Debugf("deleteSubnets: FOUND Name = %s", *subnet.Name)

				deleteSubnetOptions = vpc.vpcSvc.NewDeleteSubnetOptions(*subnet.ID)

				response, err = vpc.vpcSvc.DeleteSubnetWithContext(vpc.ctx, deleteSubnetOptions)
				if err != nil {
					log.Fatalf("Error: DeleteSubnetWithContext: response = %v, err = %v", response, err)
					return err
				}

				err = vpc.waitForSubnetDeleted(*subnet.ID)
				if err != nil {
					log.Fatalf("Error: waitForSubnetDeleted: err = %v", err)
					return err
				}
			} else {
				log.Debugf("deleteSubnets: SKIP Name = %s", *subnet.Name)
			}
		}

		if subnets.Next != nil {
			log.Debugf("deleteSubnets: Next = %+v", *subnets.Next)
			start, err := subnets.GetNextStart()
			if err != nil {
				log.Fatalf("Error: deleteSubnets: GetNextStart returns %v", err)
				return err
			}
			log.Debugf("deleteSubnets: start = %+v", *start)
			listOptions.SetStart(*start)
		} else {
			log.Debugf("deleteSubnets: Next = nil")
			moreData = false
		}
	}

	return nil
}

func (vpc *VPC) findVPC() (*vpcv1.VPC, error) {

	var (
		// type ListVpcsOptions
		options *vpcv1.ListVpcsOptions

		perPage int64 = 64

		moreData = true

		// type VPCCollection
		vpcs *vpcv1.VPCCollection

		response *core.DetailedResponse

		err error
	)

	log.Debugf("findVPC: name = %s", vpc.options.Name)

	options = vpc.vpcSvc.NewListVpcsOptions()
	options.SetLimit(perPage)

	for moreData {
		vpcs, response, err = vpc.vpcSvc.ListVpcsWithContext(vpc.ctx, options)
		if err != nil {
			log.Fatalf("Error: findVPC: ListVpcs: response = %v, err = %v", response, err)
			return nil, err
		}

		for _, currentVpc := range vpcs.Vpcs {
			if strings.Contains(*currentVpc.Name, vpc.options.Name) {
				var (
					getOptions *vpcv1.GetVPCOptions

					response *core.DetailedResponse

					foundVpc *vpcv1.VPC
				)

				getOptions = vpc.vpcSvc.NewGetVPCOptions(*currentVpc.ID)

				foundVpc, response, err = vpc.vpcSvc.GetVPCWithContext(vpc.ctx, getOptions)
				if err != nil {
					log.Fatalf("Error: GetVPCWithContext: response = %v, err = %v", response, err)
					return nil, err
				}

				log.Debugf("findVPC: FOUND ID = %s, Name = %s", *currentVpc.ID, *currentVpc.Name)

				return foundVpc, nil
			} else {
				log.Debugf("findVPC: SKIP ID = %s, Name = %s", *currentVpc.ID, *currentVpc.Name)
			}
		}

		if vpcs.Next != nil {
			log.Debugf("findVPC: Next = %+v", *vpcs.Next)
			start, err := vpcs.GetNextStart()
			if err != nil {
				log.Fatalf("Error: findVPC: GetNextStart returns %v", err)
				return nil, err
			}
			log.Debugf("findVPC: start = %+v", *start)
			options.SetStart(*start)
		} else {
			log.Debugf("findVPC: Next = nil")
			moreData = false
		}
	}

	return nil, nil
}

func (vpc *VPC) findPublicGateway(name string) (*vpcv1.PublicGateway, error) {

	var (
		listOptions *vpcv1.ListPublicGatewaysOptions

		perPage int64 = 64

		moreData = true

		gateways *vpcv1.PublicGatewayCollection

		response *core.DetailedResponse

		err error
	)

	log.Debugf("findPublicGateway: name = %s", name)

	if vpc.innerVpc == nil {
		return nil, fmt.Errorf("findPublicGateway innerVpc is nil")
	}

	listOptions = vpc.vpcSvc.NewListPublicGatewaysOptions()
	listOptions.SetLimit(perPage)
	listOptions.SetResourceGroupID(vpc.options.GroupID)

	for moreData {
		gateways, response, err = vpc.vpcSvc.ListPublicGatewaysWithContext(vpc.ctx, listOptions)
		if err != nil {
			log.Fatalf("Error: findPublicGateway: ListPublicGatewaysWithContext: response = %v, err = %v", response, err)
			return nil, err
		}

		for _, publicGateway := range gateways.PublicGateways {

			if strings.Contains(*publicGateway.Name, name) {
				log.Debugf("findPublicGateway: FOUND Name = %s, FloatingIP = %s", *publicGateway.Name, *publicGateway.FloatingIP.Address)

				return &publicGateway, nil
			} else {
				log.Debugf("findPublicGateway: SKIP Name = %s, FloatingIP = %s", *publicGateway.Name, *publicGateway.FloatingIP.Address)
			}
		}

		if gateways.Next != nil {
			log.Debugf("findPublicGateway: Next = %+v", *gateways.Next)
			start, err := gateways.GetNextStart()
			if err != nil {
				log.Fatalf("Error: findPublicGateway: GetNextStart returns %v", err)
				return nil, err
			}
			log.Debugf("findPublicGateway: start = %+v", *start)
			listOptions.SetStart(*start)
		} else {
			log.Debugf("findPublicGateway: Next = nil")
			moreData = false
		}
	}

	return nil, nil
}

func (vpc *VPC) deletePublicGateways() error {

	var (
		listOptions *vpcv1.ListPublicGatewaysOptions

		perPage int64 = 64

		moreData = true

		gateways *vpcv1.PublicGatewayCollection

		response *core.DetailedResponse

		deletePublicGatewayOptions *vpcv1.DeletePublicGatewayOptions

		err error
	)

	if vpc.innerVpc == nil {
		return fmt.Errorf("deletePublicGateways innerVpc is nil")
	}

	listOptions = vpc.vpcSvc.NewListPublicGatewaysOptions()
	listOptions.SetLimit(perPage)
	listOptions.SetResourceGroupID(vpc.options.GroupID)

	for moreData {
		gateways, response, err = vpc.vpcSvc.ListPublicGatewaysWithContext(vpc.ctx, listOptions)
		if err != nil {
			log.Fatalf("Error: deletePublicGateways: ListPublicGatewaysWithContext: response = %v, err = %v", response, err)
			return err
		}

		for _, publicGateway := range gateways.PublicGateways {

			if strings.Contains(*publicGateway.Name, vpc.options.Name) {
				log.Debugf("deletePublicGateways: FOUND Name = %s", *publicGateway.Name)

				deletePublicGatewayOptions = vpc.vpcSvc.NewDeletePublicGatewayOptions(*publicGateway.ID)

				response, err = vpc.vpcSvc.DeletePublicGatewayWithContext(vpc.ctx, deletePublicGatewayOptions)
				if err != nil {
					log.Fatalf("Error: deletePublicGateways: DeletePublicGatewayWithContext: response = %v, err = %v", response, err)
					return err
				}
			} else {
				log.Debugf("deletePublicGateways: SKIP Name = %s", *publicGateway.Name)
			}
		}

		if gateways.Next != nil {
			log.Debugf("deletePublicGateways: Next = %+v", *gateways.Next)
			start, err := gateways.GetNextStart()
			if err != nil {
				log.Fatalf("Error: deletePublicGateways: GetNextStart returns %v", err)
				return err
			}
			log.Debugf("deletePublicGateways: start = %+v", *start)
			listOptions.SetStart(*start)
		} else {
			log.Debugf("deletePublicGateways: Next = nil")
			moreData = false
		}
	}

	return nil
}

func (vpc *VPC) waitForSubnetDeleted(id string) error {

	var (
		getOptions *vpcv1.GetSubnetOptions

		foundSubnet *vpcv1.Subnet

		response *core.DetailedResponse

		err error
	)

	if vpc.innerVpc == nil {
		return fmt.Errorf("waitForSubnetDeleted innerVpc is nil")
	}

	getOptions = vpc.vpcSvc.NewGetSubnetOptions(id)

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(vpc.ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(vpc.ctx, backoff, func(context.Context) (bool, error) {
		var err2 error

		foundSubnet, response, err2 = vpc.vpcSvc.GetSubnetWithContext(vpc.ctx, getOptions)
		if err != nil {
			log.Fatalf("Error: Wait GetSubnetWithContext: response = %v, err = %v", response, err2)
			return false, err2
		}
		log.Debugf("waitForSubnetDeleted: Status = %s", *foundSubnet.Status)
		switch *foundSubnet.Status {
		case vpcv1.SubnetStatusAvailableConst:
			return true, nil
		case vpcv1.SubnetStatusDeletingConst:
			return false, nil
		case vpcv1.SubnetStatusFailedConst:
			return true, fmt.Errorf("waitForSubnetDeleted: failed status")
		case vpcv1.SubnetStatusPendingConst:
			return true, fmt.Errorf("waitForSubnetDeleted: pending status")
		default:
			return true, fmt.Errorf("waitForSubnetDeleted: unknown status: %s", *foundSubnet.Status)
		}
	})
	if err != nil {
		log.Fatalf("Error: ExponentialBackoffWithContext returns %v", err)
		return err
	}

	return nil
}

func (vpc *VPC) createInstance() error {

	var (
		// InstancePrototype : InstancePrototype struct
		// Models which "extend" this model:
		// - InstancePrototypeInstanceByImage
		// - InstancePrototypeInstanceByCatalogOffering
		// - InstancePrototypeInstanceByVolume
		// - InstancePrototypeInstanceBySourceSnapshot
		// - InstancePrototypeInstanceBySourceTemplate
		instancePrototype vpcv1.InstancePrototype
		createOptions     *vpcv1.CreateInstanceOptions
		instance          *vpcv1.Instance
		response          *core.DetailedResponse
		err               error
	)

	createOptions = vpc.vpcSvc.NewCreateInstanceOptions(&instancePrototype)

	instance, response, err = vpc.vpcSvc.CreateInstanceWithContext(vpc.ctx, createOptions)
	if err != nil {
		log.Fatalf("Error: createInstance: CreateInstanceWithContext: response = %v, err = %v", response, err)
	}
	log.Debugf("createInstance: instance = %+v", instance)

	return nil
}

func (vpc *VPC) deleteVPC() error {

	var (
		// type DeleteVPCOptions
		options *vpcv1.DeleteVPCOptions

		response *core.DetailedResponse

		err error
	)

	if vpc.innerVpc != nil {
		err = vpc.deletePublicGateways()
		if err != nil {
			log.Fatalf("Error: deleteVPC: deletePublicGateways returns %v", err)
			return err
		}

		err = vpc.deleteSubnets()
		if err != nil {
			log.Fatalf("Error: deleteVPC: deleteSubnets returns %v", err)
			return err
		}

		options = vpc.vpcSvc.NewDeleteVPCOptions(*vpc.innerVpc.ID)

		response, err = vpc.vpcSvc.DeleteVPCWithContext(vpc.ctx, options)
		if err != nil {
			log.Fatalf("Error: deleteVPC: DeleteVPC: response = %v, err = %v", response, err)
			return err
		}
	}

	return nil
}