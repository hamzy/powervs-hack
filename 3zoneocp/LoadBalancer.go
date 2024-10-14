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
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/vpc-go-sdk/vpcv1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/ptr"
)

type LoadBalancerOptions struct {
	Mode     Mode
	ApiKey   string
	Region   string
	Name     string
	GroupID  string
	IsPublic bool
	Subnets  []vpcv1.SubnetIdentityIntf
}

type LoadBalancer struct {
	options LoadBalancerOptions

	// type VpcV1 struct
	vpcSvc *vpcv1.VpcV1

	ctx context.Context

	lbName string

	innerLb *vpcv1.LoadBalancer
}

func initLBVPCService(options LoadBalancerOptions) (*vpcv1.VpcV1, error) {

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
	log.Debugf("initLBVPCService: vpcSvc = %v", vpcSvc)
	if err != nil {
		log.Fatalf("Error: vpcv1.NewVpcV1 returns %v", err)
		return nil, err
	}
	if vpcSvc == nil {
		panic(fmt.Errorf("Error: vpcSvc is empty?"))
	}

	return vpcSvc, nil
}

func NewLoadBalancer(lbOptions LoadBalancerOptions) (*LoadBalancer, error) {

	var (
		lbName string
		vpcSvc *vpcv1.VpcV1
		ctx    context.Context
		err    error
	)

	log.Debugf("NewLoadBalancer: lbOptions = %+v", lbOptions)

	if lbOptions.IsPublic {
		lbName = fmt.Sprintf("%s-loadbalancer", lbOptions.Name)
	} else {
		lbName = fmt.Sprintf("%s-loadbalancer-int", lbOptions.Name)
	}

	vpcSvc, err = initLBVPCService(lbOptions)
	log.Debugf("NewLoadBalancer: vpcSvc = %+v", vpcSvc)
	if err != nil {
		log.Fatalf("Error: NewLoadBalancer: initLBVPCService returns %v", err)
		return nil, err
	}

	ctx = context.Background()
	log.Debugf("NewLoadBalancer: ctx = %v", ctx)

	return &LoadBalancer{
		options: lbOptions,
		vpcSvc:  vpcSvc,
		ctx:     ctx,
		lbName:  lbName,
		innerLb: nil,
	}, nil
}

func (lb *LoadBalancer) Run() error {

	var (
		foundLb *vpcv1.LoadBalancer
		err     error
	)

	// Does it already exist?
	if lb.innerLb == nil {
		foundLb, err = lb.findLoadBalancer()
		if err != nil {
			log.Fatalf("Error: findLoadBalancer returns %v", err)
			return err
		} else {
			log.Debugf("Run: foundLb = %v", foundLb)
			lb.innerLb = foundLb
		}
	}

	switch lb.options.Mode {
	case ModeCreate:
		err = lb.createLoadBalancer()
	case ModeDelete:
		err = lb.deleteLoadBalancer()
	default:
		return fmt.Errorf("LoadBalancer options must be either Create or Delete (%d)", lb.options.Mode)
	}

	return err
}

func (lb *LoadBalancer) CRN() (string, error) {

	if lb.innerLb == nil {
		return "", fmt.Errorf("LoadBalancer does not exist to have a CRN")
	}

	return *lb.innerLb.CRN, nil
}

func (lb *LoadBalancer) Name() (string, error) {

	if lb.innerLb == nil {
		return "", fmt.Errorf("LoadBalancer does not exist to have a Name")
	}

	return *lb.innerLb.Name, nil
}

func (lb *LoadBalancer) Valid() bool {

	if lb.innerLb == nil {
		return false
	}

	return true
}

func (lb *LoadBalancer) IsPublic() (bool, error) {

	if lb.innerLb == nil {
		return false, fmt.Errorf("LoadBalancer does not exist to be public")
	}

	return lb.options.IsPublic, nil
}

func (lb *LoadBalancer) getHostname() (string, error) {

	if lb.innerLb == nil {
		return "", fmt.Errorf("LoadBalancer does not exist to have a hostname")
	}

	return *lb.innerLb.Hostname, nil
}

func (lb *LoadBalancer) findLoadBalancer() (*vpcv1.LoadBalancer, error) {

	var (
		matchExp     *regexp.Regexp
		listOptions  *vpcv1.ListLoadBalancersOptions
		resources    *vpcv1.LoadBalancerCollection
		response     *core.DetailedResponse
		loadbalancer vpcv1.LoadBalancer
		foundLb      *vpcv1.LoadBalancer
		err          error
	)

	log.Debugf("findLoadBalancer: lb.lbName = %s", lb.lbName)
	matchExp = regexp.MustCompile(lb.lbName+"$")

	listOptions = lb.vpcSvc.NewListLoadBalancersOptions()
	log.Debugf("findLoadBalancer: listOptions = %+v", listOptions)

	resources, response, err = lb.vpcSvc.ListLoadBalancersWithContext(lb.ctx, listOptions)
	if err != nil {
		return nil, fmt.Errorf("Error: findLoadBalancer: ListLoadBalancersWithContext failed with %w and response is %v", err, response)
	}

	for _, loadbalancer = range resources.LoadBalancers {
		if matchExp.MatchString(*loadbalancer.Name) {
			log.Debugf("findLoadBalancers: FOUND: %s, %s, %s", *loadbalancer.ID, *loadbalancer.Name, *loadbalancer.ProvisioningStatus)

			foundLb, response, err = lb.vpcSvc.GetLoadBalancer(&vpcv1.GetLoadBalancerOptions{
				ID: loadbalancer.ID,
			})
			if err != nil {
				return nil, fmt.Errorf("Error: findLoadBalancer: GetLoadBalancer failed with %w and response is %v", err, response)
			}

			return foundLb, nil
		}

		log.Debugf("findLoadBalancers: SKIP: %s, %s, %s", *loadbalancer.ID, *loadbalancer.Name, *loadbalancer.ProvisioningStatus)
	}

	return nil, nil
}

func (lb *LoadBalancer) createLoadBalancer() error {

	var (
		createOptions *vpcv1.CreateLoadBalancerOptions
		response      *core.DetailedResponse
		getOptions    *vpcv1.GetLoadBalancerOptions
		updatedLb     *vpcv1.LoadBalancer
		err           error
	)

	if lb.innerLb == nil {
		createOptions = lb.vpcSvc.NewCreateLoadBalancerOptions(lb.options.IsPublic, lb.options.Subnets)
		createOptions.SetName(lb.lbName)
		createOptions.SetResourceGroup(&vpcv1.ResourceGroupIdentityByID{
			ID: &lb.options.GroupID,
		})

		log.Debugf("createLoadBalancer: createOptions = %+v", *createOptions)

		lb.innerLb, response, err = lb.vpcSvc.CreateLoadBalancerWithContext(lb.ctx, createOptions)
		if err != nil {
			log.Fatalf("Error: CreateLoadBalancerWithContext response = %v, err = %v", response, err)
			return err
		}
		log.Debugf("createLoadBalancer: lb.innerLb = %+v", lb.innerLb)

		err = lb.waitForLoadBalancer(*lb.innerLb.ID)
		if err != nil {
			log.Fatalf("Error: waitForLoadBalancer returns %v", err)
			return err
		}

		getOptions = lb.vpcSvc.NewGetLoadBalancerOptions(*lb.innerLb.ID)

		updatedLb, response, err = lb.vpcSvc.GetLoadBalancer(getOptions)
		if err != nil {
			log.Fatalf("Error: GetLoadBalancer returns %v", err)
			return err
		}
		log.Debugf("createLoadBalancer: updatedLb.Listeners = %+v", updatedLb.Listeners)
		log.Debugf("createLoadBalancer: updatedLb.Pools     = %+v", updatedLb.Pools)
		log.Debugf("createLoadBalancer: len(updatedLb.Listeners) = %d", len(updatedLb.Listeners))
		log.Debugf("createLoadBalancer: len(updatedLb.Pools)     = %d", len(updatedLb.Pools))
	}
	if lb.innerLb == nil {
		return fmt.Errorf("Error: createLoadBalancer has a nil LoadBalancer!")
	}

	return err
}

func (lb *LoadBalancer) waitForLoadBalancer(lbId string) error {

	var (
		getOptions *vpcv1.GetLoadBalancerOptions

		foundLb *vpcv1.LoadBalancer

		response *core.DetailedResponse

		err error
	)

	getOptions = lb.vpcSvc.NewGetLoadBalancerOptions(lbId)

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(lb.ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(lb.ctx, backoff, func(context.Context) (bool, error) {
		var err2 error

		foundLb, response, err2 = lb.vpcSvc.GetLoadBalancer(getOptions)
		if err2 != nil {
			if strings.Contains(err2.Error(), fmt.Sprintf("The load balancer with ID '%s' cannot be found.", lbId)) {
				return true, nil
			}
			log.Fatalf("Error: Wait GetLoadBalancer: response = %v, err = %v", response, err2)
			return false, err2
		}
		if foundLb == nil {
			log.Debugf("waitForLoadBalancer: foundLb is nil")
			return true, nil
		}
		log.Debugf("waitForLoadBalancer: Status = %s", *foundLb.ProvisioningStatus)
		switch *foundLb.ProvisioningStatus {
		case "active":
			return true, nil
		case "create_pending":
			return false, nil
		case "delete_pending":
			return false, nil
		case "maintenance_pending":
			return false, nil
		case "migrate_pending":
			return false, nil
		case "update_pending":
			return false, nil
		default:
			return true, fmt.Errorf("waitForLoadBalancer: unknown status: %s", *foundLb.ProvisioningStatus)
		}
	})
	if err != nil {
		log.Fatalf("Error: ExponentialBackoffWithContext returns %v", err)
		return err
	}

	return nil
}

func (lb *LoadBalancer) AddLoadBalancerPoolMember(name string, port int64, address string) error {

	var (
		err error
	)

	log.Debugf("AddLoadBalancerPoolMember: name = %s, port = %d, address = %s", name, port, address)

	err = lb.AddLoadBalancerPool(name, port, address)
	if err != nil {
		return err
	}

	err = lb.AddLoadBalancerListener(name, port, address)

	return err
}

func (lb *LoadBalancer) AddLoadBalancerPool(name string, port int64, address string) error {

	var (
		getOptions       *vpcv1.GetLoadBalancerOptions
		currentLb        *vpcv1.LoadBalancer
		createLBPOptions *vpcv1.CreateLoadBalancerPoolOptions
		lbp              *vpcv1.LoadBalancerPool
		lbpr             vpcv1.LoadBalancerPoolReference
		lbpID            string
		lbpmc            *vpcv1.LoadBalancerPoolMemberCollection
		lbpm             *vpcv1.LoadBalancerPoolMember
		response         *core.DetailedResponse
		err              error
	)

	if lb.innerLb == nil {
		return fmt.Errorf("Error: AddLoadBalancerPool has a nil LoadBalancer!")
	}

	getOptions = lb.vpcSvc.NewGetLoadBalancerOptions(*lb.innerLb.ID)
	currentLb, response, err = lb.vpcSvc.GetLoadBalancer(getOptions)
	if err != nil {
		log.Fatalf("Error: GetLoadBalancer returns %v", err)
		return err
	}

	log.Debugf("AddLoadBalancerPool: Searching for name = %s", name)
	for _, lbpr = range currentLb.Pools {
		log.Debugf("AddLoadBalancerPool: lbpr.Name = %s", *lbpr.Name)
		log.Debugf("AddLoadBalancerPool: lbpr.ID   = %s", *lbpr.ID)
		if *lbpr.Name == name {
			lbpID = *lbpr.ID
			break
		}
	}
	log.Debugf("AddLoadBalancerPool: lbpID = %s", lbpID)

	if lbpID == ""{
		// Create a pool first!
		log.Debugf("AddLoadBalancerPool: Creating a pool...")

		createLBPOptions = lb.vpcSvc.NewCreateLoadBalancerPoolOptions(
			*lb.innerLb.ID,
			vpcv1.CreateLoadBalancerPoolOptionsAlgorithmRoundRobinConst,
			&vpcv1.LoadBalancerPoolHealthMonitorPrototype{
				Delay:      core.Int64Ptr(5),
				MaxRetries: core.Int64Ptr(2),
				Timeout:    core.Int64Ptr(2),
				Type:       ptr.To("tcp"),
			},
			vpcv1.CreateLoadBalancerPoolOptionsProtocolTCPConst,
		)
		createLBPOptions.SetName(name)

		lbp, response, err = lb.vpcSvc.CreateLoadBalancerPoolWithContext(lb.ctx, createLBPOptions)
		if err != nil {
			log.Fatalf("Error: CreateLoadBalancerPoolWithContext returns response = %v, err = %v", response, err)
			return err
		}
		log.Debugf("AddLoadBalancerPool: lbp = %+v", lbp)

		err = lb.waitForLoadBalancer(*lb.innerLb.ID)
		if err != nil {
			log.Fatalf("Error: waitForLoadBalancer returns %v", err)
			return err
		}

		getOptions = lb.vpcSvc.NewGetLoadBalancerOptions(*lb.innerLb.ID)
		currentLb, response, err = lb.vpcSvc.GetLoadBalancer(getOptions)
		if err != nil {
			log.Fatalf("Error: GetLoadBalancer returns %v", err)
			return err
		}

		if len(currentLb.Pools) == 0 {
			return fmt.Errorf("Error: AddLoadBalancerPool Pools is still 0!")
		}
	}

	log.Debugf("AddLoadBalancerPool: Searching for name = %s", name)
	for _, lbpr = range currentLb.Pools {
		log.Debugf("AddLoadBalancerPool: lbpr.Name = %s", *lbpr.Name)
		log.Debugf("AddLoadBalancerPool: lbpr.ID   = %s", *lbpr.ID)
		if *lbpr.Name == name {
			lbpID = *lbpr.ID
			break
		}
	}
	log.Debugf("AddLoadBalancerPool: lbpID = %s", lbpID)
	if lbpID == "" {
		return fmt.Errorf("Error: AddLoadBalancerPool has a empty lbpID!")
	}

	// Does it already exist?
	lbpmc, response, err = lb.vpcSvc.ListLoadBalancerPoolMembersWithContext(
		lb.ctx,
		&vpcv1.ListLoadBalancerPoolMembersOptions{
			LoadBalancerID: lb.innerLb.ID,
			PoolID:         &lbpID,
		},
	)
	if err != nil {
		log.Fatalf("Error: ListLoadBalancerPoolMembersWithContext returns response = %v, err = %v", response, err)
		return err
	}
	log.Debugf("AddLoadBalancerPool: lbpmc = %+v", lbpmc)

	for _, member := range lbpmc.Members {
		log.Debugf("AddLoadBalancerPool: member.Port = %d", *member.Port)
		log.Debugf("AddLoadBalancerPool: member.Target = %T", member.Target)
		if *member.Port == port {
			switch reflect.TypeOf(member.Target).String() {
			case "*vpcv1.LoadBalancerPoolMemberTarget":
				addr, ok := member.Target.(*vpcv1.LoadBalancerPoolMemberTarget)
				if !ok {
					return fmt.Errorf("could not convert to LoadBalancerPoolMemberTarget")
				}
				log.Debugf("AddLoadBalancerPool: addr.Address = %s", *addr.Address)
				if *addr.Address == address {
					log.Debugf("AddLoadBalancerPool: found!")
					return nil
				}
			case "*vpcv1.LoadBalancerPoolMemberTargetIP":
				addr, ok := member.Target.(*vpcv1.LoadBalancerPoolMemberTargetIP)
				if !ok {
					return fmt.Errorf("could not convert to LoadBalancerPoolMemberTargetIP")
				}
				log.Debugf("AddLoadBalancerPool: addr.Address = %s", *addr.Address)
				if *addr.Address == address {
					log.Debugf("AddLoadBalancerPool: found!")
					return nil
				}
			default:
			}
		}
	}

	lbpm, response, err = lb.vpcSvc.CreateLoadBalancerPoolMemberWithContext(
		lb.ctx,
		&vpcv1.CreateLoadBalancerPoolMemberOptions{
			LoadBalancerID: lb.innerLb.ID,
			PoolID:         &lbpID,
			Port:           &port,
			Target:         &vpcv1.LoadBalancerPoolMemberTargetPrototype{
				Address: &address,
			},
		},
	)
	if err != nil {
		log.Fatalf("Error: CreateLoadBalancerPoolMemberWithContext returns response = %v, err = %v", response, err)
		return err
	}
	log.Debugf("AddLoadBalancerPool: lbpm = %+v", lbpm)

	err = lb.waitForLoadBalancer(*lb.innerLb.ID)
	if err != nil {
		log.Fatalf("Error: waitForLoadBalancer returns %v", err)
		return err
	}

	return err
}

func (lb *LoadBalancer) AddLoadBalancerListener(name string, port int64, address string) error {

	var (
		getOptions       *vpcv1.GetLoadBalancerOptions
		currentLb        *vpcv1.LoadBalancer
		lbpr             vpcv1.LoadBalancerPoolReference
		lbpID            string
		optionsLBL       *vpcv1.ListLoadBalancerListenersOptions
		createLBLOptions *vpcv1.CreateLoadBalancerListenerOptions
		lblc             *vpcv1.LoadBalancerListenerCollection
		lbl              *vpcv1.LoadBalancerListener
		response         *core.DetailedResponse
		err              error
	)

	if lb.innerLb == nil {
		return fmt.Errorf("Error: AddLoadBalancerListener has a nil LoadBalancer!")
	}

	getOptions = lb.vpcSvc.NewGetLoadBalancerOptions(*lb.innerLb.ID)
	currentLb, response, err = lb.vpcSvc.GetLoadBalancer(getOptions)
	if err != nil {
		log.Fatalf("Error: GetLoadBalancer returns %v", err)
		return err
	}

	if len(currentLb.Pools) == 0 {
		return fmt.Errorf("Error: currentLb.Pools has no elements")
	}

	log.Debugf("AddLoadBalancerListener: Searching for name = %s", name)
	for _, lbpr = range currentLb.Pools {
		log.Debugf("AddLoadBalancerListener: lbpr.Name = %s", *lbpr.Name)
		log.Debugf("AddLoadBalancerListener: lbpr.ID   = %s", *lbpr.ID)
		if *lbpr.Name == name {
			lbpID = *lbpr.ID
			break
		}
	}
	log.Debugf("AddLoadBalancerListener: lbpID = %s", lbpID)
	if lbpID == "" {
		return fmt.Errorf("Error: AddLoadBalancerListener has a empty lbpID!")
	}

	optionsLBL = lb.vpcSvc.NewListLoadBalancerListenersOptions(*lb.innerLb.ID)

	lblc, response, err = lb.vpcSvc.ListLoadBalancerListenersWithContext(lb.ctx, optionsLBL)
	if err != nil {
		log.Fatalf("Error: ListLoadBalancerListenersWithContext returns response = %v, err = %v", response, err)
		return err
	}
	log.Debugf("lblc = %+v", lblc)

	for _, member := range lblc.Listeners {
		log.Debugf("member.DefaultPool.Name = %s", *member.DefaultPool.Name)
		if *member.DefaultPool.Name == name {
			return nil
		}
	}

	log.Debugf("AddLoadBalancerListener: Creating a listener...")

	createLBLOptions = lb.vpcSvc.NewCreateLoadBalancerListenerOptions(
		*lb.innerLb.ID,
		vpcv1.CreateLoadBalancerListenerOptionsProtocolTCPConst)
	createLBLOptions.SetDefaultPool(
		&vpcv1.LoadBalancerPoolIdentityLoadBalancerPoolIdentityByID{
			ID: &lbpID,
		})
	createLBLOptions.SetPort(port)

	lbl, response, err = lb.vpcSvc.CreateLoadBalancerListenerWithContext(lb.ctx, createLBLOptions)
	if err != nil {
		log.Fatalf("Error: CreateLoadBalancerPoolMemberWithContext returns response = %v, err = %v", response, err)
		return err
	}
	log.Debugf("AddLoadBalancerListener: lbl = %+v", lbl)

	err = lb.waitForLoadBalancer(*lb.innerLb.ID)
	if err != nil {
		log.Fatalf("Error: waitForLoadBalancer returns %v", err)
		return err
	}

	return err
}

func (lb *LoadBalancer) deleteLoadBalancer() error {

	var (
		deleteOptions *vpcv1.DeleteLoadBalancerOptions
		response      *core.DetailedResponse
		err error
	)

	if lb.innerLb == nil {
		return nil
	}

	deleteOptions = lb.vpcSvc.NewDeleteLoadBalancerOptions(*lb.innerLb.ID)

	response, err = lb.vpcSvc.DeleteLoadBalancerWithContext(lb.ctx, deleteOptions)
	if err != nil {
		log.Fatalf("Error: DeleteLoadBalancerWithContext returns response = %v, err = %v", response, err)
		return err
	}

	err = lb.waitForLoadBalancer(*lb.innerLb.ID)
	if err != nil {
		log.Fatalf("Error: waitForLoadBalancer returns %v", err)
		return err
	}

	lb.innerLb = nil

	return err
}
