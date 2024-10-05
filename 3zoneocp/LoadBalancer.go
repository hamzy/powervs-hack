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
	"regexp"
	"time"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/vpc-go-sdk/vpcv1"
	"k8s.io/apimachinery/pkg/util/wait"
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

func NewLoadBalancer(lbOptions LoadBalancerOptions) (*LoadBalancer, error) {

	var (
		lbName string
		vpcSvc *vpcv1.VpcV1
		ctx    context.Context
		err    error
	)

	log.Debugf("NewLoadBalancer: lbOptions = %+v", lbOptions)

	if lbOptions.IsPublic {
		lbName = fmt.Sprintf("%s", lbOptions.Name)
	} else {
		lbName = fmt.Sprintf("%s-int", lbOptions.Name)
	}

	vpcSvc, err = initLBVPCService(lbOptions)
	log.Debugf("NewLoadBalancer: vpcSvc = %v", vpcSvc)
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

		getOptions = vpc.vpcSvc.NewGetLoadBalancerOptions(*lb.innerLb.ID)

		updatedLb, response, err = lb.vpcSvc.GetLoadBalancer(getOptions)
		if err != nil {
			log.Fatalf("Error: GetLoadBalancer returns %v", err)
			return err
		}
		log.Debugf("createLoadBalancer: updatedLb.Listeners = %+v", updatedLb.Listeners)
		log.Debugf("createLoadBalancer: updatedLb.Pools     = %+v", updatedLb.Pools)
		log.Debugf("createLoadBalancer: len(updatedLb.Listeners) = %d", len(updatedLb.Listeners))
		log.Debugf("createLoadBalancer: len(updatedLb.Pools)     = %d", len(updatedLb.Pools))

		// func (vpc *VpcV1) CreateLoadBalancerListenerWithContext(ctx context.Context, createLoadBalancerListenerOptions *CreateLoadBalancerListenerOptions) (result *LoadBalancerListener, response *core.DetailedResponse, err error)

		// func (vpc *VpcV1) CreateLoadBalancerPoolWithContext(ctx context.Context, createLoadBalancerPoolOptions *CreateLoadBalancerPoolOptions) (result *LoadBalancerPool, response *core.DetailedResponse, err error)
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

	getOptions = vpc.vpcSvc.NewGetLoadBalancerOptions(lbId)

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(vpc.ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(vpc.ctx, backoff, func(context.Context) (bool, error) {
		var err2 error

		foundLb, response, err2 = lb.vpcSvc.GetLoadBalancer(getOptions)
		if err2 != nil {
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

func (lb *LoadBalancer) AddLoadBalancerPool() error {

	var (
//		createOptions *vpcv1.CreateLoadBalancerPoolOptions
		err error
	)

	// func (vpc *VpcV1) ListLoadBalancerPoolsWithContext(ctx context.Context, listLoadBalancerPoolsOptions *ListLoadBalancerPoolsOptions) (result *LoadBalancerPoolCollection, response *core.DetailedResponse, err error)

	// func (vpc *VpcV1) CreateLoadBalancerPoolWithContext(ctx context.Context, createLoadBalancerPoolOptions *CreateLoadBalancerPoolOptions) (result *LoadBalancerPool, response *core.DetailedResponse, err error)

//	createOptions = lb.vpcSvc.NewCreateLoadBalancerPoolOptions (loadBalancerID string, algorithm string, healthMonitor *LoadBalancerPoolHealthMonitorPrototype, protocol string)

	return err
}

func (lb *LoadBalancer) deleteLoadBalancer() error {

	var (
		err error
	)

	return err
}
