package main

import (
	"context"
	"math"
	"net/http"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/vpc-go-sdk/vpcv1"
	"github.com/sirupsen/logrus"
)

var shouldDebug = false

var log *logrus.Logger

func main() {
}

// Client makes calls to the PowerVS API.
type Client struct {
	vpcAPI            *vpcv1.VpcV1
}

// ListSecurityGroupRules creates a load balancer pool for the specified port.
func (c *Client) CreateLoadBalancerPool(ctx context.Context, lbID string, poolName string, port int64) error {
	var (
		glbOptions   *vpcv1.GetLoadBalancerOptions
		llbpOptions  *vpcv1.ListLoadBalancerPoolsOptions
		llbpmOptions *vpcv1.ListLoadBalancerPoolMembersOptions
		clbpOptions  *vpcv1.CreateLoadBalancerPoolOptions
		clbpmOptions *vpcv1.CreateLoadBalancerPoolMemberOptions
		clblOptions  *vpcv1.CreateLoadBalancerListenerOptions
		lb           *vpcv1.LoadBalancer
		lbPools      *vpcv1.LoadBalancerPoolCollection
		lbMembers    *vpcv1.LoadBalancerPoolMemberCollection
		lbPool       *vpcv1.LoadBalancerPool
		lbpmtp       *vpcv1.LoadBalancerPoolMemberTargetPrototypeIP
		lbpm         *vpcv1.LoadBalancerPoolMember
		lbl          *vpcv1.LoadBalancerListener
		defaultPool  *vpcv1.LoadBalancerPoolIdentityByName
		response     *core.DetailedResponse
		err          error
	)

	glbOptions = c.vpcAPI.NewGetLoadBalancerOptions(lbID)

	lb, response, err = c.vpcAPI.GetLoadBalancerWithContext(ctx, glbOptions)
	if err != nil {
		log.Errorf("CreateLoadBalancerPool: GLBWC lb = %+v, response = %+v, err = %v", lb, response, err)
		return err
	}
	log.Debugf("CreateLoadBalancerPool: GLBWC lb = %+v", lb)

	llbpOptions = c.vpcAPI.NewListLoadBalancerPoolsOptions(lbID)

	lbPools, response, err = c.vpcAPI.ListLoadBalancerPoolsWithContext(ctx, llbpOptions)
	if err != nil {
		log.Errorf("CreateLoadBalancerPool: LLBPWC lbPools = %+v, response = %+v, err = %v", lbPools, response, err)
		return err
	}

	for _, pool := range lbPools.Pools {
		log.Debugf("CreateLoadBalancerPool: pool.ID = %v", *pool.ID)
		log.Debugf("CreateLoadBalancerPool: pool.Name = %v", *pool.Name)

		llbpmOptions = c.vpcAPI.NewListLoadBalancerPoolMembersOptions(lbID, *pool.ID)

		lbMembers, response, err = c.vpcAPI.ListLoadBalancerPoolMembersWithContext(ctx, llbpmOptions)
		if err != nil {
			return err
		}

		for _, member := range lbMembers.Members {
			log.Debugf("CreateLoadBalancerPool: member.ID = %v", *member.ID)
			log.Debugf("CreateLoadBalancerPool: member.Port = %v", *member.Port)

			if *member.Port == port {
				log.Debugf("CreateLoadBalancerPool: found matching port!")
				return nil
			}
		}
	}

	log.Debugf("CreateLoadBalancerPool: Creating pool...")

	lbpmtp, err = c.vpcAPI.NewLoadBalancerPoolMemberTargetPrototypeIP("192.168.0.13")
	if err != nil {
		log.Errorf("CreateLoadBalancerPool: NLBPMTPI err = %v", err)
		return err
	}
	log.Debugf("CreateLoadBalancerPool: lbpmtp = %+v", *lbpmtp)

	clbpOptions = c.vpcAPI.NewCreateLoadBalancerPoolOptions(
		lbID,
		"round_robin",
		&vpcv1.LoadBalancerPoolHealthMonitorPrototype{
			Delay:      core.Int64Ptr(5),
			MaxRetries: core.Int64Ptr(2),
			Timeout:    core.Int64Ptr(2),
			Type:       core.StringPtr("tcp"),
		},
		"tcp",
	)
	clbpOptions.SetName(poolName)

	lbPool, response, err = c.vpcAPI.CreateLoadBalancerPoolWithContext(ctx, clbpOptions)
	if err != nil {
		log.Debugf("CreateLoadBalancerPool: CLBPWC lbPool = %+v, response = %+v, err = %v", lbPool, response, err)
		return err
	}
	log.Debugf("CreateLoadBalancerPool: lbPool = %+v", lbPool)

	clbpmOptions = c.vpcAPI.NewCreateLoadBalancerPoolMemberOptions(lbID, *lbPool.ID, port, lbpmtp)
	log.Debugf("CreateLoadBalancerPool: clbpmOptions = %+v", clbpmOptions)

	lbpm, response, err = c.vpcAPI.CreateLoadBalancerPoolMemberWithContext(ctx, clbpmOptions)
	if err != nil {
		log.Debugf("CreateLoadBalancerPool: CLBPMWC lbpm = %+v, response = %+v, err = %v", lbpm, response, err)
		return err
	}
	log.Debugf("CreateLoadBalancerPool: CLBPMWC lbpm = %+v", lbpm)

	clblOptions = c.vpcAPI.NewCreateLoadBalancerListenerOptions(lbID,
		vpcv1.CreateLoadBalancerListenerOptionsProtocolTCPConst)
	clblOptions.SetPort(port)
	defaultPool = &vpcv1.LoadBalancerPoolIdentityByName{
		Name: core.StringPtr(poolName),
	}
	clblOptions.SetDefaultPool(defaultPool)
	log.Debugf("CreateLoadBalancerPool: clblOptions = %+v", clblOptions)

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
		log.Debugf("CreateLoadBalancerPool: Trying CreateLoadBalancerListenerWithContext")
		lbl, response, err = c.vpcAPI.CreateLoadBalancerListenerWithContext(ctx, clblOptions)
		if response != nil && response.StatusCode == http.StatusConflict {
			return false, nil
		}
		if err != nil {
			log.Debugf("CreateLoadBalancerPool: CLBLWC lbl = %+v, response = %+v, err = %v", lbl, response, err)
			return false, err
		}
		log.Debugf("CreateLoadBalancerPool: CLBLWC lbl = %+v", lbl)
		return true, nil
	})

	return err
}
