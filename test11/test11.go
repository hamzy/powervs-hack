package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"k8s.io/utils/ptr"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"

	survey "github.com/AlecAivazis/survey/v2"
	aacore "github.com/AlecAivazis/survey/v2/core"
	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/networking-go-sdk/dnsrecordsv1"
	"github.com/IBM/networking-go-sdk/dnssvcsv1"
	"github.com/IBM/networking-go-sdk/dnszonesv1"
	"github.com/IBM/networking-go-sdk/resourcerecordsv1"
	"github.com/IBM/networking-go-sdk/transitgatewayapisv1"
	"github.com/IBM/networking-go-sdk/zonesv1"
	"github.com/IBM/platform-services-go-sdk/resourcecontrollerv2"
	"github.com/IBM/platform-services-go-sdk/resourcemanagerv2"
	"github.com/IBM/vpc-go-sdk/vpcv1"
	"github.com/IBM-Cloud/bluemix-go/crn"
	"github.com/IBM-Cloud/power-go-client/ibmpisession"
	"github.com/form3tech-oss/jwt-go"
	"github.com/sirupsen/logrus"
)

var shouldDebug = false

var log *logrus.Logger

func main() {

	var logMain *logrus.Logger = &logrus.Logger{
		Out: os.Stderr,
		Formatter: new(logrus.TextFormatter),
		Level: logrus.DebugLevel,
	}

	var (
		ptrApiKey         *string
		ptrCISInstanceCRN *string
		ptrBaseDomain     *string
		ptrVPCId          *string
		ptrShouldDebug    *string
		client            *Client
		ctx               context.Context
		err               error
	)

	ptrApiKey = flag.String("apiKey", "", "Your IBM Cloud API key")
	ptrCISInstanceCRN = flag.String("CISInstanceCRN", "", "CISInstanceCRN")
	ptrBaseDomain = flag.String("BaseDomain", "", "BaseDomain")
	ptrVPCId = flag.String("VPCID", "", "VPCID")
	ptrShouldDebug = flag.String("shouldDebug", "false", "Should output debug output")

	flag.Parse()

	if *ptrApiKey == "" {
		logMain.Fatal("Error: No API key set, use --apiKey")
	}

	switch strings.ToLower(*ptrShouldDebug) {
	case "true":
		shouldDebug = true
	case "false":
		shouldDebug = false
	default:
		logMain.Fatal("Error: shouldDebug is not true/false (%s)\n", *ptrShouldDebug)
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

	s1 := sets.New[int64](22, 10258, 22623)
	log.Printf("s1 = %+v\n", s1)
	s2 := sets.Set[int64]{}
	log.Printf("s2 = %+v\n", s2)
	s2.Insert(22, 77)
	log.Printf("s2 = %+v\n", s2)
	log.Printf("s1.Difference(s2) = %+v\n", s1.Difference(s2))
	for i := range s1.Difference(s2) {
		log.Printf("i = %+v\n", i)
	}

	infraID := "rdr-hamzy-test-dal10-lrzr7"
	log.Debugf("infraID = %s", infraID)
	idx := strings.LastIndex(infraID, "-")
	log.Debugf("idx = %d", idx)
	substr := infraID[idx:]
	log.Debugf("substr = %s", substr)
	hostnameOld := "rdr-hamzy-test-dal10-lrzr7-loadbalancer-int"
	log.Debugf("hostnameOld = %s", hostnameOld)
	hostnameNew := strings.ReplaceAll(hostnameOld, substr, "")
	log.Debugf("hostnameNew = %s", hostnameNew)

	log.Debugf("ptrCISInstanceCRN = %s", *ptrCISInstanceCRN)
	log.Debugf("ptrBaseDomain     = %s", *ptrBaseDomain)
	log.Debugf("ptrVPCId          = %s", *ptrVPCId)

	client, err = NewClient()
	if err != nil {
		log.Errorf("NewClient returns %v", err)
		return
	}
	log.Debugf("NewClient returns %+v", client)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	log.Debugf("ctx = %v", ctx)

	if err = client.SetVPCServiceURLForRegion(ctx, "us-south"); err != nil {
		log.Errorf("SetVPCServiceURLForRegion returns %v", err)
		return
	}

//	serviceInstanceNameToGUID(*ptrVPCId,
//		client,
//		ctx)

//	createDNSRecords(ptrCISInstanceCRN,
//		ptrBaseDomain,
//		client,
//		ctx,
//	)

//	addSecurityGroupRules(ptrVPCId,
//		client,
//		ctx)

//	listSecurityGroupRules(ptrVPCId,
//		client,
//		ctx)

//	createLoadBalancerPool(ptrVPCId,
//		client,
//		ctx,
//		"additional-pool-22",
//		22,
//		"192.168.0.13")

	addIPToLoadBalancerPool(ptrVPCId,
		client,
		ctx,
		"additional-pool-22623",
		22623,
		"192.168.0.13")
}

func serviceInstanceNameToGUID(name string, client *Client, ctx context.Context) {

	var (
		guid string
		err  error
	)

	guid, err = client.ServiceInstanceNameToGUID(ctx, name)
	if err != nil {
		log.Errorf("client.ServiceInstanceNameToGUID returns %v", err)
		return
	}
	log.Debugf("serviceInstanceNameToGUID: guid = %s", guid)
}

func createDNSRecords(ptrCISInstanceCRN *string,
		ptrBaseDomain     *string,
		client            *Client,
		ctx               context.Context) {

	var (
		err error
	)

	err = client.CreateDNSRecord(ctx,
		*ptrCISInstanceCRN,
		*ptrBaseDomain,
		"api-int.rdr-hamzy-test-dal10.powervs-openshift-ipi.cis.ibm.net",
		"93327b30-us-south.lb.appdomain.cloud",
	)
	if err != nil {
		log.Errorf("client.CreateDNSRecord (call 1) returns %v", err)
		return
	}

	err = client.CreateDNSRecord(ctx,
		*ptrCISInstanceCRN,
		*ptrBaseDomain,
		"api.rdr-hamzy-test-dal10.powervs-openshift-ipi.cis.ibm.net",
		"2eb95ecc-us-south.lb.appdomain.cloud",
	)
	if err != nil {
		log.Errorf("client.CreateDNSRecord (call 2) returns %v", err)
		return
	}
}

func addSecurityGroupRules(ptrVPCId *string, client *Client, ctx context.Context) {
	var (
		rule *vpcv1.SecurityGroupRulePrototype
	)

	rule = &vpcv1.SecurityGroupRulePrototype{
		Direction: ptr.To("inbound"),
		Protocol:  ptr.To("tcp"),
		PortMin:   ptr.To(int64(22)),
		PortMax:   ptr.To(int64(22)),
	}

	client.AddSecurityGroupRule(ctx, *ptrVPCId, rule)
}

func listSecurityGroupRules(ptrVPCId *string, client *Client, ctx context.Context) {
	var (
		rules       *vpcv1.SecurityGroupRuleCollection
		found       = false
		err         error
	)

	rules, err = client.ListSecurityGroupRules(ctx, *ptrVPCId)
	if err != nil {
		log.Debugf("client.ListSecurityGroupRules: err = %v", err)
		return
	}

	for _, existingRule := range rules.Rules {
		switch reflect.TypeOf(existingRule).String() {
		case "*vpcv1.SecurityGroupRuleSecurityGroupRuleProtocolAll":
		case "*vpcv1.SecurityGroupRuleSecurityGroupRuleProtocolTcpudp":
			securityGroupRule, ok := existingRule.(*vpcv1.SecurityGroupRuleSecurityGroupRuleProtocolTcpudp)
			if !ok {
				log.Debugf("could not convert to ProtocolTcpudp")
				return
			}
			log.Debugf("listSecurityGroupRules: VPC has rule: direction = %s, proto = %s, min = %d, max = %d",
				*securityGroupRule.Direction,
				*securityGroupRule.Protocol,
				*securityGroupRule.PortMin,
				*securityGroupRule.PortMax)
			found = false
			if *securityGroupRule.Direction == "inbound" &&
				*securityGroupRule.Protocol == "tcp" &&
				*securityGroupRule.PortMin == 6443 {
				found = true
			}
			log.Debugf("listSecurityGroupRules: found = %v", found)
		case "*vpcv1.SecurityGroupRuleSecurityGroupRuleProtocolIcmp":
		}
	}
}

func createLoadBalancerPool(lbID *string, client *Client, ctx context.Context, poolName string, port int64, ip string) {
	var (
		err         error
	)

	err = client.CreateLoadBalancerPool(ctx, *lbID, poolName, port, ip)
	if err != nil {
		log.Errorf("client.CreateLoadBalancerPool returns %v", err)
	}
}

func addIPToLoadBalancerPool(lbID *string, client *Client, ctx context.Context, poolName string, port int64, ip string) {
	var (
		err         error
	)

	err = client.AddIPToLoadBalancerPool(ctx, *lbID, poolName, port, ip)
	if err != nil {
		log.Errorf("client.AddIPToLoadBalancerPool returns %v", err)
	}
}

// 8<--------8<--------8<--------8<--------8<--------8<--------8<--------8<--------8<--------8<--------

const (
	// resource Id for Power Systems Virtual Server in the Global catalog.
	powerIAASResourceID = "abd259f0-9990-11e8-acc8-b9f54a8f1661"
)

// ServiceInstanceNameToGUIDreturns the name of the matching service instance GUID which was passed in.
func (c *Client) ServiceInstanceNameToGUID(ctx context.Context, name string) (string, error) {
	var (
		options   *resourcecontrollerv2.ListResourceInstancesOptions
		resources *resourcecontrollerv2.ResourceInstancesList
		err       error
		perPage   int64 = 10
		moreData        = true
		nextURL   *string
		groupID   = c.BXCli.PowerVSResourceGroup
	)

	// If the user passes in a human readable group id, then we need to convert it to a UUID
	listGroupOptions := c.managementAPI.NewListResourceGroupsOptions()
	listGroupOptions.AccountID = &c.BXCli.User.Account
	groups, _, err := c.managementAPI.ListResourceGroupsWithContext(ctx, listGroupOptions)
	if err != nil {
		return "", fmt.Errorf("failed to list resource groups: %w", err)
	}
	for _, group := range groups.Resources {
		if *group.Name == groupID {
			groupID = *group.ID
		}
	}

	options = c.controllerAPI.NewListResourceInstancesOptions()
	options.SetResourceGroupID(groupID)
	// resource ID for Power Systems Virtual Server in the Global catalog
	options.SetResourceID(powerIAASResourceID)
	options.SetLimit(perPage)

	for moreData {
		resources, _, err = c.controllerAPI.ListResourceInstancesWithContext(ctx, options)
		if err != nil {
			return "", fmt.Errorf("failed to list resource instances: %w", err)
		}

		for _, resource := range resources.Resources {
			var (
				getResourceOptions *resourcecontrollerv2.GetResourceInstanceOptions
				resourceInstance   *resourcecontrollerv2.ResourceInstance
				response           *core.DetailedResponse
			)

			getResourceOptions = c.controllerAPI.NewGetResourceInstanceOptions(*resource.ID)

			resourceInstance, response, err = c.controllerAPI.GetResourceInstance(getResourceOptions)
			if err != nil {
				return "", fmt.Errorf("failed to get instance: %w", err)
			}
			if response != nil && response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusInternalServerError {
				continue
			}

			if resourceInstance.Type != nil && (*resourceInstance.Type == "service_instance" || *resourceInstance.Type == "composite_instance") {
				if resourceInstance.Name != nil && *resourceInstance.Name == name {
					if resourceInstance.GUID == nil {
						return "", nil
					}
					return *resourceInstance.GUID, nil
				}
			}
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

// 8<--------8<--------8<--------8<--------8<--------8<--------8<--------8<--------8<--------8<--------

// CreateDNSRecord Creates a DNS CNAME record in the given base domain and CRN.
func (c *Client) CreateDNSRecord(ctx context.Context, crnstr string, baseDomain string, hostname string, cname string) error {
	log.Debugf("CreateDNSRecord: crnstr = %s, hostname = %s, cname = %s", crnstr, hostname, cname)

	var (
		zoneID           string
		err              error
		authenticator    *core.IamAuthenticator
		globalOptions    *dnsrecordsv1.DnsRecordsV1Options
		dnsRecordService *dnsrecordsv1.DnsRecordsV1
	)

	// Get CIS zone ID by name
	zoneID, err = c.GetDNSZoneIDByName(ctx, baseDomain, ExternalPublishingStrategy)
	if err != nil {
		log.Errorf("c.GetDNSZoneIDByName returns %v", err)
		return err
	}
	log.Debugf("CreateDNSRecord: zoneID = %s", zoneID)

	authenticator = &core.IamAuthenticator{
		ApiKey: c.APIKey,
	}
	globalOptions = &dnsrecordsv1.DnsRecordsV1Options{
		Authenticator:  authenticator,
		Crn:            ptr.To(crnstr),
		ZoneIdentifier: ptr.To(zoneID),
	}
	dnsRecordService, err = dnsrecordsv1.NewDnsRecordsV1(globalOptions)
	if err != nil {
		log.Errorf("dnsrecordsv1.NewDnsRecordsV1 returns %v", err)
		return err
	}
	log.Debugf("CreateDNSRecord: dnsRecordService = %+v", dnsRecordService)

	createOptions := dnsRecordService.NewCreateDnsRecordOptions()
	createOptions.SetName(hostname)
	createOptions.SetType(dnsrecordsv1.CreateDnsRecordOptions_Type_Cname)
	createOptions.SetContent(cname)

	result, response, err := dnsRecordService.CreateDnsRecord(createOptions)
	if err != nil {
		log.Errorf("dnsRecordService.CreateDnsRecord returns %v", err)
		return err
	}
	log.Debugf("CreateDNSRecord: Result.ID = %v, RawResult = %v", *result.Result.ID, response.RawResult)

	return nil
}

// 8<--------8<--------8<--------8<--------8<--------8<--------8<--------8<--------8<--------8<--------

// AddSecurityGroupRule adds a security group rule to an existing security group.
func (c *Client) AddSecurityGroupRule(ctx context.Context, securityGroupID string, rule *vpcv1.SecurityGroupRulePrototype) error {
	log.Debugf("AddSecurityGroupRule: securityGroupID = %s, rule = %+v", securityGroupID, *rule)

	var (
		vpcOptions  *vpcv1.GetVPCOptions
		vpc         *vpcv1.VPC
		optionsCSGR *vpcv1.CreateSecurityGroupRuleOptions
		result      vpcv1.SecurityGroupRuleIntf
		response    *core.DetailedResponse
		err         error
	)

	vpcOptions = c.vpcAPI.NewGetVPCOptions(securityGroupID)

	vpc, response, err = c.vpcAPI.GetVPC(vpcOptions)
	if err != nil {
		return fmt.Errorf("failure AddSecurityGroupRule GetVPC returns %v, response is %+v", err, response)
	}
	log.Debugf("AddSecurityGroupRule: vpc = %+v", vpc)

	optionsCSGR = &vpcv1.CreateSecurityGroupRuleOptions{}
	optionsCSGR.SetSecurityGroupID(*vpc.DefaultSecurityGroup.ID)
	optionsCSGR.SetSecurityGroupRulePrototype(rule)

	result, response, err = c.vpcAPI.CreateSecurityGroupRule(optionsCSGR)
	if err != nil {
		log.Debugf("AddSecurityGroupRule: result = %+v, response = %+v, err = %v", result, response, err)
	}

	return err
}

// 8<--------8<--------8<--------8<--------8<--------8<--------8<--------8<--------8<--------8<--------

// ListSecurityGroupRules returns a list of the security group rules.
func (c *Client) ListSecurityGroupRules(ctx context.Context, securityGroupID string) (*vpcv1.SecurityGroupRuleCollection, error) {
	log.Debugf("ListSecurityGroupRules: securityGroupID = %s", securityGroupID)

	var (
		vpcOptions  *vpcv1.GetVPCOptions
		vpc         *vpcv1.VPC
		optionsLSGR *vpcv1.ListSecurityGroupRulesOptions
		result      *vpcv1.SecurityGroupRuleCollection
		response    *core.DetailedResponse
		err         error
	)

	vpcOptions = c.vpcAPI.NewGetVPCOptions(securityGroupID)

	vpc, response, err = c.vpcAPI.GetVPC(vpcOptions)
	if err != nil {
		return nil, fmt.Errorf("failure ListSecurityGroupRules GetVPC returns %w, response is %+v", err, response)
	}
	log.Debugf("ListSecurityGroupRules: vpc = %+v", vpc)

	optionsLSGR = c.vpcAPI.NewListSecurityGroupRulesOptions(*vpc.DefaultSecurityGroup.ID)

	result, response, err = c.vpcAPI.ListSecurityGroupRulesWithContext(ctx, optionsLSGR)
	if err != nil {
		log.Debugf("ListSecurityGroupRules: result = %+v, response = %+v, err = %v", result, response, err)
		return nil, err
	}

	return result, err
}

// 8<--------8<--------8<--------8<--------8<--------8<--------8<--------8<--------8<--------8<--------

// CreateLoadBalancerPool creates a load balancer pool for the specified port and ip address.
func (c *Client) CreateLoadBalancerPool(ctx context.Context, lbID string, poolName string, port int64, ip string) error {
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
		response     *core.DetailedResponse
		err          error
	)

	// Make sure the load balancer exists
	glbOptions = c.vpcAPI.NewGetLoadBalancerOptions(lbID)

	lb, response, err = c.vpcAPI.GetLoadBalancerWithContext(ctx, glbOptions)
	if err != nil {
		log.Errorf("CreateLoadBalancerPool: GLBWC lb = %+v, response = %+v, err = %v", lb, response, err)
		return err
	}
	log.Debugf("CreateLoadBalancerPool: GLBWC lb = %+v", lb)

	// Query the existing load balancer pools
	llbpOptions = c.vpcAPI.NewListLoadBalancerPoolsOptions(lbID)

	lbPools, response, err = c.vpcAPI.ListLoadBalancerPoolsWithContext(ctx, llbpOptions)
	if err != nil {
		log.Errorf("CreateLoadBalancerPool: LLBPWC lbPools = %+v, response = %+v, err = %v", lbPools, response, err)
		return err
	}

	// Is there an existing listener with that port?
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

	lbpmtp, err = c.vpcAPI.NewLoadBalancerPoolMemberTargetPrototypeIP(ip)
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
	clblOptions.SetDefaultPool(&vpcv1.LoadBalancerPoolIdentity{
		ID: lbPool.ID,
	})
	log.Debugf("CreateLoadBalancerPool: clblOptions = %+v", clblOptions)

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
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

// 8<--------8<--------8<--------8<--------8<--------8<--------8<--------8<--------8<--------8<--------

// AddIPToLoadBalancerPool adds a server to a load balancer pool for the specified port.
func (c *Client) AddIPToLoadBalancerPool(ctx context.Context, lbID string, poolName string, port int64, ip string) error {
	var (
		glbOptions    *vpcv1.GetLoadBalancerOptions
		llbpOptions   *vpcv1.ListLoadBalancerPoolsOptions
		llbpmOptions  *vpcv1.ListLoadBalancerPoolMembersOptions
		clbpmOptions  *vpcv1.CreateLoadBalancerPoolMemberOptions
		lb            *vpcv1.LoadBalancer
		lbPools       *vpcv1.LoadBalancerPoolCollection
		lbPool        vpcv1.LoadBalancerPool
		lbPoolMembers *vpcv1.LoadBalancerPoolMemberCollection
		lbpmtp        *vpcv1.LoadBalancerPoolMemberTargetPrototypeIP
		lbpm          *vpcv1.LoadBalancerPoolMember
		response      *core.DetailedResponse
		err           error
	)

	// Make sure the load balancer exists
	glbOptions = c.vpcAPI.NewGetLoadBalancerOptions(lbID)

	lb, response, err = c.vpcAPI.GetLoadBalancerWithContext(ctx, glbOptions)
	if err != nil {
		log.Errorf("AddIPToLoadBalancerPool: GLBWC lb = %+v, response = %+v, err = %v", lb, response, err)
		return err
	}
	log.Debugf("AddIPToLoadBalancerPool: GLBWC lb = %+v", lb)

	// Query the existing load balancer pools
	llbpOptions = c.vpcAPI.NewListLoadBalancerPoolsOptions(lbID)

	lbPools, response, err = c.vpcAPI.ListLoadBalancerPoolsWithContext(ctx, llbpOptions)
	if err != nil {
		log.Errorf("AddIPToLoadBalancerPool: LLBPWC lbPools = %+v, response = %+v, err = %v", lbPools, response, err)
		return err
	}

	// Find the pool with the specified name
	for _, pool := range lbPools.Pools {
		log.Debugf("AddIPToLoadBalancerPool: pool.ID = %v", *pool.ID)
		log.Debugf("AddIPToLoadBalancerPool: pool.Name = %v", *pool.Name)

		if *pool.Name == poolName {
			lbPool = pool
			break
		}
	}
	if lbPool.ID == nil {
		return fmt.Errorf("could not find loadbalancer pool with name %s", poolName)
	}

	// Query the load balancer pool members
	llbpmOptions = c.vpcAPI.NewListLoadBalancerPoolMembersOptions(lbID, *lbPool.ID)

	lbPoolMembers, response, err = c.vpcAPI.ListLoadBalancerPoolMembersWithContext(ctx, llbpmOptions)
	if err != nil {
		log.Errorf("AddIPToLoadBalancerPool: LLBPMWC lbPoolMembers = %+v, response = %+v, err = %v",
			lbPools,
			response,
			err)
	}

	// See if a member already exists with that IP
	for _, poolMember := range lbPoolMembers.Members {
		logrus.Debugf("AddIPToLoadBalancerPool: poolMember.ID = %s", *poolMember.ID)
		switch pmt := poolMember.Target.(type) {
		case *vpcv1.LoadBalancerPoolMemberTarget:
			log.Debugf("AddIPToLoadBalancerPool: pmt.Address = %+v", *pmt.Address)
			if ip == *pmt.Address {
				log.Debugf("AddIPToLoadBalancerPool: found %s", ip)
				return nil
			}
		case *vpcv1.LoadBalancerPoolMemberTargetIP:
			log.Debugf("AddIPToLoadBalancerPool: pmt.Address = %+v", *pmt.Address)
			if ip == *pmt.Address {
				log.Debugf("AddIPToLoadBalancerPool: found %s", ip)
				return nil
			}
		case *vpcv1.LoadBalancerPoolMemberTargetInstanceReference:
			// No IP address, ignore
		default:
			log.Debugf("AddIPToLoadBalancerPool: unhandled type %T", poolMember.Target)
		}
	}

	// Create a new member
	lbpmtp, err = c.vpcAPI.NewLoadBalancerPoolMemberTargetPrototypeIP(ip)
	if err != nil {
		log.Errorf("AddIPToLoadBalancerPool: NLBPMTPI err = %v", err)
		return err
	}
	log.Debugf("AddIPToLoadBalancerPool: lbpmtp = %+v", *lbpmtp)

	// Add that member to the pool
	clbpmOptions = c.vpcAPI.NewCreateLoadBalancerPoolMemberOptions(lbID, *lbPool.ID, port, lbpmtp)
	log.Debugf("AddIPToLoadBalancerPool: clbpmOptions = %+v", clbpmOptions)

	lbpm, response, err = c.vpcAPI.CreateLoadBalancerPoolMemberWithContext(ctx, clbpmOptions)
	if err != nil {
		log.Debugf("AddIPToLoadBalancerPool: CLBPMWC lbpm = %+v, response = %+v, err = %v", lbpm, response, err)
		return err
	}
	log.Debugf("AddIPToLoadBalancerPool: CLBPMWC lbpm = %+v", lbpm)

	return nil
}

// 8<--------8<--------8<--------8<--------8<--------8<--------8<--------8<--------8<--------8<--------

func leftInContext(ctx context.Context) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return math.MaxInt64
	}

	duration := time.Until(deadline)

	return duration
}

// PublishingStrategy is a strategy for how various endpoints for the cluster are exposed.
// +kubebuilder:validation:Enum="";External;Internal
type PublishingStrategy string

const (
	// ExternalPublishingStrategy exposes endpoints for the cluster to the Internet.
	ExternalPublishingStrategy PublishingStrategy = "External"
	// InternalPublishingStrategy exposes the endpoints for the cluster to the private network only.
	InternalPublishingStrategy PublishingStrategy = "Internal"
	// MixedPublishingStrategy allows for the api server and the ingress to be configured individually for exposure to
	// private network or Internet.
	MixedPublishingStrategy PublishingStrategy = "Mixed"
)

// BxClient is struct which provides bluemix session details
type BxClient struct {
	APIKey               string
	Region               string
	Zone                 string
	PISession            *ibmpisession.IBMPISession
	User                 *User
	PowerVSResourceGroup string
}

// User is struct with user details
type User struct {
	ID      string
	Email   string
	Account string
}

// SessionStore is an object and store that holds credentials and variables required to create a SessionVars object.
type SessionStore struct {
	ID                   string `json:"id,omitempty"`
	APIKey               string `json:"apikey,omitempty"`
	DefaultRegion        string `json:"region,omitempty"`
	DefaultZone          string `json:"zone,omitempty"`
	PowerVSResourceGroup string `json:"resourcegroup,omitempty"`
}

// SessionVars is an object that holds the variables required to create an ibmpisession object.
type SessionVars struct {
	ID                   string
	APIKey               string
	Region               string
	Zone                 string
	PowerVSResourceGroup string
}

var (
	defSessionTimeout   time.Duration = 9000000000000000000.0
	defRegion                         = "us_south"
	defaultAuthFilePath               = filepath.Join(os.Getenv("HOME"), ".powervs", "config.json")
)

// getSessionStoreFromAuthFile gets the session creds from the auth file.
func getSessionStoreFromAuthFile(pss *SessionStore) error {
	if pss == nil {
		return fmt.Errorf("nil var: SessionStore")
	}

	authFilePath := defaultAuthFilePath
	if f := os.Getenv("POWERVS_AUTH_FILEPATH"); len(f) > 0 {
		authFilePath = f
	}

	if _, err := os.Stat(authFilePath); os.IsNotExist(err) {
		return nil
	}

	content, err := os.ReadFile(authFilePath)
	if err != nil {
		return err
	}

	err = json.Unmarshal(content, pss)
	if err != nil {
		return err
	}

	return nil
}

func getSessionVarsFromEnv(psv *SessionVars) error {
	if psv == nil {
		return fmt.Errorf("nil var: PiSessionVars")
	}

	if len(psv.ID) == 0 {
		psv.ID = os.Getenv("IBMID")
	}

	if len(psv.APIKey) == 0 {
		// APIKeyEnvVars is a list of environment variable names containing an IBM Cloud API key.
		var APIKeyEnvVars = []string{"IC_API_KEY", "IBMCLOUD_API_KEY", "BM_API_KEY", "BLUEMIX_API_KEY"}
		psv.APIKey = getEnv(APIKeyEnvVars)
	}

	if len(psv.Region) == 0 {
		var regionEnvVars = []string{"IBMCLOUD_REGION", "IC_REGION"}
		psv.Region = getEnv(regionEnvVars)
	}

	if len(psv.Zone) == 0 {
		var zoneEnvVars = []string{"IBMCLOUD_ZONE"}
		psv.Zone = getEnv(zoneEnvVars)
	}

	if len(psv.PowerVSResourceGroup) == 0 {
		var resourceEnvVars = []string{"IBMCLOUD_RESOURCE_GROUP"}
		psv.PowerVSResourceGroup = getEnv(resourceEnvVars)
	}

	return nil
}

// Prompt the user for the first set of remaining variables.
// This is a chicken and egg problem.  We cannot call NewBxClient() or NewClient()
// yet for complicated questions to the user since those calls load the session
// variables from the store.  There is the possibility that the are empty at the
// moment.
func getFirstSessionVarsFromUser(psv *SessionVars, pss *SessionStore) error {
	var err error

	if psv == nil {
		return fmt.Errorf("nil var: PiSessionVars")
	}

	if len(psv.ID) == 0 {
		err = survey.Ask([]*survey.Question{
			{
				Prompt: &survey.Input{
					Message: "IBM Cloud User ID",
					Help:    "The login for \nhttps://cloud.ibm.com/",
				},
			},
		}, &psv.ID)
		if err != nil {
			return fmt.Errorf("error saving the IBM Cloud User ID")
		}
	}

	if len(psv.APIKey) == 0 {
		err = survey.Ask([]*survey.Question{
			{
				Prompt: &survey.Password{
					Message: "IBM Cloud API Key",
					Help:    "The API key installation.\nhttps://cloud.ibm.com/iam/apikeys",
				},
			},
		}, &psv.APIKey)
		if err != nil {
			return fmt.Errorf("error saving the API Key")
		}
	}

	return nil
}

// Prompt the user for the second set of remaining variables.
// This is a chicken and egg problem.  Now we can call NewBxClient() or NewClient()
// because the session store should at least have some minimal settings like the
// APIKey.
func getSecondSessionVarsFromUser(psv *SessionVars, pss *SessionStore) error {
	var (
		client *Client
		err    error
	)

	if psv == nil {
		return fmt.Errorf("nil var: PiSessionVars")
	}

	if len(psv.Region) == 0 {
		psv.Region, err = GetRegion(pss.DefaultRegion)
		if err != nil {
			return err
		}
	}

	if len(psv.Zone) == 0 {
		psv.Zone, err = GetZone(psv.Region, pss.DefaultZone)
		if err != nil {
			return err
		}
	}

	if len(psv.PowerVSResourceGroup) == 0 {
		if client == nil {
			client, err = NewClient()
			if err != nil {
				return fmt.Errorf("failed to powervs.NewClient: %w", err)
			}
		}

		ctx, cancel := context.WithTimeout(context.TODO(), 5*time.Minute)
		defer cancel()

		resourceGroups, err := client.ListResourceGroups(ctx)
		if err != nil {
			return fmt.Errorf("failed to list resourceGroups: %w", err)
		}

		resourceGroupsSurvey := make([]string, len(resourceGroups.Resources))
		for i, resourceGroup := range resourceGroups.Resources {
			resourceGroupsSurvey[i] = *resourceGroup.Name
		}

		err = survey.Ask([]*survey.Question{
			{
				Prompt: &survey.Select{
					Message: "Resource Group",
					Help:    "The Power VS resource group to be used for installation.",
					Default: "",
					Options: resourceGroupsSurvey,
				},
			},
		}, &psv.PowerVSResourceGroup)
		if err != nil {
			return fmt.Errorf("survey.ask failed with: %w", err)
		}
	}

	return nil
}

func saveSessionStoreToAuthFile(pss *SessionStore) error {
	authFilePath := defaultAuthFilePath
	if f := os.Getenv("POWERVS_AUTH_FILEPATH"); len(f) > 0 {
		authFilePath = f
	}

	jsonVars, err := json.Marshal(*pss)
	if err != nil {
		return err
	}

	err = os.MkdirAll(filepath.Dir(authFilePath), 0700)
	if err != nil {
		return err
	}

	return os.WriteFile(authFilePath, jsonVars, 0o600)
}

func getEnv(envs []string) string {
	for _, k := range envs {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
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

// Client makes calls to the PowerVS API.
type Client struct {
	APIKey            string
	BXCli             *BxClient
	managementAPI     *resourcemanagerv2.ResourceManagerV2
	controllerAPI     *resourcecontrollerv2.ResourceControllerV2
	vpcAPI            *vpcv1.VpcV1
	dnsServicesAPI    *dnssvcsv1.DnsSvcsV1
	transitGatewayAPI *transitgatewayapisv1.TransitGatewayApisV1
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

// NewBxClient func returns bluemix client
func NewBxClient(survey bool) (*BxClient, error) {
	c := &BxClient{}
	sv, err := getSessionVars(survey)
	if err != nil {
		return nil, err
	}

	c.APIKey = sv.APIKey
	c.Region = sv.Region
	c.Zone = sv.Zone
	c.PowerVSResourceGroup = sv.PowerVSResourceGroup

	c.User, err = FetchUserDetails(c.APIKey)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func getSessionVars(survey bool) (SessionVars, error) {
	var sv SessionVars
	var ss SessionStore

	// Grab the session store from the installer written authFilePath
	logrus.Debug("Gathering credentials from AuthFile")
	err := getSessionStoreFromAuthFile(&ss)
	if err != nil {
		return sv, err
	}

	// Transfer the store to vars if they were found in the AuthFile
	sv.ID = ss.ID
	sv.APIKey = ss.APIKey
	sv.Region = ss.DefaultRegion
	sv.Zone = ss.DefaultZone
	sv.PowerVSResourceGroup = ss.PowerVSResourceGroup

	// Grab variables from the users environment
	logrus.Debug("Gathering variables from user environment")
	err = getSessionVarsFromEnv(&sv)
	if err != nil {
		return sv, err
	}

	// Grab variable from the user themselves
	if survey {
		// Prompt the user for the first set of remaining variables.
		err = getFirstSessionVarsFromUser(&sv, &ss)
		if err != nil {
			return sv, err
		}

		// Transfer vars to the store to write out to the AuthFile
		ss.ID = sv.ID
		ss.APIKey = sv.APIKey
		ss.DefaultRegion = sv.Region
		ss.DefaultZone = sv.Zone
		ss.PowerVSResourceGroup = sv.PowerVSResourceGroup

		// Save the session store to the disk.
		err = saveSessionStoreToAuthFile(&ss)
		if err != nil {
			return sv, err
		}

		// Since there is a minimal store at this point, it is safe
		// to call the function.
		// Prompt the user for the second set of remaining variables.
		err = getSecondSessionVarsFromUser(&sv, &ss)
		if err != nil {
			return sv, err
		}
	}

	// Transfer vars to the store to write out to the AuthFile
	ss.ID = sv.ID
	ss.APIKey = sv.APIKey
	ss.DefaultRegion = sv.Region
	ss.DefaultZone = sv.Zone
	ss.PowerVSResourceGroup = sv.PowerVSResourceGroup

	// Save the session store to the disk.
	err = saveSessionStoreToAuthFile(&ss)
	if err != nil {
		return sv, err
	}

	return sv, nil
}

// API represents the calls made to the API.
type API interface {
	GetDNSRecordsByName(ctx context.Context, crnstr string, zoneID string, recordName string, publish PublishingStrategy) ([]DNSRecordResponse, error)
	GetDNSZoneIDByName(ctx context.Context, name string, publish PublishingStrategy) (string, error)
	GetDNSZones(ctx context.Context, publish PublishingStrategy) ([]DNSZoneResponse, error)
	GetDNSInstancePermittedNetworks(ctx context.Context, dnsID string, dnsZone string) ([]string, error)
	GetAPIKey() string
	ListResourceGroups(ctx context.Context) (*resourcemanagerv2.ResourceGroupList, error)
}

// cisServiceID is the Cloud Internet Services' catalog service ID.
const (
	cisServiceID = "75874a60-cb12-11e7-948e-37ac098eb1b9"
	dnsServiceID = "b4ed8a30-936f-11e9-b289-1d079699cbe5"
)

// DNSZoneResponse represents a DNS zone response.
type DNSZoneResponse struct {
	// Name is the domain name of the zone.
	Name string

	// ID is the zone's ID.
	ID string

	// CISInstanceCRN is the IBM Cloud Resource Name for the CIS instance where
	// the DNS zone is managed.
	InstanceCRN string

	// CISInstanceName is the display name of the CIS instance where the DNS zone
	// is managed.
	InstanceName string

	// ResourceGroupID is the resource group ID of the CIS instance.
	ResourceGroupID string
}

// DNSRecordResponse represents a DNS record response.
type DNSRecordResponse struct {
	Name string
	Type string
}

// NewClient initializes a client with a session.
func NewClient() (*Client, error) {
	bxCli, err := NewBxClient(false)
	if err != nil {
		return nil, err
	}

	client := &Client{
		APIKey: bxCli.APIKey,
		BXCli:  bxCli,
	}

	if err := client.loadSDKServices(); err != nil {
		return nil, fmt.Errorf("failed to load IBM SDK services: %w", err)
	}

	if bxCli.PowerVSResourceGroup == "Default" {
		// Here we are initialized enough to handle a default resource group
		ctx, cancel := context.WithTimeout(context.TODO(), 5*time.Minute)
		defer cancel()

		resourceGroups, err := client.ListResourceGroups(ctx)
		if err != nil {
			return nil, fmt.Errorf("client.ListResourceGroups failed: %w", err)
		}
		if resourceGroups == nil {
			return nil, fmt.Errorf("client.ListResourceGroups returns nil")
		}

		found := false
		for _, resourceGroup := range resourceGroups.Resources {
			if resourceGroup.Default != nil && *resourceGroup.Default {
				bxCli.PowerVSResourceGroup = *resourceGroup.Name
				found = true
				break
			}
		}

		if !found {
			return nil, fmt.Errorf("no default resource group found")
		}
	}

	return client, nil
}

func (c *Client) loadSDKServices() error {
	servicesToLoad := []func() error{
		c.loadResourceManagementAPI,
		c.loadResourceControllerAPI,
		c.loadVPCV1API,
		c.loadDNSServicesAPI,
		c.loadTransitGatewayAPI,
	}

	// Call all the load functions.
	for _, fn := range servicesToLoad {
		if err := fn(); err != nil {
			return err
		}
	}

	return nil
}

// SetVPCServiceURLForRegion will set the VPC Service URL to a specific IBM Cloud Region, in order to access Region scoped resources
func (c *Client) SetVPCServiceURLForRegion(ctx context.Context, region string) error {
	regionOptions := c.vpcAPI.NewGetRegionOptions(region)
	vpcRegion, _, err := c.vpcAPI.GetRegionWithContext(ctx, regionOptions)
	if err != nil {
		return err
	}
	err = c.vpcAPI.SetServiceURL(fmt.Sprintf("%s/v1", *vpcRegion.Endpoint))
	if err != nil {
		return err
	}
	return nil
}

// GetDNSRecordsByName gets DNS records in specific Cloud Internet Services instance
// by its CRN, zone ID, and DNS record name.
func (c *Client) GetDNSRecordsByName(ctx context.Context, crnstr string, zoneID string, recordName string, publish PublishingStrategy) ([]DNSRecordResponse, error) {
	authenticator := &core.IamAuthenticator{
		ApiKey: c.APIKey,
	}
	dnsRecords := []DNSRecordResponse{}
	switch publish {
	case ExternalPublishingStrategy:
		// Set CIS DNS record service
		dnsService, err := dnsrecordsv1.NewDnsRecordsV1(&dnsrecordsv1.DnsRecordsV1Options{
			Authenticator:  authenticator,
			Crn:            core.StringPtr(crnstr),
			ZoneIdentifier: core.StringPtr(zoneID),
		})
		if err != nil {
			return nil, err
		}

		// Get CIS DNS records by name
		records, _, err := dnsService.ListAllDnsRecordsWithContext(ctx, &dnsrecordsv1.ListAllDnsRecordsOptions{
			Name: core.StringPtr(recordName),
		})
		if err != nil {
			return nil, fmt.Errorf("could not retrieve DNS records: %w", err)
		}
		for _, record := range records.Result {
			dnsRecords = append(dnsRecords, DNSRecordResponse{Name: *record.Name, Type: *record.Type})
		}
	case InternalPublishingStrategy:
		// Set DNS record service
		dnsService, err := resourcerecordsv1.NewResourceRecordsV1(&resourcerecordsv1.ResourceRecordsV1Options{
			Authenticator: authenticator,
		})
		if err != nil {
			return nil, err
		}

		dnsCRN, err := crn.Parse(crnstr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse DNSInstanceCRN: %w", err)
		}

		// Get DNS records by name
		records, _, err := dnsService.ListResourceRecords(&resourcerecordsv1.ListResourceRecordsOptions{
			InstanceID: &dnsCRN.ServiceInstance,
			DnszoneID:  &zoneID,
		})
		for _, record := range records.ResourceRecords {
			if *record.Name == recordName {
				dnsRecords = append(dnsRecords, DNSRecordResponse{Name: *record.Name, Type: *record.Type})
			}
		}
		if err != nil {
			return nil, fmt.Errorf("could not retrieve DNS records: %w", err)
		}
	}

	return dnsRecords, nil
}

// GetInstanceCRNByName finds the CRN of the instance with the specified name.
func (c *Client) GetInstanceCRNByName(ctx context.Context, name string, publish PublishingStrategy) (string, error) {

	zones, err := c.GetDNSZones(ctx, publish)
	if err != nil {
		return "", err
	}

	for _, z := range zones {
		if z.Name == name {
			return z.InstanceCRN, nil
		}
	}

	return "", fmt.Errorf("DNS zone %q not found", name)
}

// GetDNSZoneIDByName gets the CIS zone ID from its domain name.
func (c *Client) GetDNSZoneIDByName(ctx context.Context, name string, publish PublishingStrategy) (string, error) {

	zones, err := c.GetDNSZones(ctx, publish)
	if err != nil {
		return "", err
	}

	for _, z := range zones {
		if z.Name == name {
			return z.ID, nil
		}
	}

	return "", fmt.Errorf("DNS zone %q not found", name)
}

// GetDNSZones returns all of the active DNS zones managed by CIS.
func (c *Client) GetDNSZones(ctx context.Context, publish PublishingStrategy) ([]DNSZoneResponse, error) {
	_, cancel := context.WithTimeout(ctx, 1*time.Minute)
	defer cancel()

	options := c.controllerAPI.NewListResourceInstancesOptions()
	switch publish {
	case ExternalPublishingStrategy:
		options.SetResourceID(cisServiceID)
	case InternalPublishingStrategy:
		options.SetResourceID(dnsServiceID)
	default:
		return nil, fmt.Errorf("unknown publishing strategy")
	}

	listResourceInstancesResponse, _, err := c.controllerAPI.ListResourceInstances(options)
	if err != nil {
		return nil, fmt.Errorf("failed to get cis instance: %w", err)
	}

	var allZones []DNSZoneResponse
	for _, instance := range listResourceInstancesResponse.Resources {
		authenticator := &core.IamAuthenticator{
			ApiKey: c.APIKey,
		}

		switch publish {
		case ExternalPublishingStrategy:
			zonesService, err := zonesv1.NewZonesV1(&zonesv1.ZonesV1Options{
				Authenticator: authenticator,
				Crn:           instance.CRN,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to list DNS zones: %w", err)
			}

			options := zonesService.NewListZonesOptions()
			listZonesResponse, _, err := zonesService.ListZones(options)

			if listZonesResponse == nil {
				return nil, err
			}

			for _, zone := range listZonesResponse.Result {
				if *zone.Status == "active" {
					zoneStruct := DNSZoneResponse{
						Name:            *zone.Name,
						ID:              *zone.ID,
						InstanceCRN:     *instance.CRN,
						InstanceName:    *instance.Name,
						ResourceGroupID: *instance.ResourceGroupID,
					}
					allZones = append(allZones, zoneStruct)
				}
			}
		case InternalPublishingStrategy:
			dnsZonesService, err := dnszonesv1.NewDnsZonesV1(&dnszonesv1.DnsZonesV1Options{
				Authenticator: authenticator,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to list DNS zones: %w", err)
			}

			options := dnsZonesService.NewListDnszonesOptions(*instance.GUID)
			listZonesResponse, _, err := dnsZonesService.ListDnszones(options)

			if listZonesResponse == nil {
				return nil, err
			}

			for _, zone := range listZonesResponse.Dnszones {
				if *zone.State == "ACTIVE" {
					zoneStruct := DNSZoneResponse{
						Name:            *zone.Name,
						ID:              *zone.ID,
						InstanceCRN:     *instance.CRN,
						InstanceName:    *instance.Name,
						ResourceGroupID: *instance.ResourceGroupID,
					}
					allZones = append(allZones, zoneStruct)
				}
			}
		}
	}
	return allZones, nil
}

// GetDNSInstancePermittedNetworks gets the permitted VPC networks for a DNS Services instance
func (c *Client) GetDNSInstancePermittedNetworks(ctx context.Context, dnsID string, dnsZone string) ([]string, error) {
	_, cancel := context.WithTimeout(ctx, 1*time.Minute)
	defer cancel()

	listPermittedNetworksOptions := c.dnsServicesAPI.NewListPermittedNetworksOptions(dnsID, dnsZone)
	permittedNetworks, _, err := c.dnsServicesAPI.ListPermittedNetworksWithContext(ctx, listPermittedNetworksOptions)
	if err != nil {
		return nil, err
	}

	networks := []string{}
	for _, network := range permittedNetworks.PermittedNetworks {
		networks = append(networks, *network.PermittedNetwork.VpcCrn)
	}
	return networks, nil
}

func (c *Client) loadResourceManagementAPI() error {
	authenticator := &core.IamAuthenticator{
		ApiKey: c.APIKey,
	}
	options := &resourcemanagerv2.ResourceManagerV2Options{
		Authenticator: authenticator,
	}
	resourceManagerV2Service, err := resourcemanagerv2.NewResourceManagerV2(options)
	if err != nil {
		return err
	}
	c.managementAPI = resourceManagerV2Service
	return nil
}

func (c *Client) loadResourceControllerAPI() error {
	authenticator := &core.IamAuthenticator{
		ApiKey: c.APIKey,
	}
	options := &resourcecontrollerv2.ResourceControllerV2Options{
		Authenticator: authenticator,
	}
	resourceControllerV2Service, err := resourcecontrollerv2.NewResourceControllerV2(options)
	if err != nil {
		return err
	}
	c.controllerAPI = resourceControllerV2Service
	return nil
}

func (c *Client) loadVPCV1API() error {
	authenticator := &core.IamAuthenticator{
		ApiKey: c.APIKey,
	}
	vpcService, err := vpcv1.NewVpcV1(&vpcv1.VpcV1Options{
		Authenticator: authenticator,
	})
	if err != nil {
		return err
	}
	c.vpcAPI = vpcService
	return nil
}

func (c *Client) loadDNSServicesAPI() error {
	authenticator := &core.IamAuthenticator{
		ApiKey: c.APIKey,
	}
	dnsService, err := dnssvcsv1.NewDnsSvcsV1(&dnssvcsv1.DnsSvcsV1Options{
		Authenticator: authenticator,
	})
	if err != nil {
		return err
	}
	c.dnsServicesAPI = dnsService
	return nil
}

func (c *Client) loadTransitGatewayAPI() error {
	authenticator := &core.IamAuthenticator{
		ApiKey: c.APIKey,
	}
	versionDate := "2023-07-04"
	tgSvc, err := transitgatewayapisv1.NewTransitGatewayApisV1(&transitgatewayapisv1.TransitGatewayApisV1Options{
		Authenticator: authenticator,
		Version:       &versionDate,
	})
	if err != nil {
		return err
	}
	c.transitGatewayAPI = tgSvc
	return nil
}

// GetAPIKey returns the PowerVS API key
func (c *Client) GetAPIKey() string {
	return c.APIKey
}

// ListResourceGroups returns a list of resource groups.
func (c *Client) ListResourceGroups(ctx context.Context) (*resourcemanagerv2.ResourceGroupList, error) {
	listResourceGroupsOptions := c.managementAPI.NewListResourceGroupsOptions()
	listResourceGroupsOptions.AccountID = &c.BXCli.User.Account

	resourceGroups, _, err := c.managementAPI.ListResourceGroups(listResourceGroupsOptions)
	if err != nil {
		return nil, err
	}

	return resourceGroups, err
}

// Region describes resources associated with a region in Power VS.
// We're using a few items from the IBM Cloud VPC offering. The region names
// for VPC are different so another function of this is to correlate those.
type Region struct {
	Description string
	VPCRegion   string
	COSRegion   string
	Zones       []string
	SysTypes    []string
}

// Regions holds the regions for IBM Power VS, and descriptions used during the survey.
var Regions = map[string]Region{
	"dal": {
		Description: "Dallas, USA",
		VPCRegion:   "us-south",
		COSRegion:   "us-south",
		Zones:       []string{"dal10", "dal12"},
		SysTypes:    []string{"s922", "e980"},
	},
	"eu-de": {
		Description: "Frankfurt, Germany",
		VPCRegion:   "eu-de",
		COSRegion:   "eu-de",
		Zones:       []string{"eu-de-1", "eu-de-2"},
		SysTypes:    []string{"s922", "e980"},
	},
	"mad": {
		Description: "Madrid, Spain",
		VPCRegion:   "eu-es",
		COSRegion:   "eu-de", // @HACK - PowerVS says COS not supported in this region
		Zones:       []string{"mad02", "mad04"},
		SysTypes:    []string{"s1022"},
	},
	"sao": {
		Description: "São Paulo, Brazil",
		VPCRegion:   "br-sao",
		COSRegion:   "br-sao",
		Zones:       []string{"sao04"},
		SysTypes:    []string{"s922", "e980"},
	},
	"wdc": {
		Description: "Washington DC, USA",
		VPCRegion:   "us-east",
		COSRegion:   "us-east",
		Zones:       []string{"wdc06", "wdc07"},
		SysTypes:    []string{"s922", "e980"},
	},
}

func knownRegions() map[string]string {

	regions := make(map[string]string)

	for name, region := range Regions {
		regions[name] = region.Description
	}
	return regions
}

func knownZones(region string) []string {
	return Regions[region].Zones
}

// GetRegion prompts the user to select a region and returns that region.
func GetRegion(defaultRegion string) (string, error) {
	regions := knownRegions()

	longRegions := make([]string, 0, len(regions))
	shortRegions := make([]string, 0, len(regions))
	for id, location := range regions {
		longRegions = append(longRegions, fmt.Sprintf("%s (%s)", id, location))
		shortRegions = append(shortRegions, id)
	}
	sort.Strings(longRegions)
	sort.Strings(shortRegions)

	var regionTransform survey.Transformer = func(ans interface{}) interface{} {
		switch v := ans.(type) {
		case aacore.OptionAnswer:
			return aacore.OptionAnswer{Value: strings.SplitN(v.Value, " ", 2)[0], Index: v.Index}
		case string:
			return strings.SplitN(v, " ", 2)[0]
		}
		return ""
	}

	var region string
	li := sort.SearchStrings(shortRegions, defaultRegion)
	if li == len(shortRegions) || shortRegions[li] != defaultRegion {
		defaultRegion = ""
	} else {
		defaultRegion = longRegions[li]
	}

	err := survey.Ask([]*survey.Question{
		{
			Prompt: &survey.Select{
				Message: "Region",
				Help:    "The Power VS region to be used for installation.",
				Default: defaultRegion,
				Options: longRegions,
			},
			Validate: survey.ComposeValidators(survey.Required, func(ans interface{}) error {
				choice := regionTransform(ans).(aacore.OptionAnswer).Value
				i := sort.SearchStrings(shortRegions, choice)
				if i == len(shortRegions) || shortRegions[i] != choice {
					return fmt.Errorf("invalid region %q", choice)
				}
				return nil
			}),
			Transform: regionTransform,
		},
	}, &region)
	if err != nil {
		return "", err
	}

	return region, nil
}

// GetZone prompts the user for a zone given a zone.
func GetZone(region string, defaultZone string) (string, error) {
	zones := knownZones(region)
	if len(defaultZone) == 0 {
		defaultZone = zones[0]
	}

	var zoneTransform survey.Transformer = func(ans interface{}) interface{} {
		switch v := ans.(type) {
		case aacore.OptionAnswer:
			return aacore.OptionAnswer{Value: strings.SplitN(v.Value, " ", 2)[0], Index: v.Index}
		case string:
			return strings.SplitN(v, " ", 2)[0]
		}
		return ""
	}

	var zone string
	err := survey.Ask([]*survey.Question{
		{
			Prompt: &survey.Select{
				Message: "Zone",
				Help:    "The Power VS zone within the region to be used for installation.",
				Default: fmt.Sprintf("%s", defaultZone),
				Options: zones,
			},
			Validate: survey.ComposeValidators(survey.Required, func(ans interface{}) error {
				choice := zoneTransform(ans).(aacore.OptionAnswer).Value
				i := sort.SearchStrings(zones, choice)
				if i == len(zones) || zones[i] != choice {
					return fmt.Errorf("invalid zone %q", choice)
				}
				return nil
			}),
			Transform: zoneTransform,
		},
	}, &zone)
	if err != nil {
		return "", err
	}
	return zone, err
}
