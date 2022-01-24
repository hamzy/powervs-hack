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

// https://github.com/openshift/installer/commit/b5c77e12acc6841d08378a8a5d45ea0f6aa1dd93

// package vpc1
// https://raw.githubusercontent.com/IBM/vpc-go-sdk/master/vpcv1/vpc_v1.go

// package resourcecontrollerv2
// https://raw.githubusercontent.com/IBM/platform-services-go-sdk/main/resourcecontrollerv2/resource_controller_v2.go

// package resourcemanagerv2
// https://raw.githubusercontent.com/IBM/platform-services-go-sdk/main/resourcemanagerv2/resource_manager_v2.go

// package dnsrecordsv1
// https://raw.githubusercontent.com/IBM/networking-go-sdk/master/dnsrecordsv1/dns_records_v1.go

package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/networking-go-sdk/dnsrecordsv1"
	"github.com/IBM/networking-go-sdk/zonesv1"
	"github.com/IBM/platform-services-go-sdk/resourcecontrollerv2"
	"github.com/IBM/platform-services-go-sdk/resourcemanagerv2"
	"github.com/IBM/vpc-go-sdk/vpcv1"
	"github.com/IBM-Cloud/bluemix-go"
	"github.com/IBM-Cloud/bluemix-go/api/resource/resourcev2/controllerv2"
	"github.com/IBM-Cloud/bluemix-go/authentication"
	"github.com/IBM-Cloud/bluemix-go/http"
	"github.com/IBM-Cloud/bluemix-go/rest"
	bxsession "github.com/IBM-Cloud/bluemix-go/session"
	"github.com/IBM-Cloud/power-go-client/clients/instance"
	"github.com/IBM-Cloud/power-go-client/helpers"
	"github.com/IBM-Cloud/power-go-client/ibmpisession"
	"github.com/IBM-Cloud/power-go-client/power/client/p_cloud_tenants_ssh_keys"
	"github.com/IBM-Cloud/power-go-client/power/models"
	"log"
	gohttp "net/http"
	"net/url"
	"regexp"
	"reflect"
	"strings"
	"time"
)

var shouldDebug = false
var shouldDelete = false

// $ ibmcloud catalog service cloud-object-storage --output json | jq -r '.[].id'
// dff97f5c-bc5e-4455-b470-411c3edbe49c
const cosResourceID = "dff97f5c-bc5e-4455-b470-411c3edbe49c"

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

func createPiSession (ptrApiKey *string, ptrServiceName *string) (*ibmpisession.IBMPISession, string, error) {

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
	if shouldDebug { log.Printf("bxSession = %v\n", bxSession) }

	tokenRefresher, err := authentication.NewIAMAuthRepository(bxSession.Config, &rest.Client{
		DefaultHeader: gohttp.Header{
			"User-Agent": []string{http.UserAgent()},
		},
	})
	if err != nil {
		return nil, "", fmt.Errorf("Error authentication.NewIAMAuthRepository: %v", err)
	}
	if shouldDebug { log.Printf("tokenRefresher = %v\n", tokenRefresher) }
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
	if shouldDebug { log.Printf("ctrlv2 = %v\n", ctrlv2) }

	resourceClientV2 := ctrlv2.ResourceServiceInstanceV2()
	if err != nil {
		return nil, "", fmt.Errorf("Error ctrlv2.ResourceServiceInstanceV2: %v", err)
	}
	if shouldDebug { log.Printf("resourceClientV2 = %v\n", resourceClientV2) }

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

	serviceInstance, err := resourceClientV2.GetInstance(serviceGuid)
	if err != nil {
		return nil, "", fmt.Errorf("Error resourceClientV2.GetInstance: %v", err)
	}
	if shouldDebug { log.Printf("serviceInstance = %v\n", serviceInstance) }

	region, err:= GetRegion(serviceInstance.RegionID)
	if err != nil {
		return nil, "", fmt.Errorf("Error GetRegion: %v", err)
	}

	var piSession *ibmpisession.IBMPISession

	piSession, err = ibmpisession.New(bxSession.Config.IAMAccessToken,
		region,
		false,
		60*time.Minute,
		user.Account,
		serviceInstance.RegionID)
	if err != nil {
		return nil, "", fmt.Errorf("Error ibmpisession.New: %v", err)
	}
	if shouldDebug { log.Printf("piSession = %v\n", piSession) }

	return piSession, serviceGuid, nil

}

// $ ibmcloud is load-balancers --json | jq -r '.[] | select (.name|test("rdr-hamzy.*")) | "\(.name) - \(.id)"'

func cleanupLoadBalancers (rSearch *regexp.Regexp, vpcService *vpcv1.VpcV1) {

	loadBalancers, detailedResponse, err := vpcService.ListLoadBalancers(&vpcv1.ListLoadBalancersOptions{})
	if err != nil {
		log.Fatalf("Failed to list loadBalancers: %v and the response is: %s", err, detailedResponse)
	}

	for _, loadBalancer := range loadBalancers.LoadBalancers {
		if rSearch.MatchString(*loadBalancer.Name) {
			log.Printf("Found: loadBalancer: %s\n", *loadBalancer.Name)

			if !shouldDelete {
				continue
			}

			deleteVpcOptions := &vpcv1.DeleteLoadBalancerOptions{}
			deleteVpcOptions.SetID(*loadBalancer.ID)

			response, err := vpcService.DeleteLoadBalancer(deleteVpcOptions)
			if shouldDebug { log.Printf("DeleteLoadBalancer: response = %v\n", response.StatusCode) }
			if response.StatusCode != gohttp.StatusNoContent {
				log.Fatalf("Failed to delete id: %s and the response is: %v", *loadBalancer.ID, response)
			}
			if err != nil {
				log.Fatalf("Failed to delete id: %s and the response is: %v", *loadBalancer.ID, err)
			}

			options := &vpcv1.GetLoadBalancerOptions{}
			options.SetID(*loadBalancer.ID)

			var deletePending bool = true

			for deletePending {
				lb, response, err := vpcService.GetLoadBalancer(options)
				if shouldDebug { log.Printf("GetLoadBalancer: response = %v\n", response.StatusCode) }
				if response.StatusCode == gohttp.StatusNotFound {
					break
				}

				if err != nil {
					log.Fatalf("Failed to get id: %s and the response is: %v", *loadBalancer.ID, err)
				}

				if shouldDebug {
					log.Printf("lb.Name: %s\n", *lb.Name)
					log.Printf("lb.OperatingStatus: %s\n", *lb.OperatingStatus)
					log.Printf("lb.ProvisioningStatus: %s\n", *lb.ProvisioningStatus)
				}

				deletePending = response.StatusCode == gohttp.StatusOK
				deletePending = deletePending && (*lb.OperatingStatus == "offline")
				deletePending = deletePending && (*lb.ProvisioningStatus == "delete_pending")
			}

			log.Printf("Deleted %s\n", *loadBalancer.Name)
		}
	}

}

// $ ibmcloud is floating-ips --output json  | jq -r '.[] | select (.name|test("rdr-hamzy.*")) | .name'

func cleanupISFloatingIPs (rSearch *regexp.Regexp, vpcService *vpcv1.VpcV1) {

	listFloatingIPsOptions := vpcService.NewListFloatingIpsOptions()

	floatingIPs, detailedResponse, err := vpcService.ListFloatingIps(listFloatingIPsOptions)
	if err != nil {
		log.Fatalf("Failed to list floatingIPs: %v and the response is: %s", err, detailedResponse)
	}

	for _, floatingIP := range floatingIPs.FloatingIps {
		if rSearch.MatchString(*floatingIP.Name) {
			if *floatingIP.Status == vpcv1.FloatingIPStatusDeletingConst {
				continue
			}
			if (*floatingIP.Status == vpcv1.FloatingIPStatusFailedConst) ||
			   (*floatingIP.Status == vpcv1.FloatingIPStatusPendingConst) {
				log.Printf("WARNING: Found: floatingIP: %s in %s state\n", *floatingIP.Name, *floatingIP.Status)
				continue
			}

			// This floating IP could have already disappeared underneath us!
			getFloatingIPOptions := vpcService.NewGetFloatingIPOptions(*floatingIP.ID)
			_, detailedResponse, _ = vpcService.GetFloatingIP(getFloatingIPOptions)
			if detailedResponse.StatusCode == gohttp.StatusNotFound {
				if shouldDebug { log.Printf("Has already disappeared!\n") }
				continue
			}

			log.Printf("Found: floatingIP: %s\n", *floatingIP.Name)

			if !shouldDelete {
				continue
			}

			deleteFloatingIPOptions := &vpcv1.DeleteFloatingIPOptions{}
			deleteFloatingIPOptions.SetID(*floatingIP.ID)

			response, err := vpcService.DeleteFloatingIP(deleteFloatingIPOptions)
			if shouldDebug { log.Printf("DeleteFloatingIP: response = %v\n", response.StatusCode) }
			if err != nil {
				log.Fatalf("Failed to delete id: %s and the response is: %v", *floatingIP.ID, err)
			}

			log.Printf("Deleted %s\n", *floatingIP.Name)
		}
	}

}

// $ ibmcloud is public-gateways --output json  | jq -r '.[] | select (.name|test("rdr-hamzy.*")) | .name'

func cleanupISPublicGateways (rSearch *regexp.Regexp, vpcService *vpcv1.VpcV1) {

	listPublicGatewaysOptions := vpcService.NewListPublicGatewaysOptions()

	publicGateways, detailedResponse, err := vpcService.ListPublicGateways(listPublicGatewaysOptions)
	if err != nil {
		log.Fatalf("Failed to list publicGateways: %v and the response is: %s", err, detailedResponse)
	}

	for _, publicGateway := range publicGateways.PublicGateways {
		if rSearch.MatchString(*publicGateway.Name) {
			log.Printf("Found: publicGateway: %s\n", *publicGateway.Name)

			if !shouldDelete {
				continue
			}

			deletePublicGatewayOptions := &vpcv1.DeletePublicGatewayOptions{}
			deletePublicGatewayOptions.SetID(*publicGateway.ID)

			response, err := vpcService.DeletePublicGateway(deletePublicGatewayOptions)
			if shouldDebug { log.Printf("DeletePublicGateway: response = %v\n", response.StatusCode) }
			if err != nil {
				log.Fatalf("Failed to delete id: %s and the response is: %v", *publicGateway.ID, err)
			}

			log.Printf("Deleted %s\n", *publicGateway.Name)
		}
	}

}

// $ ibmcloud is subnets --output json  | jq -r '.[] | select (.name|test("rdr-hamzy.*")) | .name'

func cleanupISSubnets (rSearch *regexp.Regexp, vpcService *vpcv1.VpcV1) {

	listSubnetsOptions := vpcService.NewListSubnetsOptions()

	subnets, detailedResponse, err := vpcService.ListSubnets(listSubnetsOptions)
	if err != nil {
		log.Fatalf("Failed to list subnets: %v and the response is: %s", err, detailedResponse)
	}

	for _, subnet := range subnets.Subnets {
		if rSearch.MatchString(*subnet.Name) {
			log.Printf("Found: subnet: %s\n", *subnet.Name)

			if !shouldDelete {
				continue
			}

			deleteSubnetOptions := &vpcv1.DeleteSubnetOptions{}
			deleteSubnetOptions.SetID(*subnet.ID)

			response, err := vpcService.DeleteSubnet(deleteSubnetOptions)
			if shouldDebug { log.Printf("DeleteSubnet: response = %v\n", response.StatusCode) }
			if response.StatusCode != gohttp.StatusNoContent {
				log.Fatalf("Failed to delete id: %s and the response is: %v", *subnet.ID, response)
			}
			if err != nil {
				log.Fatalf("Failed to delete id: %s and the response is: %v", *subnet.ID, err)
			}

			log.Printf("Deleted %s\n", *subnet.Name)

		}
	}

}

// $ ibmcloud is vpcs --output json | jq -r '.[] | select (.name|test("rdr-hamzy.*")) | .name'

func cleanupISVPCs (rSearch *regexp.Regexp, vpcService *vpcv1.VpcV1) {

	listVpcsOptions := vpcService.NewListVpcsOptions();

	vpcs, detailedResponse, err := vpcService.ListVpcs(listVpcsOptions)
	if err != nil {
		log.Fatalf("Failed to list vpcs: %v and the response is: %s", err, detailedResponse)
	}

	for _, vpc := range vpcs.Vpcs {
		if rSearch.MatchString(*vpc.Name) {
			log.Printf("Found: vpc: %s\n", *vpc.Name)

			if !shouldDelete {
				continue
			}

			deleteVpcOptions := &vpcv1.DeleteVPCOptions{}
			deleteVpcOptions.SetID(*vpc.ID)

			response, err := vpcService.DeleteVPC(deleteVpcOptions)
			if shouldDebug { log.Printf("DeleteVPC: response = %v\n", response.StatusCode) }
			if response.StatusCode != gohttp.StatusNoContent {
				log.Fatalf("Failed to delete id: %s and the response is: %v", *vpc.ID, response)
			}
			if err != nil {
				log.Fatalf("Failed to delete id: %s and the response is: %v", *vpc.ID, err)
			}

			log.Printf("Deleted %s\n", *vpc.Name)

		}
	}

}

// ibmcloud resource service-instances --output JSON --service-name cloud-object-storage | jq -r '.[] | select(.name|test("rdr-hamzy.*")) | .name'

func cleanupServiceInstances (rSearch *regexp.Regexp, controllerSvc *resourcecontrollerv2.ResourceControllerV2, ctx context.Context) {

	options := controllerSvc.NewListResourceInstancesOptions()
	options.SetResourceID(cosResourceID)
	options.SetType("service_instance")

	resources, _, err := controllerSvc.ListResourceInstancesWithContext(ctx, options)
	if err != nil {
		log.Fatalf("Failed to list COS instances: %v", err)
	}

	for _, resource := range resources.Resources {
		if rSearch.MatchString(*resource.Name) {
			log.Printf("Found: serviceInstance: %s\n", *resource.Name)

			if !shouldDelete {
				continue
			}

			deleteResourceInstanceOptions := controllerSvc.NewDeleteResourceInstanceOptions(
				*resource.GUID,
			)
			deleteResourceInstanceOptions.SetRecursive(true)

			response, err := controllerSvc.DeleteResourceInstance(deleteResourceInstanceOptions)
			if err != nil {
				log.Fatalf("Failed to delete GUID: %s, %v", *resource.GUID, err)
			}
			if shouldDebug { log.Printf("DeleteResourceInstance: response = %v\n", response.StatusCode) }
			if (response.StatusCode != gohttp.StatusAccepted) && (response.StatusCode != gohttp.StatusNoContent) {
				log.Fatalf("Bad StatusCode!\n")
			}

			log.Printf("Deleted %s\n", *resource.Name)
		}
	}

}

// $ ibmcloud is security-groups --json | jq -r '.[] | select (.name|test("rdr-hamzy.*")) | [ .name, .id ]'

func cleanupSecurityGroups (rSearch *regexp.Regexp, vpcService *vpcv1.VpcV1, ctx context.Context) {

	var start string = ""

	securityGroupsOptions := vpcService.NewListSecurityGroupsOptions()
	securityGroupsOptions.Start = &start

	for {

		if securityGroupsOptions.Start == nil {
			if shouldDebug { log.Printf("Start = nil\n") }
		} else {
			if *securityGroupsOptions.Start == "" {
				securityGroupsOptions.Start = nil
				if shouldDebug { log.Printf("Start = nil (2)\n") }
			} else {
				if shouldDebug { log.Printf("Start = %v\n", *securityGroupsOptions.Start) }
			}
		}

		securityGroups, detailedResponse, err := vpcService.ListSecurityGroups(securityGroupsOptions)
		if err != nil {
			log.Fatalf("Failed to list securityGroups: %v and the response is: %s", err, detailedResponse)
		}

		if securityGroups.Next == nil {
			if shouldDebug { log.Printf("Next = nil\n") }
		} else {
			if shouldDebug { log.Printf("Next = %v\n", *securityGroups.Next) }
			start = GetNext(securityGroups.Next)
			securityGroupsOptions.Start = &start
			if shouldDebug { log.Printf("start = %v\n", start) }
		}

		for _, securityGroup := range securityGroups.SecurityGroups {

			if rSearch.MatchString(*securityGroup.Name) {
				log.Printf("Found: securityGroup: %s\n", *securityGroup.Name)

				if !shouldDelete {
					continue
				}

				deleteSecurityGroupOptions := vpcService.NewDeleteSecurityGroupOptions(*securityGroup.ID)

				response, err := vpcService.DeleteSecurityGroupWithContext(ctx, deleteSecurityGroupOptions)
				if err != nil {
					log.Fatalf("Failed to delete ID: %s, %v", *securityGroup.ID, err)
				}
				if shouldDebug { log.Printf("DeleteSecurityGroupWithContext: response = %v\n", response.StatusCode) }

				log.Printf("Deleted %s\n", *securityGroup.Name)
			}

		}

		if start == "" {
			break
		}
	}

}

// $ export SERVICE_ID=$(ibmcloud pi service-list --json | jq -r '.[] | select (.Name|test("powervs-ipi-lon04")) | .CRN')
// $ ibmcloud pi service-target ${SERVICE_ID}
// $ ibmcloud pi instances --json | jq -r '.Payload.pvmInstances[] | select (.serverName|test("rdr-hamzy.*")) | .serverName'

func cleanupInstances (rSearch *regexp.Regexp, piInstanceClient *instance.IBMPIInstanceClient, serviceGuid string) {

	var err error

	instances, err := piInstanceClient.GetAll(serviceGuid, 5*time.Minute)
	if err != nil {
		log.Fatal("Error piInstanceClient.GetAll: %v\n", err)
	}

	for _, instance := range instances.PvmInstances {
		// https://github.com/IBM-Cloud/power-go-client/blob/master/power/models/p_vm_instance.go
		if rSearch.MatchString(*instance.ServerName) {
			log.Printf("Found: instance: %s\n", *instance.ServerName)

			if !shouldDelete {
				continue
			}

			err = piInstanceClient.Delete(*instance.PvmInstanceID, serviceGuid, 5*time.Minute)
			if err != nil {
				log.Fatal("Error piInstanceClient.Delete: %v\n", err)
			}

			log.Printf("Deleted %s\n", *instance.ServerName)
		}
	}

}

// $ ibmcloud pi images --json | jq -r '.Payload.images[] | select (.name|test("rdr-hamzy.*")) | .name'

func cleanupImages (rSearch *regexp.Regexp, piImageClient *instance.IBMPIImageClient, serviceGuid string) {

	var err error

	images, err := piImageClient.GetAll(serviceGuid)
	if err != nil {
		log.Fatal("Error piImageClient.GetAll: %v\n", err)
	}

	for _, image := range images.Images {
		// https://github.com/IBM-Cloud/power-go-client/blob/master/power/models/image.go
		if rSearch.MatchString(*image.Name) {
			log.Printf("Found: image: %s\n", *image.Name)

			if !shouldDelete {
				continue
			}

			err = piImageClient.Delete(*image.ImageID, serviceGuid)
			if err != nil {
				log.Fatal("Error piImageClient.Delete: %v\n", err)
			}

			log.Printf("Deleted %s\n", *image.Name)
		}
	}

}

// $ export DNS_DOMAIN_ID=$(ibmcloud cis domains --output json | jq -r '.[].id')
// $ ibmcloud cis dns-records ${DNS_DOMAIN_ID} --output json | jq -r '.[] | select (.name|test("rdr-hamzy.*")) | .name'

func cleanupDNS (rSearch *regexp.Regexp, dnsRecordsService *dnsrecordsv1.DnsRecordsV1, ctx context.Context) {

	var perPage int64 = 20
	var page int64 = 1
	var match bool = false
	var moreData bool = true

	dnsRecordsOptions := dnsRecordsService.NewListAllDnsRecordsOptions()
	dnsRecordsOptions.PerPage = &perPage
	dnsRecordsOptions.Page = &page

	for moreData {

		dnsResources, detailedResponse, err := dnsRecordsService.ListAllDnsRecordsWithContext(ctx, dnsRecordsOptions)

		if err != nil {
			log.Fatalf("Failed to list DNS records: %v and the response is: %s", err, detailedResponse)
		}

		for _, record := range dnsResources.Result {

			match = false

			if rSearch.MatchString(*record.Name) {
				match = true
			}
			if rSearch.MatchString(*record.Content) {
				match = true
			}

			if match {
				log.Printf("Found: DNS name: %s\n", *record.Name)
				if shouldDebug {
					log.Printf("DNS content: %s\n", *record.Content)
				}

				if !shouldDelete {
					continue
				}

				deleteDNSOptions := dnsRecordsService.NewDeleteDnsRecordOptions(*record.ID)
				_, details, err := dnsRecordsService.DeleteDnsRecordWithContext(ctx, deleteDNSOptions)

				if err != nil {
					log.Printf("Failed to delete the DNS entry, err: %v\n", err)
					if details != nil {
						log.Printf("Failed to delete the DNS entry, details: %v\n", details)
					}
					return
				}
				if details == nil {
					log.Fatalf("Expecting details\n")
				}
				if shouldDebug { log.Printf("details = %v\n", details.StatusCode) }
				if details.StatusCode == gohttp.StatusOK {
					log.Printf("Deleted %s\n", *record.Name)
					continue
				}
				if details.StatusCode != gohttp.StatusNotFound {
					log.Fatalf ("Failed to delete DNS record")
				}
				log.Printf("Deleted %s\n", *record.Name)
			}

		}

		if shouldDebug {
			log.Printf("PerPage = %v\n", *dnsResources.ResultInfo.PerPage)
			log.Printf("Page = %v\n", *dnsResources.ResultInfo.Page)
			log.Printf("Count = %v\n", *dnsResources.ResultInfo.Count)
		}

		// WRONG!
		//moreData = (*dnsResources.ResultInfo.PerPage * *dnsResources.ResultInfo.Page) < *dnsResources.ResultInfo.Count
		moreData = *dnsResources.ResultInfo.PerPage == *dnsResources.ResultInfo.Count
		if shouldDebug { log.Printf("moreData = %v\n", moreData) }

		page++
	}

}

// $ ibmcloud pi keys --json | jq -r '.[] | select (.name|test("rdr-hamzy-test.*"))'

func cleanupSSHKeys (rSearch *regexp.Regexp, piSession *ibmpisession.IBMPISession, serviceGuid string) {

	var tenantId string = piSession.UserAccount
	var err error

	params := p_cloud_tenants_ssh_keys.NewPcloudTenantsSshkeysGetallParamsWithTimeout(helpers.PIGetTimeOut).WithTenantID(tenantId)
	resp, err := piSession.Power.PCloudTenantsSSHKeys.PcloudTenantsSshkeysGetall(params, ibmpisession.NewAuth(piSession, serviceGuid))
	if err != nil {
		log.Fatal("Error PcloudTenantsSshkeysGetall: %v\n", err)
	}

	var sshKeys *models.SSHKeys = resp.Payload

	for _, sshKey := range sshKeys.SSHKeys {
		if rSearch.MatchString(*sshKey.Name) {
			log.Printf("Found: sshKey: %v\n", *sshKey.Name)
			if shouldDebug { log.Printf("sshKey.SSHKey = %v\n", *sshKey.SSHKey) }

			if !shouldDelete {
				continue
			}

			params := p_cloud_tenants_ssh_keys.NewPcloudTenantsSshkeysDeleteParamsWithTimeout(helpers.PIDeleteTimeOut).WithTenantID(tenantId).WithSshkeyName(*sshKey.Name)
			_, err = piSession.Power.PCloudTenantsSSHKeys.PcloudTenantsSshkeysDelete(params, ibmpisession.NewAuth(piSession, serviceGuid))
			if err != nil {
				log.Fatal("Error NewPcloudTenantsSshkeysDeleteParamsWithTimeout: %v\n", err)
			}

			log.Printf("Deleted %s\n", *sshKey.Name)
		}
	}

}

// $ ibmcloud resource groups --output json | jq -r '.[] | select (.name|test("rdr-hamzy.*"))'

func cleanupISResourceGroups (rSearch *regexp.Regexp, mgmtService *resourcemanagerv2.ResourceManagerV2) {

	listResourceGroupsOptions := mgmtService.NewListResourceGroupsOptions()

	resourceGroups, detailedResponse, err := mgmtService.ListResourceGroups(listResourceGroupsOptions)
	if err != nil {
		log.Fatalf("Failed to list resourceGroups: %v and the response is: %s", err, detailedResponse)
	}

	for _, resourceGroup := range resourceGroups.Resources {
		if rSearch.MatchString(*resourceGroup.Name) {
			log.Printf("Found: resourceGroup: %s\n", *resourceGroup.Name)

			// @TBD
		}
	}

}

func cleanupReclamations (rSearch *regexp.Regexp, controllerSvc *resourcecontrollerv2.ResourceControllerV2, ctx context.Context) {
	var getReclamationOptions *resourcecontrollerv2.ListReclamationsOptions
	var reclamations *resourcecontrollerv2.ReclamationsList
	var reclamation resourcecontrollerv2.Reclamation
	var response *core.DetailedResponse
	var err error
	var getInstanceOptions *resourcecontrollerv2.GetResourceInstanceOptions
	var cosInstance *resourcecontrollerv2.ResourceInstance

	getReclamationOptions = controllerSvc.NewListReclamationsOptions()

	reclamations, response, err = controllerSvc.ListReclamationsWithContext(ctx, getReclamationOptions)
	if err != nil {
		log.Fatal("Error: ListReclamationsWithContext: %v, response = %v\n", err, response)
	}

	// ibmcloud resource reclamations --output json
	for _, reclamation = range reclamations.Resources {
		getInstanceOptions = controllerSvc.NewGetResourceInstanceOptions(*reclamation.ResourceInstanceID)

		cosInstance, response, err = controllerSvc.GetResourceInstanceWithContext(ctx, getInstanceOptions)
		if err != nil {
			log.Fatal("Error: GetResourceInstanceWithContext: %v, response = %v\n", err, response)
		}

		if rSearch.MatchString(*cosInstance.Name) {
			log.Printf("Found: reclamation for: %v / %v\n", *reclamation.ID, *cosInstance.Name)

			if shouldDebug {
				log.Printf("reclamation: %v / %v\n", *reclamation.ID, *reclamation.ResourceInstanceID)
				log.Printf("cosInstance: %v / %v", *cosInstance.Name, *cosInstance.GUID)
			}

			if !shouldDelete {
				continue
			}

			var reclamationActionOptions *resourcecontrollerv2.RunReclamationActionOptions

			reclamationActionOptions = controllerSvc.NewRunReclamationActionOptions(*reclamation.ID, "reclaim")

			_, response, err = controllerSvc.RunReclamationActionWithContext(ctx, reclamationActionOptions)
			if err != nil {
				log.Fatal("Error: RunReclamationActionWithContext: %v, response = %v\n", err, response)
			}
		}
	}
}

func test1 (rSearch *regexp.Regexp, controllerSvc *resourcecontrollerv2.ResourceControllerV2, ctx context.Context) {
	deleteResourceInstanceOptions := controllerSvc.NewDeleteResourceInstanceOptions(
		"rdr-hamzy-test-7nzrm-cos",
	)
	deleteResourceInstanceOptions.SetRecursive(true)
	response, err := controllerSvc.DeleteResourceInstance(deleteResourceInstanceOptions)
	log.Printf("%v", response)
	log.Printf("%v", err)
}

func test2 (rSearch *regexp.Regexp, controllerSvc *resourcecontrollerv2.ResourceControllerV2, ctx context.Context) {
}

func main() {

	// CLI parameters:
	var ptrApiKey *string
	var ptrSearch *string
	var ptrServiceName *string
	var ptrCISInstanceCRN *string
	var ptrDNSZone *string
	var ptrRegion *string
	var ptrShouldDebug *string
	var ptrShouldDelete *string

	ptrApiKey = flag.String("apiKey", "", "Your IBM Cloud API key")
	ptrSearch = flag.String("search", "", "The search string to match for deletes")
	ptrServiceName = flag.String("serviceName", "", "The cloud service to use")
	ptrCISInstanceCRN = flag.String("CISInstanceCRN", "", "ibmcloud cis instances --output json | jq -r '.[] | select (.name|test(\"powervs-ipi-cis\")) | .crn'")
	ptrDNSZone = flag.String("dnsZone", "", "The DNS zone Ex: scnl-ibm.com")
	ptrRegion = flag.String("region", "", "The region to use")
	ptrShouldDebug = flag.String("shouldDebug", "true", "Should output debug output")
	ptrShouldDelete = flag.String("shouldDelete", "false", "Should delete matching records")

	flag.Parse()

	if *ptrApiKey == "" {
		log.Fatal("Error: No API key set, use -apiKey")
	}
	if *ptrSearch == "" {
		log.Fatal("Error: No search term set, use -search")
	}
	if *ptrServiceName == "" {
		log.Fatal("Error: No cloud service set, use -serviceName")
	}
	if *ptrCISInstanceCRN == "" {
		log.Fatal("Error: No CISInstanceCRN set, use -CISInstanceCRN")
	}
	if *ptrDNSZone == "" {
		log.Fatal("Error: No DNS zone set, use -dnsZone")
	}
	if *ptrRegion == "" {
		log.Fatal("Error: No region set, use -region")
	}
	switch strings.ToLower(*ptrShouldDebug) {
	case "true":
		shouldDebug = true
	case "false":
		shouldDebug = false
	default:
		log.Fatal("Error: shouldDebug is not true/false (%s)\n", *ptrShouldDebug)
	}
	switch strings.ToLower(*ptrShouldDelete) {
	case "true":
		shouldDelete = true
	case "false":
		shouldDelete = false
	default:
		log.Fatal("Error: shouldDelete is not true/false (%s)\n", *ptrShouldDelete)
	}

	rSearch, _ := regexp.Compile(*ptrSearch)

	var ctx context.Context
	var vpcService *vpcv1.VpcV1
	var controllerSvc *resourcecontrollerv2.ResourceControllerV2
	var err error

	// Instantiate the service with an API key based IAM authenticator
	vpcService, err = vpcv1.NewVpcV1(&vpcv1.VpcV1Options{
		Authenticator: &core.IamAuthenticator{
			ApiKey: *ptrApiKey,
		},
		URL:  "https://" + *ptrRegion + ".iaas.cloud.ibm.com/v1",
	})
	if err != nil {
		log.Fatal("Error creating VPC Service.")
	}

	// Instantiate the service with an API key based IAM authenticator
	controllerSvc, err = resourcecontrollerv2.NewResourceControllerV2(&resourcecontrollerv2.ResourceControllerV2Options{
		Authenticator: &core.IamAuthenticator{
			ApiKey: *ptrApiKey,
		},
		ServiceName: "cloud-object-storage",
		URL: "https://resource-controller.cloud.ibm.com",
	})
	if err != nil {
		log.Fatal("Error creating ControllerV2 Service.")
	}

	var mgmtService *resourcemanagerv2.ResourceManagerV2

	// Instantiate the service with an API key based IAM authenticator
	mgmtService, err = resourcemanagerv2.NewResourceManagerV2(&resourcemanagerv2.ResourceManagerV2Options{
		Authenticator: &core.IamAuthenticator{
			ApiKey: *ptrApiKey,
		},
	})
	if err != nil {
		log.Fatal("Error creating ResourceManagerV2 Service.")
	}

	var zonesSvc *zonesv1.ZonesV1

	zonesSvc, err = zonesv1.NewZonesV1(&zonesv1.ZonesV1Options{
		Authenticator: &core.IamAuthenticator{
			ApiKey: *ptrApiKey,
		},
		Crn:           ptrCISInstanceCRN,
	})
	if err != nil {
		log.Fatalf("Failed to instantiate zonesSvc: %v", err)
	}

	// Get the Zone ID
	zoneOptions := zonesSvc.NewListZonesOptions()
	zoneResources, detailedResponse, err := zonesSvc.ListZonesWithContext(ctx, zoneOptions)
	if err != nil {
		log.Fatalf("Failed to list Zones: %v and the response is: %s", err, detailedResponse)
	}

	zoneID := ""
	for _, zone := range zoneResources.Result {
		if shouldDebug { log.Printf("Zone: %s\n", *zone.Name) }
		if strings.Contains(*ptrDNSZone, *zone.Name) {
			zoneID = *zone.ID
		}
	}

	var dnsRecordsService *dnsrecordsv1.DnsRecordsV1

	dnsRecordsService, err = dnsrecordsv1.NewDnsRecordsV1(&dnsrecordsv1.DnsRecordsV1Options{
		Authenticator: &core.IamAuthenticator{
			ApiKey: *ptrApiKey,
		},
		Crn:		ptrCISInstanceCRN,
		ZoneIdentifier:	&zoneID,
	})
	if err != nil {
		log.Fatalf("Failed to instantiate dnsRecordsService: %v", err)
	}

	var piSession *ibmpisession.IBMPISession
	var serviceGuid string

	piSession, serviceGuid, err = createPiSession(ptrApiKey, ptrServiceName)
	if err != nil {
		log.Fatal("Error createPiSession: %v\n", err)
	}

	var piInstanceClient *instance.IBMPIInstanceClient

	//piInstanceClient = instance.NewIBMPIInstanceClient(context.Background(), piSession, serviceGuid)
	piInstanceClient = instance.NewIBMPIInstanceClient(piSession, serviceGuid)
	if shouldDebug { log.Printf("piInstanceClient = %v\n", piInstanceClient) }

	var piImageClient *instance.IBMPIImageClient

	//piImageClient = instance.NewIBMPIImageClient(context.Background(), piSession, serviceGuid)
	piImageClient = instance.NewIBMPIImageClient(piSession, serviceGuid)
	if shouldDebug { log.Printf("piImageClient = %v\n", piImageClient) }

	cleanupServiceInstances(rSearch, controllerSvc, ctx)
	cleanupLoadBalancers(rSearch, vpcService)
	cleanupSecurityGroups(rSearch, vpcService, ctx)
	cleanupInstances(rSearch, piInstanceClient, serviceGuid)
	cleanupISPublicGateways (rSearch, vpcService)
	cleanupISFloatingIPs(rSearch, vpcService)
	cleanupISVPCs(rSearch, vpcService)
	cleanupISSubnets(rSearch, vpcService)
	cleanupImages(rSearch, piImageClient, serviceGuid)
	cleanupDNS(rSearch, dnsRecordsService, ctx)
	cleanupSSHKeys(rSearch, piSession, serviceGuid)
	cleanupISResourceGroups(rSearch, mgmtService)			// @TBD
	cleanupReclamations(rSearch, controllerSvc, ctx)

	return

	// In case the cleanupXXX functions get moved, this gets rid of compile errors
	log.Printf("%v", rSearch)
	log.Printf("%v", vpcService)
	log.Printf("%v", controllerSvc)
	log.Printf("%v", dnsRecordsService)
	log.Printf("%v", mgmtService)
}

// You can move all cleanupXXX functions here if you don't want to execute them for a new test
func main2() {
	var piInstanceClient *instance.IBMPIInstanceClient
	var piImageClient *instance.IBMPIImageClient
	var piSession *ibmpisession.IBMPISession
	var controllerSvc *resourcecontrollerv2.ResourceControllerV2
	var mgmtService *resourcemanagerv2.ResourceManagerV2
	var dnsRecordsService *dnsrecordsv1.DnsRecordsV1
	var vpcService *vpcv1.VpcV1
	var serviceGuid string
	var ctx context.Context
	var rSearch *regexp.Regexp

	return

	// In case the cleanupXXX functions get moved, this gets rid of compile errors
	rSearch, _ = regexp.Compile("")

	log.Printf("%v", piInstanceClient)
	log.Printf("%v", piImageClient)
	log.Printf("%v", piSession)
	log.Printf("%v", controllerSvc)
	log.Printf("%v", mgmtService)
	log.Printf("%v", dnsRecordsService)
	log.Printf("%v", vpcService)
	log.Printf("%v", serviceGuid)
	log.Printf("%v", ctx)
	log.Printf("%v", rSearch)
}
