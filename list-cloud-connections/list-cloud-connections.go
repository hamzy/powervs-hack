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

// How to run:
// (export IBMCLOUD_API_KEY="blah"; if ! ibmcloud iam oauth-tokens 1>/dev/null 2>&1; then ibmcloud login --apikey "${IBMCLOUD_API_KEY}"; fi; go run list-jobs.go -apiKey "${IBMCLOUD_API_KEY}" -search '.*rdr-hamzy-.*' -serviceName powervs-ipi-lon04 -shouldDebug false -shouldDelete false)

package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/IBM-Cloud/bluemix-go"
	"github.com/IBM-Cloud/bluemix-go/api/resource/resourcev2/controllerv2"
	"github.com/IBM-Cloud/bluemix-go/authentication"
	"github.com/IBM-Cloud/bluemix-go/http"
	"github.com/IBM-Cloud/bluemix-go/rest"
	bxsession "github.com/IBM-Cloud/bluemix-go/session"
	"github.com/IBM-Cloud/power-go-client/clients/instance"
	"github.com/IBM-Cloud/power-go-client/ibmpisession"
	"github.com/IBM-Cloud/power-go-client/power/models"
	"github.com/IBM/go-sdk-core/v5/core"
	"log"
	gohttp "net/http"
	"regexp"
	"strings"
	"time"
)

var shouldDebug = false
var shouldDelete = false

// $ ibmcloud catalog service cloud-object-storage --output json | jq -r '.[].id'
// dff97f5c-bc5e-4455-b470-411c3edbe49c
const cosResourceID = "dff97f5c-bc5e-4455-b470-411c3edbe49c"

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

func listCloudConnections (rSearch *regexp.Regexp, cloudConnectionClient *instance.IBMPICloudConnectionClient, jobClient *instance.IBMPIJobClient, serviceGuid string) {
	var (
		ctx context.Context

		// https://github.com/IBM-Cloud/power-go-client/blob/v1.0.88/power/models/cloud_connections.go#L20-L25
		cloudConnections *models.CloudConnections

		// https://github.com/IBM-Cloud/power-go-client/blob/v1.0.88/power/models/cloud_connection.go#L20-L71
		cloudConnection          *models.CloudConnection
		cloudConnectionUpdateNew *models.CloudConnection

		// https://github.com/IBM-Cloud/power-go-client/blob/v1.0.88/power/models/job_reference.go#L18-L27
		jobReference *models.JobReference

		err error

		cloudConnectionID string

		// https://github.com/IBM-Cloud/power-go-client/blob/v1.0.88/power/models/cloud_connection_endpoint_v_p_c.go#L19-L26
		endpointVpc       *models.CloudConnectionEndpointVPC
		endpointUpdateVpc models.CloudConnectionEndpointVPC

		// https://github.com/IBM-Cloud/power-go-client/blob/v1.0.88/power/models/cloud_connection_v_p_c.go#L18-L26
		Vpc *models.CloudConnectionVPC

		// https://github.com/IBM-Cloud/power-go-client/blob/v1.0.88/power/models/cloud_connection_update.go#L20
		cloudConnectionUpdate models.CloudConnectionUpdate

		// https://github.com/IBM-Cloud/power-go-client/blob/v1.0.88/power/models/job.go#L18
		job *models.Job

		foundOne       bool = false
		foundVpc       bool = false
	)

	ctx, _ = context.WithTimeout(context.Background(), 5 * time.Minute)

	if shouldDebug {
		log.Printf("Listing Cloud Connections")
	}

	select {
	case <-ctx.Done():
		if shouldDebug {
			log.Printf("listCloudConnections: case <-ctx.Done()")
		}
		return // we're cancelled, abort
	default:
	}

	cloudConnections, err = cloudConnectionClient.GetAll()
	if err != nil {
		log.Fatalf("Failed to list cloud connections: %v", err)
	}

	for _, cloudConnection = range cloudConnections.CloudConnections {
		select {
		case <-ctx.Done():
			if shouldDebug {
				log.Printf("listCloudConnections: case <-ctx.Done()")
			}
			return // we're cancelled, abort
		default:
		}

		if !rSearch.MatchString(*cloudConnection.Name) {
			// Skip this one!
			continue
		}

		foundOne = true

		if shouldDebug {
			log.Printf("listCloudConnections: FOUND: %s (%s)", *cloudConnection.Name, *cloudConnection.CloudConnectionID)
		}

		cloudConnectionID = *cloudConnection.CloudConnectionID

		cloudConnection, err = cloudConnectionClient.Get(cloudConnectionID)
		if err != nil {
			log.Fatalf("Failed to get cloud connection %s: %v", cloudConnectionID, err)
		}

		endpointVpc = cloudConnection.Vpc

		if shouldDebug {
			log.Printf("listCloudConnections: endpointVpc = %+v\n", endpointVpc)
		}

		foundVpc = false
		for _, Vpc = range endpointVpc.Vpcs {
			if shouldDebug {
				log.Printf("listCloudConnections: Vpc = %+v\n", Vpc)
			}
			if rSearch.MatchString(Vpc.Name) {
				foundVpc = true
			}
		}
		if shouldDebug {
			log.Printf("listCloudConnections: foundVpc = %v\n", foundVpc)
		}
		if !foundVpc {
			continue
		}

		// https://github.com/IBM-Cloud/power-go-client/blob/v1.0.88/power/models/cloud_connection_v_p_c.go#L18
		var vpcsUpdate []*models.CloudConnectionVPC

		endpointUpdateVpc.Enabled = cloudConnection.Vpc.Enabled

		for _, Vpc = range endpointVpc.Vpcs {
			if !rSearch.MatchString(Vpc.Name) {
				vpcsUpdate = append (vpcsUpdate, Vpc)
			}
		}

		endpointUpdateVpc.Vpcs = vpcsUpdate

		cloudConnectionUpdate.Vpc = &endpointUpdateVpc

		if shouldDebug {
			var vpcsStrings []string

			for _, Vpc = range vpcsUpdate {
				vpcsStrings = append (vpcsStrings, Vpc.Name)
			}
			log.Printf("listCloudConnections: vpcsUpdate = %v\n", vpcsStrings)
			log.Printf("listCloudConnections: endpointUpdateVpc = %+v\n", endpointUpdateVpc)
		}

		if !shouldDelete {
			if shouldDebug {
				log.Printf("Skipping updating the cloud connection %q since shouldDelete is false", *cloudConnection.Name)
			}
			continue
		}

		cloudConnectionUpdateNew, jobReference, err = cloudConnectionClient.Update(*cloudConnection.CloudConnectionID, &cloudConnectionUpdate)
		if err != nil {
			log.Fatalf("Failed to update cloud connection %v", err)
		}

		if shouldDebug {
			log.Printf("listCloudConnections: cloudConnectionUpdateNew = %+v\n", cloudConnectionUpdateNew)
			log.Printf("listCloudConnections: jobReference = %+v\n", jobReference)
		}

		for !timeout(ctx) {
			select {
			case <-ctx.Done():
				if shouldDebug {
					log.Printf("listCloudConnections: case <-ctx.Done()")
				}
				return // we're cancelled, abort
			default:
			}

			job, err = jobClient.Get(*jobReference.ID)
			if err != nil {
				log.Fatalf("Failed to get job %v: %v", *jobReference.ID, err)
			}

			if shouldDebug {
				log.Printf("listCloudConnections: job.ID = %v\n", *job.ID)
				log.Printf("listCloudConnections: job.Status.State = %v\n", *job.Status.State)
			}

			if *job.Status.State == "completed" {
				break
			}
		}
	}

	if shouldDebug {
		if !foundOne {
			log.Printf("listCloudConnections: NO matching cloud connections")
			for _, cloudConnection = range cloudConnections.CloudConnections {
				log.Printf("listCloudConnections: only found cloud connection: %s", *cloudConnection.Name)
			}
		}
	}
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

	region, err:= GetRegion(serviceInstance.RegionID)
	if err != nil {
		return nil, "", fmt.Errorf("Error GetRegion: %v", err)
	}

	var authenticator core.Authenticator = &core.IamAuthenticator{
		ApiKey:	*ptrApiKey,
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
	if shouldDebug {
		log.Printf("piSession = %v\n", piSession)
	}

	return piSession, serviceGuid, nil

}

func main() {

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
		log.Fatal("Error: No API key set, use --apiKey")
	}

	if *ptrSearch == "" {
		log.Fatal("Error: No search term set, use --search")
	}

	if *ptrServiceName == "" {
		log.Fatal("Error: No cloud service set, use --serviceName")
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

	var piSession *ibmpisession.IBMPISession
	var serviceGuid string
	var err error

	piSession, serviceGuid, err = createPiSession(ptrApiKey, ptrServiceName)
	if err != nil {
		log.Fatal("Error createPiSession: %v\n", err)
	}

	var cloudConnectionClient *instance.IBMPICloudConnectionClient

	cloudConnectionClient = instance.NewIBMPICloudConnectionClient(context.Background(), piSession, serviceGuid)
	if shouldDebug { log.Printf("cloudConnectionClient = %v\n", cloudConnectionClient) }

        var jobClient *instance.IBMPIJobClient

	jobClient = instance.NewIBMPIJobClient(context.Background(), piSession, serviceGuid)
	if shouldDebug { log.Printf("jobClient = %v\n", jobClient) }

	listCloudConnections(rSearch, cloudConnectionClient, jobClient, serviceGuid)
}
