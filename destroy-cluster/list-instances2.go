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

package main

import (
	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/vpc-go-sdk/vpcv1"
	"github.com/IBM-Cloud/bluemix-go/api/resource/resourcev2/controllerv2"
	"log"
	"os"
	"regexp"
)

func listInstances (rSearch *regexp.Regexp, vpcService *vpcv1.VpcV1) {

	options := &vpcv1.ListInstancesOptions{}

	instances, detailedResponse, err := vpcService.ListInstances(options)
	if err != nil {
		log.Fatalf("Failed to list instances: %v and the response is: %s", err, detailedResponse)
	}

	for _, instance := range instances.Instances {
		log.Printf("instance: %s\n", *instance.Name)
		if rSearch.MatchString(*instance.Name) {
			log.Printf("found instance: %s\n", *instance.Name)
		}
	}
}

func main() {

	apiKey := os.Getenv("IBMCLOUD_API_KEY")
	if apiKey == "" {
		log.Fatal("No API key set")
	}

	var region string = "eu-gb"
	var search string = ".*rdr-hamzy-test.*"

	rSearch, _ := regexp.Compile(search)

	var vpcService *vpcv1.VpcV1
	var err error

	// Instantiate the service with an API key based IAM authenticator
	vpcService, err = vpcv1.NewVpcV1(&vpcv1.VpcV1Options{
		Authenticator: &core.IamAuthenticator{
			ApiKey: apiKey,
		},
		URL:  "https://" + region + ".iaas.cloud.ibm.com/v1",
	})
	if err != nil {
		log.Fatal("Error creating VPC Service.")
	}

	svcs, err := controllerv2.ResourceServiceInstanceRepository.ListInstances(controllerv2.ServiceInstanceQuery{
		Type: "service_instance",
	})
	if err != nil {
		log.Fatal("failed to list the resource instances: %v", err)
	}
	found := false
	for _, svc := range svcs {
		log.Printf("Service ID: %s, region_id: %s, Name: %s", svc.Guid, svc.RegionID, svc.Name)
		log.Printf("crn: %v", svc.Crn)
		if region == svc.RegionID {
			instanceID = svc.Guid
			found = true
			break
		}
	}
	if !found {
		log.Fatal("region: %s not found", region)
	}

	listInstances (rSearch, vpcService)
}
