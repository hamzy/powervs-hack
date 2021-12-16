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
	"log"
	"os"
	"regexp"
)

func listOtherStuff (rSearch *regexp.Regexp, vpcService *vpcv1.VpcV1) {

	// Retrieve the list of regions for your account.
	regions, detailedResponse, err := vpcService.ListRegions(&vpcv1.ListRegionsOptions{})
	if err != nil {
		log.Fatalf("Failed to list the regions: %v and the response is: %s", err, detailedResponse)
	}

	// regions is type *vpcv1.RegionCollection
	for _, region := range regions.Regions {
		log.Printf("region: %s\n", *region.Name)
	}

	// Retrieve the list of vpcs for your account.
	vpcs, detailedResponse, err := vpcService.ListVpcs(&vpcv1.ListVpcsOptions{})
	if err != nil {
		log.Fatalf("Failed to list vpcs: %v and the response is: %s", err, detailedResponse)
	}

	// vpcs is type *vpcv1.VPCCollection
	for _, vpc := range vpcs.Vpcs {
		log.Printf("vpc: %s\n", *vpc.Name)
	}

}

func listLoadBalancers (rSearch *regexp.Regexp, vpcService *vpcv1.VpcV1) {

//	var limit int64 = 1
//	var start string = ""

	listLoadBalancersOptions := vpcService.NewListLoadBalancersOptions()

	// These are in vpc-go-sdk@v0.7.0 and vpc-go-sdk@v0.8.0 but not vpc-go-sdk@v1.0.1 ?
//	listLoadBalancersOptions.Limit = &limit
//	listLoadBalancersOptions.Start = &start

	loadBalancers, detailedResponse, err := vpcService.ListLoadBalancers(listLoadBalancersOptions)
	if err != nil {
		log.Fatalf("Failed to list loadBalancers: %v and the response is: %s", err, detailedResponse)
	}

	for _, loadBalancer := range loadBalancers.LoadBalancers {
		if rSearch.MatchString(*loadBalancer.Name) {
			log.Printf("loadBalancer: %s\n", *loadBalancer.Name)
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

	listLoadBalancers (rSearch, vpcService)
}
