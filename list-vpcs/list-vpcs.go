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

func listVPCs (rSearch *regexp.Regexp, vpcService *vpcv1.VpcV1) {

	listVpcsOptions := vpcService.NewListVpcsOptions();

	vpcs, detailedResponse, err := vpcService.ListVpcs(listVpcsOptions)
	if err != nil {
		log.Fatalf("Failed to list vpcs: %v and the response is: %s", err, detailedResponse)
	}

	for _, vpc := range vpcs.Vpcs {
		log.Printf("vpc: %s\n", *vpc.Name)
		if rSearch.MatchString(*vpc.Name) {
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

	listVPCs (rSearch, vpcService)
}
