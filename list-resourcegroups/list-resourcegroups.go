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
	"github.com/IBM/platform-services-go-sdk/resourcemanagerv2"
	"log"
	"os"
	"regexp"
)

func listResourceGroups (rSearch *regexp.Regexp, mgmtService *resourcemanagerv2.ResourceManagerV2) {

	listResourceGroupsOptions := mgmtService.NewListResourceGroupsOptions()

	resourceGroups, detailedResponse, err := mgmtService.ListResourceGroups(listResourceGroupsOptions)
	if err != nil {
		log.Fatalf("Failed to list resourceGroups: %v and the response is: %s", err, detailedResponse)
	}

	for _, resourceGroup := range resourceGroups.Resources {
		log.Printf("resourceGroup: %s\n", *resourceGroup.Name)
		if rSearch.MatchString(*resourceGroup.Name) {
		}
	}
}

func main() {

	apiKey := os.Getenv("IBMCLOUD_API_KEY")
	if apiKey == "" {
		log.Fatal("No API key set")
	}

	var search string = ".*rdr-hamzy-test.*"

	rSearch, _ := regexp.Compile(search)

	var mgmtService *resourcemanagerv2.ResourceManagerV2
	var err error

	// Instantiate the service with an API key based IAM authenticator
	mgmtService, err = resourcemanagerv2.NewResourceManagerV2(&resourcemanagerv2.ResourceManagerV2Options{
		Authenticator: &core.IamAuthenticator{
			ApiKey: apiKey,
		},
	})
	if err != nil {
		log.Fatal("Error creating ResourceManagerV2 Service.")
	}

	listResourceGroups (rSearch, mgmtService)
}
