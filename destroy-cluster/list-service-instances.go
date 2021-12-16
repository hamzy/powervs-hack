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
	"context"
	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/platform-services-go-sdk/resourcecontrollerv2"
	"log"
	"os"
	"regexp"
)

const cosTypeName = "cos instance"
const resourceGroupID = "powervs-ipi-resource-group"
const cosResourceID = "dff97f5c-bc5e-4455-b470-411c3edbe49c"

func listServiceInstances (rSearch *regexp.Regexp, controllerSvc *resourcecontrollerv2.ResourceControllerV2, context context.Context) {

	options := controllerSvc.NewListResourceInstancesOptions()
//	options.SetResourceGroupID(resourceGroupID)
	options.SetResourceID(cosResourceID)
	options.SetType("service_instance")

	resources, _, err := controllerSvc.ListResourceInstancesWithContext(context, options)
	if err != nil {
		log.Fatalf("Failed to list COS instances: %v", err)
	}

	for _, resource := range resources.Resources {
		if rSearch.MatchString(*resource.Name) {
			log.Printf("resource: %s\n", *resource.Name)
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

	var context context.Context
	var controllerSvc *resourcecontrollerv2.ResourceControllerV2
	var err error

	// Instantiate the service with an API key based IAM authenticator
	controllerSvc, err = resourcecontrollerv2.NewResourceControllerV2(&resourcecontrollerv2.ResourceControllerV2Options{
		Authenticator: &core.IamAuthenticator{
			ApiKey: apiKey,
		},
		ServiceName: "cloud-object-storage",
		URL: "https://resource-controller.cloud.ibm.com",
	})
	if err != nil {
		log.Fatal("Error creating ControllerV2 Service.")
	}

	listServiceInstances (rSearch, controllerSvc, context)
}
