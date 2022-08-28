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
	gohttp "net/http"
	"os"
	"regexp"
)

const resourceGroupID = "c1cb9b2679344ee9951ab8b4bc22eca0"     // "powervs-ipi-resource-group"
const cosResourceID   = "dff97f5c-bc5e-4455-b470-411c3edbe49c" //

func listServiceInstances1 (rSearch *regexp.Regexp, controllerSvc *resourcecontrollerv2.ResourceControllerV2, context context.Context) {

	options := controllerSvc.NewListResourceInstancesOptions()
//	options.SetResourceGroupID(resourceGroupID)
	options.SetResourceID(cosResourceID)
	options.SetType("service_instance")

	resources, _, err := controllerSvc.ListResourceInstancesWithContext(context, options)
	if err != nil {
		log.Fatalf("Failed to list COS instances: %v", err)
	}

	for _, resource := range resources.Resources {
//		if rSearch.MatchString(*resource.Name) {
			log.Printf("resource: %s\n", *resource.Name)
//		}
	}
}

func listServiceInstances2 (rSearch *regexp.Regexp, controllerSvc *resourcecontrollerv2.ResourceControllerV2, context context.Context) {

	var options *resourcecontrollerv2.ListResourceInstancesOptions
	var resources *resourcecontrollerv2.ResourceInstancesList
	var err error
	var perPage int64 = 10
	var moreData bool = true
	var nextURL *string

	options = controllerSvc.NewListResourceInstancesOptions()
//	options.SetType("resource_instance")
//	options.SetType("service_instance")
//	options.SetResourceID(cosResourceID)
//	options.SetResourceGroupID(resourceGroupID)
	options.SetLimit(perPage)

	for moreData {

		log.Printf("options = %+v\n", options)
		log.Printf("options.Limit = %v\n", *options.Limit)
		if options.Start != nil {
			log.Printf("optionsStart = %v\n", *options.Start)
		}
		resources, _, err = controllerSvc.ListResourceInstancesWithContext(context, options)
		if err != nil {
			log.Fatalf("Failed to list resource instances: %v", err)
		}

		log.Printf("resources.RowsCount = %v\n", *resources.RowsCount)

		for _, resource := range resources.Resources {
			var getResourceOptions *resourcecontrollerv2.GetResourceInstanceOptions
			var resourceInstance *resourcecontrollerv2.ResourceInstance
			var response *core.DetailedResponse

			log.Printf("resource: %s\n", *resource.Name)

			getResourceOptions = controllerSvc.NewGetResourceInstanceOptions(*resource.ID)

			resourceInstance, response, err = controllerSvc.GetResourceInstance(getResourceOptions)
			if err != nil {
				log.Fatalf("Failed to get instance: %v", err)
				continue
			}
			if err != nil && response != nil && response.StatusCode == gohttp.StatusNotFound {
				log.Printf("gohttp.StatusNotFound\n")
				continue
			}
			if err != nil && response != nil && response.StatusCode == gohttp.StatusInternalServerError {
				log.Printf("gohttp.StatusInternalServerError\n")
				continue
			}

			if resourceInstance.Type == nil {
				log.Printf("type: nil\n")
			} else {
				log.Printf("type: %v\n", *resourceInstance.Type)
			}
			if resourceInstance.SubType == nil {
				log.Printf("sub type: nil\n")
			} else {
				log.Printf("sub type: %v\n", *resourceInstance.SubType)
			}
		}

		// Based on: https://cloud.ibm.com/apidocs/resource-controller/resource-controller?code=go#list-resource-instances
		nextURL, err = core.GetQueryParam(resources.NextURL, "start")
		if err != nil {
			log.Fatalf("Failed to GetQueryParam on start: %v", err)
		}
		log.Printf("nextURL = %v\n", *nextURL)
		options.SetStart(*nextURL)

		moreData = *resources.RowsCount == perPage

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
//		ServiceName: "cloud-object-storage",
//		URL: "https://resource-controller.cloud.ibm.com",
	})
	if err != nil {
		log.Fatal("Error creating ControllerV2 Service.")
	}

	listServiceInstances2 (rSearch, controllerSvc, context)
}
