// Copyright 2025 IBM Corp
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

// How to run:
// (cd test15/; echo "vet:"; go vet || exit 1; echo "build:"; go build *.go || exit 1; ./test15 --apiKey "${IBMCLOUD_API_KEY}" -shouldDebug false)

package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/IBM/platform-services-go-sdk/globalsearchv2"
//	"github.com/IBM/platform-services-go-sdk/globaltaggingv1"
	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/sirupsen/logrus"
	"k8s.io/utils/ptr"
	"math"
	"io"
	"os"
	"strings"
	"time"
)

var (
	shouldDebug bool   = false
	log         *logrus.Logger
)

// ResourceType is the different types that can be selected by a tag.
type ResourceType int

const (
	// ResourceUnknown Is an unmatched resource.
	ResourceUnknown ResourceType = iota

	// ResourceCOS Is a Cloud Object Storage resource.
        ResourceCOS

	// ResourceIAAS Is an Infrastructure As A Service resource (AKA PowerVS server).
	ResourceIAAS

	// ResourceGateway Is a Transit Gateway resource.
	ResourceTransitGateway

	// ResourceLoadBalancer Is a Load Balancer resource.
	ResourceLoadBalancer

	// ResourceVPC Is a Virtual Private Cloud resource.
	ResourceVPC
)

func leftInContext(ctx context.Context) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return math.MaxInt64
	}

	duration := time.Until(deadline)

	return duration
}

/*
** if Family == "resource_controller" AND Type == "resource-instance" AND CRN contains ":cloud-object-storage:"
** if Family == "resource_controller" AND Type == "resource-instance" AND CRN contains ":power-iaas:"
** if Family == "resource_controller" AND Type == "gateway"
** if Family == "is" AND Type == "load-balancer"
** if Family == "is" AND Type == "vpc"
*/
func determineResourceType (propertyFamily string, propertyName string, propertyType string, CRN string) ResourceType {

	switch propertyFamily {
	case "resource_controller":
		switch propertyType {
			case "resource-instance":
				if strings.Contains(CRN, ":cloud-object-storage:") {
					return ResourceCOS
				} else if strings.Contains(CRN, ":power-iaas:") {
					return ResourceIAAS
				}
			case "gateway":
				return ResourceTransitGateway
		}
	case "is":
		switch propertyType {
			case "load-balancer":
				return ResourceLoadBalancer
			case "vpc":
				return ResourceVPC
		}
	}

	return ResourceUnknown
}

func main() {

	var (
		logMain             *logrus.Logger = &logrus.Logger{
			Out: os.Stderr,
			Formatter: new(logrus.TextFormatter),
			Level: logrus.DebugLevel,
		}
		out                 io.Writer
		ptrApiKey           *string
		ptrShouldDebug      *string
		ctx                 context.Context
		authenticator       core.Authenticator
		globalSearchOptions *globalsearchv2.GlobalSearchV2Options
		searchService       *globalsearchv2.GlobalSearchV2
		moreData            bool  = true
		perPage             int64 = 100
		searchCursor        string
		searchOptions       *globalsearchv2.SearchOptions
		result              *globalsearchv2.ScanResult
		response            *core.DetailedResponse
		properties          map[string]interface{}
		err                 error
	)

	ptrApiKey = flag.String("apiKey", "", "Your IBM Cloud API key")
	ptrShouldDebug = flag.String("shouldDebug", "false", "Should output debug output")

	flag.Parse()

	switch strings.ToLower(*ptrShouldDebug) {
	case "true":
		shouldDebug = true
	case "false":
		shouldDebug = false
	default:
		err2 := fmt.Errorf("Error: shouldDebug is not true/false (%s)\n", *ptrShouldDebug)
		fmt.Println(err2)
		os.Exit(1)
	}

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

	if *ptrApiKey == "" {
		fmt.Println("Error: No API key set, use -apiKey")
		os.Exit(1)
	}

	if shouldDebug { logMain.Printf("Begin") }

	ctx, cancel := context.WithTimeout(context.TODO(), 15*time.Minute)
	defer cancel()

	authenticator = &core.IamAuthenticator{
		ApiKey: *ptrApiKey,
	}

	err = authenticator.Validate()
	if err != nil {
		fmt.Printf("Error: authenticator.Validate: %v", err)
		os.Exit(1)
	}

	globalSearchOptions = &globalsearchv2.GlobalSearchV2Options{
		URL:           globalsearchv2.DefaultServiceURL,
		Authenticator: authenticator,
	}
	if shouldDebug { logMain.Printf("globalSearchOptions = %+v", globalSearchOptions) }

	searchService, err = globalsearchv2.NewGlobalSearchV2(globalSearchOptions)
	if err != nil {
		fmt.Printf("Error: globalsearchv2.NewGlobalSearchV2: %v", err)
		os.Exit(1)
	}

	for moreData {
		searchOptions = &globalsearchv2.SearchOptions{
			Query:        ptr.To("tags:hamzy-test"),
			Limit:        ptr.To(perPage),
		}
		if searchCursor != "" {
			searchOptions.SetSearchCursor(searchCursor)
		}
		if shouldDebug { logMain.Printf("searchOptions = %+v", searchOptions) }

		result, response, err = searchService.SearchWithContext(ctx, searchOptions)
		if err != nil {
			fmt.Printf("Error: globalsearchv2.SearchWithContext: err = %v, response = %v", err, response)
			os.Exit(1)
		}
		if shouldDebug {
			logMain.Printf("result = %+v", result)
			if result.SearchCursor != nil {
				logMain.Printf("result.SearchCursor = %+v", *result.SearchCursor)
			} else {
				logMain.Printf("result.SearchCursor = nil")
			}
			logMain.Printf("len result.Items = %d", len(result.Items))
		}

		for _, item := range result.Items {
			properties = item.GetProperties()

			var (
				propertyFamily string
				propertyName   string
				propertyType   string
				ok             bool
				resourceType   ResourceType
			)

			propertyFamily, ok = properties["family"].(string)
			if !ok {
				fmt.Printf("Error: %v is not a string?", properties["family"])
				os.Exit(1)
			}

			propertyName, ok = properties["name"].(string)
			if !ok {
				fmt.Printf("Error: %v is not a string?", properties["name"])
				os.Exit(1)
			}

			propertyType, ok = properties["type"].(string)
			if !ok {
				fmt.Printf("Error: %v is not a string?", properties["type"])
				os.Exit(1)
			}

			resourceType = determineResourceType (propertyFamily, propertyName, propertyType, *item.CRN)

//			fmt.Printf("%+v\n", item)
			fmt.Printf("CRN:          %s\n", *item.CRN)
			fmt.Printf("Family:       %s\n", properties["family"])
			fmt.Printf("Name:         %s\n", properties["name"])
			fmt.Printf("Type:         %s\n", properties["type"])
			fmt.Printf("ResourceType: %d\n", resourceType)
			fmt.Printf("\n")
		}

		moreData = int64(len(result.Items)) == perPage
		if moreData {
			if result.SearchCursor != nil {
				searchCursor = *result.SearchCursor
			}
		}
	}
}
