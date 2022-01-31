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
	"github.com/IBM/vpc-go-sdk/vpcv1"
	"log"
	"net/url"
	"os"
	"reflect"
	"regexp"
)

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

func listSecurityGroups (rSearch *regexp.Regexp, vpcService *vpcv1.VpcV1, context context.Context) {

	var start string = ""

	securityGroupsOptions := vpcService.NewListSecurityGroupsOptions()
	securityGroupsOptions.Start = &start

	for {

		if securityGroupsOptions.Start == nil {
			log.Printf("Start = nil\n")
		} else {
			if *securityGroupsOptions.Start == "" {
				securityGroupsOptions.Start = nil
				log.Printf("Start = nil (2)\n")
			} else {
				log.Printf("Start = %v\n", *securityGroupsOptions.Start)
			}
		}

		securityGroups, detailedResponse, err := vpcService.ListSecurityGroups(securityGroupsOptions)
		if err != nil {
			log.Fatalf("Failed to list securityGroups: %v and the response is: %s", err, detailedResponse)
		}

		if securityGroups.Next == nil {
			log.Printf("Next = nil\n")
		} else {
			log.Printf("Next = %v\n", *securityGroups.Next)
			start = GetNext(securityGroups.Next)
			securityGroupsOptions.Start = &start
			log.Printf("start = %v\n", start)
		}

		for _, securityGroup := range securityGroups.SecurityGroups {
			if rSearch.MatchString(*securityGroup.Name) {
				log.Printf("securityGroup: %s\n", *securityGroup.Name)
			}
		}

		if start == "" {
			break
		}
	}

}

func main() {

	apiKey := os.Getenv("IBMCLOUD_API_KEY")
	if apiKey == "" {
		log.Fatal("No API key set")
	}

	var region string = "eu-gb"
	var search string = ".*" // ".*rdr-hamzy-test.*"

	rSearch, _ := regexp.Compile(search)

	var context context.Context
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

	listSecurityGroups (rSearch, vpcService, context)
}
