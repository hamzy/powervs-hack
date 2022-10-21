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
	"github.com/IBM/networking-go-sdk/dnsrecordsv1"
	"github.com/IBM/networking-go-sdk/zonesv1"
	"log"
	"os"
	"regexp"
	"strings"
)

func listDNS (rSearch *regexp.Regexp, dnsRecordsService *dnsrecordsv1.DnsRecordsV1, context context.Context) {

	var perPage int64 = 4
	var page int64 = 1
	var match bool = false
	var moreData bool = true

	dnsRecordsOptions := dnsRecordsService.NewListAllDnsRecordsOptions()
	dnsRecordsOptions.PerPage = &perPage
	dnsRecordsOptions.Page = &page

	for moreData {

		dnsResources, detailedResponse, err := dnsRecordsService.ListAllDnsRecordsWithContext(context, dnsRecordsOptions)

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
				log.Printf("DNS name: %s\n", *record.Name)
				log.Printf("DNS content: %s\n", *record.Content)
			}
		}

		log.Printf("PerPage = %v\n", *dnsResources.ResultInfo.PerPage)
		log.Printf("Page = %v\n", *dnsResources.ResultInfo.Page)
		log.Printf("Count = %v\n", *dnsResources.ResultInfo.Count)

		// WRONG!
		//moreData = (*dnsResources.ResultInfo.PerPage * *dnsResources.ResultInfo.Page) < *dnsResources.ResultInfo.Count
		moreData = *dnsResources.ResultInfo.PerPage == *dnsResources.ResultInfo.Count
		log.Printf("moreData = %v\n", moreData)

		page++
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
	var err error

	// ibmcloud cis instances --output json | jq -r '.[].crn'
//	var CISInstanceCRN = "crn:v1:bluemix:public:internet-svcs:global:a/65b64c1f1c29460e8c2e4bbfbd893c2c:453c4cff-2ee0-4309-95f1-2e9384d9bb96::"
	var CISInstanceCRN = "crn:v1:bluemix:public:internet-svcs:global:a/3c24cb272ca44aa1ac9f6e9490ac5ecd:9b372a78-cec3-45b7-875e-04ba0270c87d::"

	var zonesSvc *zonesv1.ZonesV1

	zonesSvc, err = zonesv1.NewZonesV1(&zonesv1.ZonesV1Options{
		Authenticator: &core.IamAuthenticator{
			ApiKey: apiKey,
		},
		Crn:           &CISInstanceCRN,
	})
	if err != nil {
		log.Fatalf("Failed to instantiate zonesSvc: %v", err)
	}

	// Get the Zone ID
	zoneOptions := zonesSvc.NewListZonesOptions()
	zoneResources, detailedResponse, err := zonesSvc.ListZonesWithContext(context, zoneOptions)
	if err != nil {
		log.Fatalf("Failed to list Zones: %v and the response is: %s", err, detailedResponse)
	}

	zoneID := ""
	for _, zone := range zoneResources.Result {
		log.Printf("Zone: %s\n", *zone.Name)
		if strings.Contains("scnl-ibm.com", *zone.Name) {
			zoneID = *zone.ID
		}
	}

	var dnsRecordsService *dnsrecordsv1.DnsRecordsV1

	dnsRecordsService, err = dnsrecordsv1.NewDnsRecordsV1(&dnsrecordsv1.DnsRecordsV1Options{
		Authenticator: &core.IamAuthenticator{
			ApiKey: apiKey,
		},
		Crn:            &CISInstanceCRN,
		ZoneIdentifier: &zoneID,
	})
	if err != nil {
		log.Fatalf("Failed to instantiate dnsRecordsService: %v", err)
	}

	listDNS (rSearch, dnsRecordsService, context)
}
