// Copyright 2024 IBM Corp
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

// https://raw.githubusercontent.com/IBM/networking-go-sdk/refs/heads/master/dnsrecordsv1/dns_records_v1.go
// https://raw.githubusercontent.com/IBM/networking-go-sdk/refs/heads/master/dnssvcsv1/dns_svcs_v1.go
// https://raw.githubusercontent.com/IBM/networking-go-sdk/refs/heads/master/zonesv1/zones_v1.go

package main

import (
	"context"
	"fmt"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/networking-go-sdk/dnsrecordsv1"
	"github.com/IBM/networking-go-sdk/dnssvcsv1"
	"github.com/IBM/networking-go-sdk/zonesv1"
	"github.com/IBM/platform-services-go-sdk/resourcecontrollerv2"
)

type DNSOptions struct {
	Mode       Mode
	ApiKey     string
	Name       string
	BaseDomain string
	CIS        string
	lbInt      *LoadBalancer
	lbExt      *LoadBalancer
}

type DNS struct {
	options DNSOptions

	dnsService *dnssvcsv1.DnsSvcsV1

	dnsRecordService *dnsrecordsv1.DnsRecordsV1

	ctx    context.Context
}

func initDNSService(dnsOptions DNSOptions) (*dnssvcsv1.DnsSvcsV1, *dnsrecordsv1.DnsRecordsV1, error) {

	var (
		authenticator    core.Authenticator = &core.IamAuthenticator{
			ApiKey: dnsOptions.ApiKey,
		}
		dnsService          *dnssvcsv1.DnsSvcsV1
		globalOptions       *dnsrecordsv1.DnsRecordsV1Options
		dnsRecordService    *dnsrecordsv1.DnsRecordsV1
		controllerSvc       *resourcecontrollerv2.ResourceControllerV2
		listResourceOptions *resourcecontrollerv2.ListResourceInstancesOptions
		zonesService        *zonesv1.ZonesV1
		listZonesOptions    *zonesv1.ListZonesOptions
		listZonesResponse   *zonesv1.ListZonesResp
		zoneID              string
		err                 error
	)

	dnsService, err = dnssvcsv1.NewDnsSvcsV1(&dnssvcsv1.DnsSvcsV1Options{
		Authenticator: authenticator,
	})
	if err != nil {
		log.Fatalf("Error: dnssvcsv1.NewDnsSvcsV1 returns %v", err)
		return nil, nil, err
	}

	authenticator = &core.IamAuthenticator{
		ApiKey: dnsOptions.ApiKey,
	}

	controllerSvc, err = resourcecontrollerv2.NewResourceControllerV2(&resourcecontrollerv2.ResourceControllerV2Options{
		Authenticator: authenticator,
		ServiceName:   "cloud-object-storage",
		URL:           "https://resource-controller.cloud.ibm.com",
	})
	if err != nil {
		log.Fatalf("Error: resourcecontrollerv2.NewResourceControllerV2 returns %v", err)
		return nil, nil, err
	}
	log.Debugf("initDNSService: controllerSvc= %+v", controllerSvc)

	listResourceOptions = controllerSvc.NewListResourceInstancesOptions()
	listResourceOptions.SetResourceID("75874a60-cb12-11e7-948e-37ac098eb1b9") // CIS service ID

	listResourceInstancesResponse, _, err := controllerSvc.ListResourceInstances(listResourceOptions)
	if err != nil {
		log.Fatalf("Error: ListResourceInstances returns %v", err)
		return nil, nil, err
	}

	for _, instance := range listResourceInstancesResponse.Resources {
		log.Debugf("initDNSService: instance.CRN = %s", *instance.CRN)

		authenticator = &core.IamAuthenticator{
			ApiKey: dnsOptions.ApiKey,
		}

		zonesService, err = zonesv1.NewZonesV1(&zonesv1.ZonesV1Options{
			Authenticator: authenticator,
			Crn:           instance.CRN,
		})
		if err != nil {
			log.Fatalf("Error: zonesv1.NewZonesV1 returns %v", err)
			return nil, nil, err
		}
		log.Debugf("initDNSService: zonesService = %+v", zonesService)

		listZonesOptions = zonesService.NewListZonesOptions()

		listZonesResponse, _, err = zonesService.ListZones(listZonesOptions)
		if err != nil {
			log.Fatalf("Error: zonesService.ListZones returns %v", err)
			return nil, nil, err
		}

		for _, zone := range listZonesResponse.Result {
			log.Debugf("initDNSService: zone.Name = %s", *zone.Name)
			log.Debugf("initDNSService: zone.ID   = %s", *zone.ID)

			if *zone.Name == dnsOptions.BaseDomain {
				zoneID = *zone.ID
			}
		}
	}
	log.Debugf("initDNSService: zoneID = %s", zoneID)

	authenticator = &core.IamAuthenticator{
		ApiKey: dnsOptions.ApiKey,
	}
	globalOptions = &dnsrecordsv1.DnsRecordsV1Options{
		Authenticator:  authenticator,
		Crn:            &dnsOptions.CIS,
		ZoneIdentifier: &zoneID,
	}
	dnsRecordService, err = dnsrecordsv1.NewDnsRecordsV1(globalOptions)
	log.Debugf("initDNSService: dnsRecordService = %+v", dnsRecordService)

	return dnsService, dnsRecordService, err
}

func NewDNS(dnsOptions DNSOptions) (*DNS, error) {

	var (
		dnsService       *dnssvcsv1.DnsSvcsV1
		dnsRecordService *dnsrecordsv1.DnsRecordsV1
		ctx              context.Context
		err              error
	)

	log.Debugf("NewDNS: dnsOptions = %+v", dnsOptions)

	dnsService, dnsRecordService, err = initDNSService(dnsOptions)
	log.Debugf("NewDNS: dnsService = %+v", dnsService)
	log.Debugf("NewDNS: dnsRecordService = %+v", dnsRecordService)
	if err != nil {
		log.Fatalf("Error: NewDNS: initDNSService returns %v", err)
		return nil, err
	}

	return &DNS{
		options:          dnsOptions,
		dnsService:       dnsService,
		dnsRecordService: dnsRecordService,
		ctx:              ctx,
	}, nil
}

func (dns *DNS) Run() error {

	var (
		err error
	)

	switch dns.options.Mode {
	case ModeCreate:
		err = dns.createDNS()
	case ModeDelete:
		err = dns.deleteDNS()
	default:
		return fmt.Errorf("DNS options must be either Create or Delete (%d)", dns.options.Mode)
	}

	return err
}

func (dns *DNS) CRN() (string, error) {

	if dns.dnsService == nil {
		return "", fmt.Errorf("DNS is not initialized")
	}

	return dns.options.CIS, nil
}

func (dns *DNS) Name() (string, error) {

	if dns.dnsService == nil {
		return "", fmt.Errorf("DNS is not initialized")
	}

	return "", nil
}

func (dns *DNS) Valid() bool {

	if dns.dnsService == nil {
		return false
	}

	return true
}

func createHostnameRecord(lb *LoadBalancer) error {

	var (
		isPublic      bool
		dnsHostname   string
		lbHostname    string
		found         bool
		createOptions *dnsrecordsv1.CreateDnsRecordOptions
		result        *dnsrecordsv1.DnsrecordResp
		response      *core.DetailedResponse
		err           error
	)

	isPublic, err = lb.IsPublic()
	if err != nil {
		log.Fatalf("Error: createHostnameRecord: isPublic returns %v", err)
		return err
	}

	if isPublic {
		dnsHostname = fmt.Sprintf("api.%s.%s", dns.options.Name, dns.options.BaseDomain)
	} else {
		dnsHostname = fmt.Sprintf("api-int.%s.%s", dns.options.Name, dns.options.BaseDomain)
	}
	log.Debugf("createHostnameRecord: dnsHostname = %s", dnsHostname)

	found, err = dns.findHostname(dnsHostname)
	if err != nil {
		log.Fatalf("Error: createHostnameRecord: findHostname returns %v", err)
		return err
	}

	if !found {
		lbHostname, err = lb.getHostname()
		if err != nil {
			log.Fatalf("Error: createHostnameRecord: lb.getHostname returns %v", err)
			return err
		}
		log.Debugf("createHostnameRecord: lbHostname = %s", lbHostname)

		createOptions = dns.dnsRecordService.NewCreateDnsRecordOptions()
		createOptions.SetName(dnsHostname)
		createOptions.SetType(dnsrecordsv1.CreateDnsRecordOptions_Type_Cname)
		createOptions.SetContent(lbHostname)

		result, response, err = dns.dnsRecordService.CreateDnsRecord(createOptions)
		if err != nil {
			log.Errorf("dnsRecordService.CreateDnsRecord returns %v", err)
			return err
		}
		log.Debugf("createHostnameRecord: Result.ID = %v, RawResult = %v", *result.Result.ID, response.RawResult)
	}

	return err
}

func (dns *DNS) findHostname(hostname string) (bool, error) {

	var (
		dnsRecordsOptions *dnsrecordsv1.ListAllDnsRecordsOptions
		dnsResources      *dnsrecordsv1.ListDnsrecordsResp
		record            dnsrecordsv1.DnsrecordDetails
		perPage           int64 = 20
		page              int64 = 1
		moreData                = true
		response          *core.DetailedResponse
		err               error
	)

	dnsRecordsOptions = dns.dnsRecordService.NewListAllDnsRecordsOptions()
	dnsRecordsOptions.PerPage = &perPage
	dnsRecordsOptions.Page = &page

	for moreData {
		dnsResources, response, err = dns.dnsRecordService.ListAllDnsRecordsWithContext(dns.ctx, dnsRecordsOptions)
		if err != nil {
			return false, fmt.Errorf("failed to list DNS records: %w and the response is: %s", err, response)
		}

		for _, record = range dnsResources.Result {
			log.Debugf("findHostname: ID = %s, Name = %s, Content = %s", *record.ID, *record.Name, *record.Content)

			// Match all of the cluster's DNS records
			nameMatches := *record.Name == hostname
			contentMatches := *record.Content == hostname
			if nameMatches || contentMatches {
				log.Debugf("findHostname: FOUND: %v, %v", *record.ID, *record.Name)
				return true, nil
			}
		}

		log.Debugf("findHostname: PerPage = %v, Page = %v, Count = %v", *dnsResources.ResultInfo.PerPage, *dnsResources.ResultInfo.Page, *dnsResources.ResultInfo.Count)

		moreData = *dnsResources.ResultInfo.PerPage == *dnsResources.ResultInfo.Count
		log.Debugf("findHostname: moreData = %v", moreData)

		page++
	}

	return false, err
}

func (dns *DNS) createDNS() error {

	var (
		err error
	)

	err = createHostnameRecord(dns.options.lbInt)
	if err != nil {
		return err
	}

	err = createHostnameRecord(dns.options.lbExt)
	if err != nil {
		return err
	}

	return err
}

func (dns *DNS) deleteDNS() error {

	var (
		err error
	)

	return err
}
