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

package main

import (
	"context"
	"fmt"
	"regexp"
	"strings"

//	"gopkg.in/yaml.v2"
	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/platform-services-go-sdk/resourcecontrollerv2"
//	"k8s.io/utils/ptr"
)

const (
	// $ ibmcloud catalog service cloud-object-storage --output json | jq -r '.[].id'
	// dff97f5c-bc5e-4455-b470-411c3edbe49c.
//	cosResourceID = "dff97f5c-bc5e-4455-b470-411c3edbe49c"

	// $ ibmcloud catalog service cloud-object-storage --output json | jq -r '.[].children | .[] | select(.name=="standard") | .id'
	// 744bfc56-d12c-4866-88d5-dac9139e0e5d
	cosResourceID = "744bfc56-d12c-4866-88d5-dac9139e0e5d"
)

type CloudObjectStorageOptions struct {
	Mode Mode
	ApiKey  string
	Name    string
	GroupID string
}

type CloudObjectStorage struct {
	options CloudObjectStorageOptions

	controllerSvc *resourcecontrollerv2.ResourceControllerV2

	innerCos *resourcecontrollerv2.ResourceInstance

	ctx context.Context
}

func initCloudObjectStorageService(options CloudObjectStorageOptions) (*resourcecontrollerv2.ResourceControllerV2, error) {

	var (
		authenticator core.Authenticator = &core.IamAuthenticator{
			ApiKey: options.ApiKey,
		}
		controllerSvc *resourcecontrollerv2.ResourceControllerV2
		err           error
	)

	controllerSvc, err = resourcecontrollerv2.NewResourceControllerV2(&resourcecontrollerv2.ResourceControllerV2Options{
		Authenticator: authenticator,
	})
	if err != nil {
		log.Fatalf("Error: resourcecontrollerv2.NewResourceControllerV2 returns %v", err)
		return nil, err
	}
	if controllerSvc == nil {
		panic(fmt.Errorf("Error: controllerSvc is empty?"))
	}

	return controllerSvc, nil
}

func NewCloudObjectStorage(cosOptions CloudObjectStorageOptions) (*CloudObjectStorage, error) {

	var (
		controllerSvc *resourcecontrollerv2.ResourceControllerV2
		ctx           context.Context
		err           error
	)
	log.Debugf("NewCloudObjectStorage: cosOptions = %+v", cosOptions)

	controllerSvc, err = initCloudObjectStorageService(cosOptions)
	log.Debugf("NewCloudObjectStorage: controllerSvc = %+v", controllerSvc)
	if err != nil {
		log.Fatalf("Error: NewCloudObjectStorage: initCloudObjectStorageService returns %v", err)
		return nil, err
	}

	ctx = context.Background()
	log.Debugf("NewCloudObjectStorage: ctx = %v", ctx)

	return &CloudObjectStorage{
		options:       cosOptions,
		controllerSvc: controllerSvc,
		innerCos:      nil,
		ctx:           ctx,
	}, nil
}

func (cos *CloudObjectStorage) CRN() (string, error) {

	if cos.innerCos == nil {
		return "", fmt.Errorf("CloudObjectStorage does not exist to have a CRN")
	}

	return *cos.innerCos.CRN, nil
}

func (cos *CloudObjectStorage) Run() error {

	var (
		foundCos *resourcecontrollerv2.ResourceInstance
		err      error
	)

	// Does it already exist?
	if cos.innerCos == nil {
		foundCos, err = cos.findCOS()
		if err != nil {
			log.Fatalf("Error: findCOS returns %v", err)
			return err
		} else {
			log.Debugf("Run: foundCos = %+v", foundCos)
			cos.innerCos = foundCos
		}
	}

	switch cos.options.Mode {
	case ModeCreate:
		err = cos.createCloudObjectStorage()
	case ModeDelete:
		err = cos.deleteCloudObjectStorage()
	default:
		return fmt.Errorf("CloudObjectStorage options must be either Create or Delete (%d)", cos.options.Mode)
	}

	return err
}

func (cos *CloudObjectStorage) findCOS() (*resourcecontrollerv2.ResourceInstance, error) {

	var (
		// https://github.com/IBM/platform-services-go-sdk/blob/main/resourcecontrollerv2/resource_controller_v2.go#L3086
		options *resourcecontrollerv2.ListResourceInstancesOptions

		perPage int64 = 64

		// https://github.com/IBM/platform-services-go-sdk/blob/main/resourcecontrollerv2/resource_controller_v2.go#L4525-L4534
		resources *resourcecontrollerv2.ResourceInstancesList

		err error

		moreData = true
	)

	options = cos.controllerSvc.NewListResourceInstancesOptions()
	options.Limit = &perPage
	options.SetType("service_instance")
	options.SetResourcePlanID(cosResourceID)

	for moreData {
		// https://github.com/IBM/platform-services-go-sdk/blob/main/resourcecontrollerv2/resource_controller_v2.go#L173
		resources, _, err = cos.controllerSvc.ListResourceInstancesWithContext(cos.ctx, options)
		if err != nil {
			return nil, fmt.Errorf("failed to list COS instances: %w", err)
		}
		log.Debugf("findCOS: RowsCount %v", *resources.RowsCount)

		for _, instance := range resources.Resources {
			if strings.Contains(*instance.Name, cos.options.Name) {
				var (
					getOptions *resourcecontrollerv2.GetResourceInstanceOptions
					response   *core.DetailedResponse
					foundCos   *resourcecontrollerv2.ResourceInstance
				)
				log.Debugf("findCOS: FOUND %s %s", *instance.Name, *instance.GUID)

				getOptions = cos.controllerSvc.NewGetResourceInstanceOptions(*instance.GUID)

				foundCos, response, err = cos.controllerSvc.GetResourceInstanceWithContext(cos.ctx, getOptions)
				if err != nil {
					log.Fatalf("Error: GetResourceInstanceWithContext: response = %v, err = %v", response, err)
					return nil, err
				}
				log.Debugf("findCOS: foundCos = %+v", foundCos)

				return foundCos, nil
			} else {
				log.Debugf("findCOS: SKIP %s %s", *instance.Name, *instance.GUID)
			}
		}

		if resources.NextURL != nil {
			start, err := resources.GetNextStart()
			if err != nil {
				log.Debugf("findCOS: err = %v", err)
				return nil, fmt.Errorf("failed to GetNextStart: %w", err)
			}
			if start != nil {
				log.Debugf("findCOS: start = %v", *start)
				options.SetStart(*start)
			}
		} else {
			log.Debugf("findCOS: NextURL = nil")
			moreData = false
		}
	}

	return nil, nil
}

// Since there is no API to query these, we have to hard-code them here.

// Region describes resources associated with a region in Power VS.
// We're using a few items from the IBM Cloud VPC offering. The region names
// for VPC are different so another function of this is to correlate those.
type Region struct {
	Description string
	VPCRegion   string
	COSRegion   string
	Zones       []string
	SysTypes    []string
	VPCZones    []string
}

// Regions holds the regions for IBM Power VS, and descriptions used during the survey.
var Regions = map[string]Region{
	"dal": {
		Description: "Dallas, USA",
		VPCRegion:   "us-south",
		COSRegion:   "us-south",
		Zones:       []string{"dal10", "dal12"},
		SysTypes:    []string{"s922", "e980"},
		VPCZones:    []string{"us-south-1", "us-south-2", "us-south-3"},
	},
	"eu-de": {
		Description: "Frankfurt, Germany",
		VPCRegion:   "eu-de",
		COSRegion:   "eu-de",
		Zones:       []string{"eu-de-1", "eu-de-2"},
		SysTypes:    []string{"s922", "e980"},
		VPCZones:    []string{"eu-de-2", "eu-de-3"},
	},
	"lon": {
		Description: "London, UK",
		VPCRegion:   "eu-gb",
		COSRegion:   "eu-gb",
		Zones:       []string{"lon06"},
		SysTypes:    []string{"s922", "e980"},
		VPCZones:    []string{"eu-gb-1", "eu-gb-2", "eu-gb-3"},
	},
	"mad": {
		Description: "Madrid, Spain",
		VPCRegion:   "eu-es",
		COSRegion:   "eu-de", // @HACK - PowerVS says COS not supported in this region
		Zones:       []string{"mad02", "mad04"},
		SysTypes:    []string{"e980", "s1022"},
		VPCZones:    []string{"eu-es-1", "eu-es-2"},
	},
	"osa": {
		Description: "Osaka, Japan",
		VPCRegion:   "jp-osa",
		COSRegion:   "jp-osa",
		Zones:       []string{"osa21"},
		SysTypes:    []string{"s922", "e980"},
		VPCZones:    []string{"jp-osa-1", "jp-osa-2", "jp-osa-3"},
	},
	"sao": {
		Description: "São Paulo, Brazil",
		VPCRegion:   "br-sao",
		COSRegion:   "br-sao",
		Zones:       []string{"sao01", "sao04"},
		SysTypes:    []string{"s922", "e980"},
		VPCZones:    []string{"br-sao-1", "br-sao-2", "br-sao-3"},
	},
	"syd": {
		Description: "Sydney, Australia",
		VPCRegion:   "au-syd",
		COSRegion:   "au-syd",
		Zones:       []string{"syd04"},
		SysTypes:    []string{"s922", "e980"},
		VPCZones:    []string{"au-syd-1", "au-syd-2", "au-syd-3"},
	},
	"wdc": {
		Description: "Washington DC, USA",
		VPCRegion:   "us-east",
		COSRegion:   "us-east",
		Zones:       []string{"wdc06", "wdc07"},
		SysTypes:    []string{"s922", "e980"},
		VPCZones:    []string{"us-east-1", "us-east-2", "us-east-3"},
	},
}

// COSRegionForPowerVSRegion returns the IBM COS region for the specified PowerVS region.
func COSRegionForPowerVSRegion(region string) (string, error) {
	if r, ok := Regions[region]; ok {
		return r.COSRegion, nil
	}

	return "", fmt.Errorf("COS region corresponding to a PowerVS region %s not found ", region)
}

func regionForZone(zone string) string {

	var (
		region []byte
	)

	log.Debugf("regionForZone: zone = %s", zone)

	re := regexp.MustCompile(`[0-9]*`)

	region = re.ReplaceAll([]byte(zone), []byte(""))

	log.Debugf("regionForZone: region = %s", region)

	return string(region)
}

func (cos *CloudObjectStorage) createCloudObjectStorage() error {

	var (
		createOptions *resourcecontrollerv2.CreateResourceInstanceOptions
		response      *core.DetailedResponse
		err           error
	)

	if cos.innerCos == nil {
		createOptions = cos.controllerSvc.NewCreateResourceInstanceOptions(
			cos.options.Name,
			"global",
			cos.options.GroupID,
			cosResourceID,
		)
		log.Debugf("createCloudObjectStorage: createOptions = %+v", createOptions)

		cos.innerCos, response, err = cos.controllerSvc.CreateResourceInstanceWithContext(cos.ctx, createOptions)
		if err != nil {
			log.Fatalf("Error: CreateResourceInstanceWithContext: response = %v, err = %v", response, err)
			return err
		}
		log.Debugf("createCloudObjectStorage: cos.innerCos = %+v", cos.innerCos)
	}

	return nil
}

func (cos *CloudObjectStorage) deleteCloudObjectStorage() error {

	var (
		err error
	)

	return err
}
