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
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	ignV3Types "github.com/coreos/ignition/v2/config/v3_4/types"
	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/ibm-cos-sdk-go/aws"
	"github.com/IBM/ibm-cos-sdk-go/aws/awserr"
	"github.com/IBM/ibm-cos-sdk-go/aws/credentials/ibmiam"
	"github.com/IBM/ibm-cos-sdk-go/aws/session"
	"github.com/IBM/ibm-cos-sdk-go/service/s3"
	"github.com/IBM/ibm-cos-sdk-go/service/s3/s3manager"
	"github.com/IBM/platform-services-go-sdk/resourcecontrollerv2"
	"k8s.io/utils/ptr"
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
	Region  string
}

type CloudObjectStorage struct {
	options CloudObjectStorageOptions

	controllerSvc *resourcecontrollerv2.ResourceControllerV2

	innerCos *resourcecontrollerv2.ResourceInstance

	awsSession *session.Session

	s3Client *s3.S3

	ctx context.Context

	serviceEndpoint string
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
		controllerSvc   *resourcecontrollerv2.ResourceControllerV2
		ctx             context.Context
		serviceEndpoint string
		err             error
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

	serviceEndpoint = fmt.Sprintf("s3.%s.cloud-object-storage.appdomain.cloud", cosOptions.Region)

	return &CloudObjectStorage{
		options:         cosOptions,
		controllerSvc:   controllerSvc,
		innerCos:        nil,
		ctx:             ctx,
		serviceEndpoint: serviceEndpoint,
	}, nil
}

func (cos *CloudObjectStorage) CRN() (string, error) {

	if cos.innerCos == nil {
		return "", fmt.Errorf("CloudObjectStorage does not exist to have a CRN")
	}

	return *cos.innerCos.CRN, nil
}

func (cos *CloudObjectStorage) Name() (string, error) {

	if cos.innerCos == nil {
		return "", fmt.Errorf("CloudObjectStorage does not exist to have a Name")
	}

	return *cos.innerCos.Name, nil
}

func (cos *CloudObjectStorage) Valid() bool {

	if cos.innerCos == nil {
		return false
	}
	return true
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

		err = cos.waitForCloudObjectStorage()
		if err != nil {
			log.Fatalf("Error: waitForCloudObjectStorage returns %v", err)
			return err
		}
	}

	err = cos.createClients()
	if err != nil {
		log.Fatalf("Error: createClients returns %v", err)
		return err
	}

	return nil
}

func (cos *CloudObjectStorage) createClients() error {

	var (
		options session.Options
		err     error
	)

	if cos.innerCos == nil {
		return fmt.Errorf("Error: createClients called on nil CloudObjectStorage")
	}

	options.Config = *aws.NewConfig().
		WithRegion(cos.options.Region).
		WithEndpoint(cos.serviceEndpoint).
		WithCredentials(ibmiam.NewStaticCredentials(
			aws.NewConfig(),
			"https://iam.cloud.ibm.com/identity/token",
			cos.options.ApiKey,
			*cos.innerCos.GUID,
		)).
		WithS3ForcePathStyle(true)

	// https://github.com/IBM/ibm-cos-sdk-go/blob/master/aws/session/session.go#L268
	cos.awsSession, err = session.NewSessionWithOptions(options)
	if err != nil {
		log.Fatalf("Error: NewSessionWithOptions returns %v", err)
		return err
	}
	log.Debugf("createClients: cos.awsSession = %+v", cos.awsSession)
	if cos.awsSession == nil {
		log.Fatalf("Error: cos.awsSession is nil")
		return fmt.Errorf("Error: cos.awsSession is nil")
	}

	cos.s3Client = s3.New(cos.awsSession)
	log.Debugf("createClients: cos.s3Client = %+v", cos.s3Client)
	if cos.s3Client == nil {
		log.Fatalf("Error: cos.s3Client is nil")
		return fmt.Errorf("Error: cos.s3Client is nil")
	}

	return err
}

func isBucketNotFound(err interface{}) bool {

	log.Debugf("isBucketNotFound: err = %v", err)
	log.Debugf("isBucketNotFound: err.(type) = %T", err)

	if err == nil {
		return false
	}

	// vet: ./CloudObjectStorage.go:443:14: use of .(type) outside type switch
	// if _, ok := err.(type); !ok {

	switch err.(type) {
	case s3.RequestFailure:
		log.Debugf("isBucketNotFound: err.(type) s3.RequestFailure")
		if reqerr, ok := err.(s3.RequestFailure); ok {
			log.Debugf("isBucketNotFound: reqerr.Code() = %v", reqerr.Code())
			switch reqerr.Code() {
			case s3.ErrCodeNoSuchBucket:
				return true
			case "NotFound":
				return true
			case "Forbidden":
				return true
			}
			log.Debugf("isBucketNotFound: continuing")
		} else {
			log.Debugf("isBucketNotFound: s3.RequestFailure !ok")
		}
	case awserr.Error:
		log.Debugf("isBucketNotFound: err.(type) awserr.Error")
		if reqerr, ok := err.(awserr.Error); ok {
			log.Debugf("isBucketNotFound: reqerr.Code() = %v", reqerr.Code())
			switch reqerr.Code() {
			case s3.ErrCodeNoSuchBucket:
				return true
			case "NotFound":
				return true
			case "Forbidden":
				return true
			}
			log.Debugf("isBucketNotFound: continuing")
		} else {
			log.Debugf("isBucketNotFound: s3.RequestFailure !ok")
		}
	}

	// @TODO investigate
	switch s3Err := err.(type) {
	case awserr.Error:
		if s3Err.Code() == "NoSuchBucket" {
			return true
		}
		origErr := s3Err.OrigErr()
		if origErr != nil {
			return isBucketNotFound(origErr)
		}
	case s3manager.Error:
		if s3Err.OrigErr != nil {
			return isBucketNotFound(s3Err.OrigErr)
		}
	case s3manager.Errors:
		if len(s3Err) == 1 {
			return isBucketNotFound(s3Err[0])
		}
	// Weird: This does not match?!
	// case s3.RequestFailure:
	}

	return false
}

func (cos *CloudObjectStorage) testS3() error {

	var (
		bucket             = "bootstrap.ign"
		key                = "node-bootstrap"
		msg                = "Hello world."
		headBucketInput    *s3.HeadBucketInput
		headBucketOutput   *s3.HeadBucketOutput
		createBucketInput  *s3.CreateBucketInput
		createBucketOutput *s3.CreateBucketOutput
		headObjectInput    *s3.HeadObjectInput
		headObjectOutput   *s3.HeadObjectOutput
		putObjectInput     *s3.PutObjectInput
		putObjectOutput    *s3.PutObjectOutput
		output             *s3.ListBucketsOutput
		err                error
	)

	headBucketInput = &s3.HeadBucketInput{
		Bucket: aws.String(bucket),
	}
	headBucketOutput, err = cos.s3Client.HeadBucketWithContext(cos.ctx, headBucketInput)
	if isBucketNotFound(err) {
		log.Debugf("testS3: isBucketNotFound returns true")

		createBucketInput = &s3.CreateBucketInput{
			Bucket: aws.String(bucket),
		}
		createBucketOutput, err = cos.s3Client.CreateBucketWithContext(cos.ctx, createBucketInput)
		if err != nil {
			log.Fatalf("Error: CreateBucketWithContext returns %v", err)
			return err
		}
		log.Debugf("testS3: createBucketOutput = %+v", *createBucketOutput)
	} else 	if err != nil {
		log.Fatalf("Error: HeadBucketWithContext returns %v", err)
		return err
	}
	log.Debugf("testS3: headBucketOutput = %+v", *headBucketOutput)

	headObjectInput = &s3.HeadObjectInput{
		Bucket: &bucket,
		Key:    &key,
	}
	headObjectOutput, err = cos.s3Client.HeadObjectWithContext(cos.ctx, headObjectInput)
	if isBucketNotFound(err) {
		log.Debugf("testS3: isBucketNotFound returns true")
	}
	if err != nil {
		log.Fatalf("Error: HeadObjectWithContext returns %v", err)
		return err
	}
	log.Debugf("testS3: headObjectOutput = %+v", *headObjectOutput)

	// putObjectInput = new(s3.PutObjectInput).SetBucket(bucket).SetKey(key).SetBody(strings.NewReader(msg))
	putObjectInput = &s3.PutObjectInput{
		Bucket: &bucket,
		Key:    &key,
		Body:   strings.NewReader(msg),
	}

	putObjectOutput, err = cos.s3Client.PutObjectWithContext(cos.ctx, putObjectInput)
	if err != nil {
		log.Fatalf("Error: PutObjectWithContext returns %v", err)
		return err
	}
	log.Debugf("testS3: putObjectOutput = %+v", *putObjectOutput)

	output, err = cos.s3Client.ListBucketsWithContext(cos.ctx, &s3.ListBucketsInput{})
	if err != nil {
		log.Fatalf("Error: ListBucketsWithContext returns %v", err)
		return err
	}
	log.Debugf("testS3: output = %+v", *output)

	objectURL := &url.URL{
		Scheme: "https",
		Host:   cos.serviceEndpoint,
		Path:   fmt.Sprintf("%s/%s", bucket, key),
	}
	log.Debugf("testS3: objectURL = %v", objectURL)

	return err
}

func (cos *CloudObjectStorage) BucketKeyURL(bucket string, key string) url.URL {

	return url.URL{
		Scheme: "https",
		Host:   cos.serviceEndpoint,
		Path:   fmt.Sprintf("%s/%s", bucket, key),
	}
}

func (cos *CloudObjectStorage) IAMToken() string {

	return ""
}

func (cos *CloudObjectStorage) BucketKeyIgnition(bucket string, key string) ([]byte, error) {

	var (
		urlLocation   url.URL
		authenticator *core.IamAuthenticator
		iamtoken      string
		token         string
		bData         []byte
		err           error
	)

	urlLocation = cos.BucketKeyURL(bucket, key)

	authenticator = &core.IamAuthenticator{
		ApiKey: cos.options.ApiKey,
	}

	iamtoken, err = authenticator.GetToken()
	if err != nil {
		return []byte(""), fmt.Errorf("Error: authenticator.GetToken returns %v", err)
	}
	if iamtoken == "" {
		return []byte(""), fmt.Errorf("IAM token is empty")
	}
	token = "Bearer " + iamtoken

	ignData := &ignV3Types.Config{
		Ignition: ignV3Types.Ignition{
			Version: "3.2.0",
			Config: ignV3Types.IgnitionConfig{
				Replace: ignV3Types.Resource{
					Source: aws.String(urlLocation.String()),
					HTTPHeaders: ignV3Types.HTTPHeaders{
						{
							Name:  "Authorization",
							Value: aws.String(token),
						},
					},
				},
			},
		},
	}

	bData, err = json.Marshal(ignData)
	if err != nil {
		return []byte(""), fmt.Errorf("Error: json.Marshal returns %v", err)
	}

	return bData, nil

/*
	return `{
  "ignition": {
    "version": "3.2.0",
    "config": {
      "replace": {
        "source": "` + urlLocation.String() + `",
        "httpHeaders": [
          {
            "name": "Authorization",
            "value": "` + cos.IAMToken() + `"
          }
        ]
      }
    }
  }
}`
*/
}

func (cos *CloudObjectStorage) CreateBucketFile(bucket string, key string, contents string) error {

	var (
		headBucketInput    *s3.HeadBucketInput
		headBucketOutput   *s3.HeadBucketOutput
		createBucketInput  *s3.CreateBucketInput
		createBucketOutput *s3.CreateBucketOutput
		headObjectInput    *s3.HeadObjectInput
		headObjectOutput   *s3.HeadObjectOutput
		createBucketFile   = false
		putObjectInput     *s3.PutObjectInput
		putObjectOutput    *s3.PutObjectOutput
		err                error
	)

	if cos.innerCos == nil {
		return fmt.Errorf("Error: CreateBucketFile called on nil CloudObjectStorage")
	}

	// https://github.com/IBM/ibm-cos-sdk-go/blob/master/doc.go
	// https://github.com/IBM/ibm-cos-sdk-go/blob/master/service/s3/api.go

	// Does the bucket (directory) exist?
	headBucketInput = &s3.HeadBucketInput{
		Bucket: aws.String(bucket),
	}
	log.Debugf("CreateBucketFile: Calling HeadBucketWithContext")
	headBucketOutput, err = cos.s3Client.HeadBucketWithContext(cos.ctx, headBucketInput)
	if isBucketNotFound(err) {
		// No. Create the bucket.
		createBucketInput = &s3.CreateBucketInput{
			Bucket: aws.String(bucket),
		}
		log.Debugf("CreateBucketFile: Calling CreateBucketWithContext")
		createBucketOutput, err = cos.s3Client.CreateBucketWithContext(cos.ctx, createBucketInput)
		if err != nil {
			log.Fatalf("Error: CreateBucketFile returns %v", err)
			return err
		}
		log.Debugf("CreateBucketFile: createBucketOutput = %+v", *createBucketOutput)
	} else if err != nil {
		log.Fatalf("Error: HeadBucketWithContext returns %v", err)
		return err
	} else {
		log.Debugf("CreateBucketFile: headBucketOutput = %+v", *headBucketOutput)
	}

	// Does the file (key) exist?
	headObjectInput = &s3.HeadObjectInput{
		Bucket: ptr.To(bucket),
		Key:    ptr.To(key),
	}
	log.Debugf("CreateBucketFile: Calling HeadObjectWithContext")
	headObjectOutput, err = cos.s3Client.HeadObjectWithContext(cos.ctx, headObjectInput)
	if isBucketNotFound(err) {
		createBucketFile = true
	} else if err != nil {
		log.Fatalf("Error: HeadObjectWithContext returns %v", err)
		return err
	} else {
		log.Debugf("main: headObjectOutput = %+v", *headObjectOutput)
		// It is not an error to overwrite it.
		createBucketFile = true
	}

	if createBucketFile {
		// Upload the content to the bucket/key.
		// putObjectInput = new(s3.PutObjectInput).SetBucket(bucket).SetKey(key).SetBody(strings.NewReader(msg))
		putObjectInput = &s3.PutObjectInput{
			Bucket: ptr.To(bucket),
			Key:    ptr.To(key),
			Body:   strings.NewReader(contents),
		}
		log.Debugf("CreateBucketFile: Calling PutObjectWithContext")
		putObjectOutput, err = cos.s3Client.PutObjectWithContext(cos.ctx, putObjectInput)
		if err != nil {
			log.Fatalf("Error: PutObjectWithContext returns %v", err)
			return err
		}
		log.Debugf("CreateBucketFile: putObjectOutput = %+v", *putObjectOutput)
	}

	return err
}

func (cos *CloudObjectStorage) waitForCloudObjectStorage() error {

	var (
		err error
	)

	// @TBD

	return err
}

func (cos *CloudObjectStorage) deleteCloudObjectStorage() error {

	var (
		deleteOptions *resourcecontrollerv2.DeleteResourceInstanceOptions

		response *core.DetailedResponse

		err error
	)

	if cos.innerCos != nil {
		deleteOptions = cos.controllerSvc.NewDeleteResourceInstanceOptions(*cos.innerCos.GUID)

		response, err = cos.controllerSvc.DeleteResourceInstanceWithContext(cos.ctx, deleteOptions)
		if err != nil {
			log.Fatalf("Error: DeleteResourceInstanceWithContext: response = %v, err = %v", response, err)
			return err
		}
	}

	return nil
}
