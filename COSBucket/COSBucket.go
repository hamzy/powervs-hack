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
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/ibm-cos-sdk-go/aws"
	"github.com/IBM/ibm-cos-sdk-go/aws/awserr"
	"github.com/IBM/ibm-cos-sdk-go/aws/credentials/ibmiam"
	"github.com/IBM/ibm-cos-sdk-go/aws/session"
	"github.com/IBM/ibm-cos-sdk-go/service/s3"
	"github.com/IBM/ibm-cos-sdk-go/service/s3/s3manager"
	"github.com/IBM/platform-services-go-sdk/resourcecontrollerv2"
	"github.com/sirupsen/logrus"
	"k8s.io/utils/ptr"
)

var (
	log *logrus.Logger = &logrus.Logger{
		Out:       os.Stderr,
		Formatter: new(logrus.TextFormatter),
		Level:     logrus.DebugLevel,
	}
)

const (
	// $ ibmcloud catalog service cloud-object-storage --output json | jq -r '.[].id'
	// dff97f5c-bc5e-4455-b470-411c3edbe49c.
//	cosResourceID = "dff97f5c-bc5e-4455-b470-411c3edbe49c"

	// $ ibmcloud catalog service cloud-object-storage --output json | jq -r '.[].children | .[] | select(.name=="standard") | .id'
	// 744bfc56-d12c-4866-88d5-dac9139e0e5d
	cosResourceID   = "744bfc56-d12c-4866-88d5-dac9139e0e5d"

	region          = "us-south"
	serviceEndpoint = "s3.us-south.cloud-object-storage.appdomain.cloud"
	bucket          = "qwertybootstrap.ign"
	key             = "node-bootstrap"
	msg             = "Hello world."
)

func main() {

	var (
		logMain *logrus.Logger = &logrus.Logger{
			Out: os.Stderr,
			Formatter: new(logrus.TextFormatter),
			Level: logrus.DebugLevel,
		}
		ptrApiKey          *string
		authenticator      core.Authenticator
		controllerSvc      *resourcecontrollerv2.ResourceControllerV2
		ctx                context.Context
		cos                *resourcecontrollerv2.ResourceInstance
		options            session.Options
		awsSession         *session.Session
		s3Client           *s3.S3
		headBucketInput    *s3.HeadBucketInput
		headBucketOutput   *s3.HeadBucketOutput
		deleteBucketInput  *s3.DeleteBucketInput
		deleteBucketOutput *s3.DeleteBucketOutput
		createBucketInput  *s3.CreateBucketInput
		createBucketOutput *s3.CreateBucketOutput
		headObjectInput    *s3.HeadObjectInput
		headObjectOutput   *s3.HeadObjectOutput
		putObjectInput     *s3.PutObjectInput
		putObjectOutput    *s3.PutObjectOutput
		output             *s3.ListBucketsOutput
		createBucketFile   = false
		err                error
	)

	ptrApiKey = flag.String("apiKey", "", "Your IBM Cloud API key")

	flag.Parse()

	if *ptrApiKey == "" {
		logMain.Fatal("Error: No API key set, use --apiKey")
	}

	authenticator = &core.IamAuthenticator{
		ApiKey: *ptrApiKey,
	}

	controllerSvc, err = resourcecontrollerv2.NewResourceControllerV2(&resourcecontrollerv2.ResourceControllerV2Options{
		Authenticator: authenticator,
	})
	if err != nil {
		log.Fatalf("Error: resourcecontrollerv2.NewResourceControllerV2 returns %v", err)
		panic(err)
	}
	if controllerSvc == nil {
		panic(fmt.Errorf("Error: controllerSvc is empty?"))
	}

	ctx = context.Background()
	log.Debugf("main: ctx = %v", ctx)

	cos, err = findCOS(controllerSvc, ctx)
	if err != nil {
		log.Fatalf("Error: findCOS returns %v", err)
		panic(err)
	} else {
		log.Debugf("main: cos = %+v", cos)
	}

	// https://github.com/IBM/ibm-cos-sdk-go/blob/master/doc.go
	// https://github.com/IBM/ibm-cos-sdk-go/blob/master/service/s3/api.go

	options.Config = *aws.NewConfig().
		WithRegion(region).
		WithEndpoint(serviceEndpoint).
		WithCredentials(ibmiam.NewStaticCredentials(
			aws.NewConfig(),
			"https://iam.cloud.ibm.com/identity/token",
			*ptrApiKey,
			*cos.GUID,
		)).
		WithS3ForcePathStyle(true)

	// https://github.com/IBM/ibm-cos-sdk-go/blob/master/aws/session/session.go#L268
	awsSession, err = session.NewSessionWithOptions(options)
	if err != nil {
		log.Fatalf("Error: NewSessionWithOptions returns %v", err)
		panic(err)
	}
	log.Debugf("main: awsSession = %+v", awsSession)
	if awsSession == nil {
		log.Fatalf("Error: awsSession is nil")
		panic(fmt.Errorf("Error: awsSession is nil"))
	}

	s3Client = s3.New(awsSession)
	log.Debugf("main: s3Client = %+v", s3Client)
	if s3Client == nil {
		log.Fatalf("Error: s3Client is nil")
		panic(fmt.Errorf("Error: s3Client is nil"))
	}

	log.Debugf("main: Calling ListBucketsWithContext")
	output, err = s3Client.ListBucketsWithContext(ctx, &s3.ListBucketsInput{})
	if err != nil {
		log.Fatalf("Error: ListBucketsWithContext returns %v", err)
		panic(err)
	}
	log.Debugf("main: output = %+v", *output)

	// BEGIN @HACK
	if false {
		headBucketInput = &s3.HeadBucketInput{
			Bucket: aws.String(bucket),
		}
		log.Debugf("main: Calling HeadBucketWithContext")
		headBucketOutput, err = s3Client.HeadBucketWithContext(ctx, headBucketInput)

		// if bucket exists then delete it!
		if err == nil {
			log.Debugf("main: headBucketOutput = %+v", *headBucketOutput)

			deleteBucketInput = &s3.DeleteBucketInput{
				Bucket: aws.String(bucket),
			}
			log.Debugf("main: Calling DeleteBucketWithContext")
			deleteBucketOutput, err = s3Client.DeleteBucketWithContext(ctx, deleteBucketInput)
			if err != nil {
				log.Debugf("Error: DeleteBucketWithContext returns %v", err)
				panic(err)
			}
			log.Debugf("main: deleteBucketOutput = %+v", *deleteBucketOutput)
		}
	}
	// END @HACK

	// Does the bucket (directory) exist?
	headBucketInput = &s3.HeadBucketInput{
		Bucket: aws.String(bucket),
	}
	log.Debugf("main: Calling HeadBucketWithContext")
	headBucketOutput, err = s3Client.HeadBucketWithContext(ctx, headBucketInput)
	if isBucketNotFound(err) {
		// No. Create the bucket.
		createBucketInput = &s3.CreateBucketInput{
			Bucket: aws.String(bucket),
		}
		log.Debugf("main: Calling CreateBucketWithContext")
		createBucketOutput, err = s3Client.CreateBucketWithContext(ctx, createBucketInput)
		if err != nil {
			log.Fatalf("Error: CreateBucketWithContext returns %v", err)
			panic(err)
		}
		log.Debugf("main: createBucketOutput = %+v", *createBucketOutput)
	} else if err != nil {
		log.Fatalf("Error: HeadBucketWithContext returns %v", err)
		panic(err)
	} else {
		log.Debugf("main: headBucketOutput = %+v", *headBucketOutput)
	}

	// Does the file (key) exist?
	headObjectInput = &s3.HeadObjectInput{
		Bucket: ptr.To(bucket),
		Key:    ptr.To(key),
	}
	log.Debugf("main: Calling HeadObjectWithContext")
	headObjectOutput, err = s3Client.HeadObjectWithContext(ctx, headObjectInput)
	if isBucketNotFound(err) {
		createBucketFile = true
	} else if err != nil {
		log.Fatalf("Error: HeadObjectWithContext returns %v", err)
		panic(err)
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
			Body:   strings.NewReader(msg),
		}
		log.Debugf("main: Calling PutObjectWithContext")
		putObjectOutput, err = s3Client.PutObjectWithContext(ctx, putObjectInput)
		if err != nil {
			log.Fatalf("Error: PutObjectWithContext returns %v", err)
			panic(err)
		}
		log.Debugf("main: putObjectOutput = %+v", *putObjectOutput)
	}

	log.Debugf("main: Calling ListBucketsWithContext")
	output, err = s3Client.ListBucketsWithContext(ctx, &s3.ListBucketsInput{})
	if err != nil {
		log.Fatalf("Error: ListBucketsWithContext returns %v", err)
		panic(err)
	}
	log.Debugf("main: output = %+v", *output)

	objectURL := &url.URL{
		Scheme: "https",
		Host:   serviceEndpoint,
		Path:   fmt.Sprintf("%s/%s", bucket, key),
	}
	log.Debugf("main: objectURL = %v", objectURL)

}

func findCOS(controllerSvc *resourcecontrollerv2.ResourceControllerV2, ctx context.Context) (*resourcecontrollerv2.ResourceInstance, error) {

	var (
		// https://github.com/IBM/platform-services-go-sdk/blob/main/resourcecontrollerv2/resource_controller_v2.go#L3086
		options *resourcecontrollerv2.ListResourceInstancesOptions

		perPage int64 = 64

		// https://github.com/IBM/platform-services-go-sdk/blob/main/resourcecontrollerv2/resource_controller_v2.go#L4525-L4534
		resources *resourcecontrollerv2.ResourceInstancesList

		err error

		moreData = true
	)

	options = controllerSvc.NewListResourceInstancesOptions()
	options.Limit = &perPage
	options.SetType("service_instance")
	options.SetResourcePlanID(cosResourceID)

	for moreData {
		// https://github.com/IBM/platform-services-go-sdk/blob/main/resourcecontrollerv2/resource_controller_v2.go#L173
		resources, _, err = controllerSvc.ListResourceInstancesWithContext(ctx, options)
		if err != nil {
			return nil, fmt.Errorf("failed to list COS instances: %w", err)
		}
		log.Debugf("findCOS: RowsCount %v", *resources.RowsCount)

		for _, instance := range resources.Resources {
			if strings.Contains(*instance.Name, "3zone") {
				var (
					getOptions *resourcecontrollerv2.GetResourceInstanceOptions
					response   *core.DetailedResponse
					foundCos   *resourcecontrollerv2.ResourceInstance
				)
				log.Debugf("findCOS: FOUND %s %s", *instance.Name, *instance.GUID)

				getOptions = controllerSvc.NewGetResourceInstanceOptions(*instance.GUID)

				foundCos, response, err = controllerSvc.GetResourceInstanceWithContext(ctx, getOptions)
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

func isBucketNotFound(err interface{}) bool {

	log.Debugf("isBucketNotFound: err = %v", err)
	log.Debugf("isBucketNotFound: err.(type) = %T", err)

	if err == nil {
		return false
	}

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

func BucketKeyURL(bucket string, key string) url.URL {

	return url.URL{
		Scheme: "https",
		Host:   serviceEndpoint,
		Path:   fmt.Sprintf("%s/%s", bucket, key),
	}
}
