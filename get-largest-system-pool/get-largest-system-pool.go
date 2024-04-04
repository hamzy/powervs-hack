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
	"flag"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/IBM-Cloud/bluemix-go"
	"github.com/IBM-Cloud/bluemix-go/api/resource/resourcev2/controllerv2"
	"github.com/IBM-Cloud/bluemix-go/authentication"
	"github.com/IBM-Cloud/bluemix-go/http"
	"github.com/IBM-Cloud/bluemix-go/rest"
	bxsession "github.com/IBM-Cloud/bluemix-go/session"
	"github.com/IBM-Cloud/power-go-client/clients/instance"
	"github.com/IBM-Cloud/power-go-client/ibmpisession"
	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/sirupsen/logrus"
	"io"
	"os"
	gohttp "net/http"
	"strings"
	"time"
)

// Replaced with:
//   -ldflags="-X main.version=$(git describe --always --long --dirty)"
var version string = "undefined"
var shouldDebug bool = false
var log *logrus.Logger

type User struct {
	ID         string
	Email      string
	Account    string
	cloudName  string `default:"bluemix"`
	cloudType  string `default:"public"`
	generation int    `default:"2"`
}

func fetchUserDetails(bxSession *bxsession.Session, generation int) (*User, error) {
	config := bxSession.Config
	user := User{}
	var bluemixToken string

	if strings.HasPrefix(config.IAMAccessToken, "Bearer") {
		bluemixToken = config.IAMAccessToken[7:len(config.IAMAccessToken)]
	} else {
		bluemixToken = config.IAMAccessToken
	}

	token, err := jwt.Parse(bluemixToken, func(token *jwt.Token) (interface{}, error) {
		return "", nil
	})
	if err != nil && !strings.Contains(err.Error(), "key is of invalid type") {
		return &user, err
	}

	claims := token.Claims.(jwt.MapClaims)
	if email, ok := claims["email"]; ok {
		user.Email = email.(string)
	}
	user.ID = claims["id"].(string)
	user.Account = claims["account"].(map[string]interface{})["bss"].(string)
	iss := claims["iss"].(string)
	if strings.Contains(iss, "https://iam.cloud.ibm.com") {
		user.cloudName = "bluemix"
	} else {
		user.cloudName = "staging"
	}
	user.cloudType = "public"

	user.generation = generation
	return &user, nil
}

func createPiSession (ptrApiKey *string, ptrServiceName *string) (*ibmpisession.IBMPISession, string, error) {

	var bxSession *bxsession.Session
	var tokenProviderEndpoint string = "https://iam.cloud.ibm.com"
	var err error

	bxSession, err = bxsession.New(&bluemix.Config{
		BluemixAPIKey:         *ptrApiKey,
		TokenProviderEndpoint: &tokenProviderEndpoint,
		Debug:                 false,
	})
	if err != nil {
		return nil, "", fmt.Errorf("Error bxsession.New: %v", err)
	}
	log.Printf("bxSession = %v\n", bxSession)

	tokenRefresher, err := authentication.NewIAMAuthRepository(bxSession.Config, &rest.Client{
		DefaultHeader: gohttp.Header{
			"User-Agent": []string{http.UserAgent()},
		},
	})
	if err != nil {
		return nil, "", fmt.Errorf("Error authentication.NewIAMAuthRepository: %v", err)
	}
	log.Printf("tokenRefresher = %v\n", tokenRefresher)
	err = tokenRefresher.AuthenticateAPIKey(bxSession.Config.BluemixAPIKey)
	if err != nil {
		return nil, "", fmt.Errorf("Error tokenRefresher.AuthenticateAPIKey: %v", err)
	}

	user, err := fetchUserDetails(bxSession, 2)
	if err != nil {
		return nil, "", fmt.Errorf("Error fetchUserDetails: %v", err)
	}

	ctrlv2, err := controllerv2.New(bxSession)
	if err != nil {
		return nil, "", fmt.Errorf("Error controllerv2.New: %v", err)
	}
	log.Printf("ctrlv2 = %v\n", ctrlv2)

	resourceClientV2 := ctrlv2.ResourceServiceInstanceV2()
	if err != nil {
		return nil, "", fmt.Errorf("Error ctrlv2.ResourceServiceInstanceV2: %v", err)
	}
	log.Printf("resourceClientV2 = %v\n", resourceClientV2)

	svcs, err := resourceClientV2.ListInstances(controllerv2.ServiceInstanceQuery{
		Type: "service_instance",
	})
	if err != nil {
		return nil, "", fmt.Errorf("Error resourceClientV2.ListInstances: %v", err)
	}

	var serviceGuid string = ""

	for _, svc := range svcs {
		log.Printf("Guid = %v\n", svc.Guid)
		log.Printf("RegionID = %v\n", svc.RegionID)
		log.Printf("Name = %v\n", svc.Name)
		log.Printf("Crn = %v\n", svc.Crn)
		if svc.Name == *ptrServiceName {
			serviceGuid = svc.Guid
			break
		}
	}
	if serviceGuid == "" {
		return nil, "", fmt.Errorf("%s not found in list of service instances!\n", *ptrServiceName)
	}
	log.Printf("serviceGuid = %v\n", serviceGuid)

	serviceInstance, err := resourceClientV2.GetInstance(serviceGuid)
	if err != nil {
		return nil, "", fmt.Errorf("Error resourceClientV2.GetInstance: %v", err)
	}
	log.Printf("serviceInstance = %v\n", serviceInstance)

	var authenticator core.Authenticator = &core.IamAuthenticator{
		ApiKey: *ptrApiKey,
	}

	err = authenticator.Validate()
	if err != nil {
		return nil, "", fmt.Errorf("authenticator.Validate: %v", err)
	}

	var piSession *ibmpisession.IBMPISession
	var options *ibmpisession.IBMPIOptions = &ibmpisession.IBMPIOptions{
		Authenticator: authenticator,
		Debug:         false,
		UserAccount:   user.Account,
		Zone:          serviceInstance.RegionID,
	}

	piSession, err = ibmpisession.NewIBMPISession(options)
	if err != nil {
		return nil, "", fmt.Errorf("Error ibmpisession.New: %v", err)
	}
	log.Printf("piSession = %v\n", piSession)

	return piSession, serviceGuid, nil

}

func main() {

	var logMain *logrus.Logger = &logrus.Logger{
		Out: os.Stderr,
		Formatter: new(logrus.TextFormatter),
		Level: logrus.DebugLevel,
	}

	var ptrApiKey *string
	var ptrServiceName *string
	var ptrShouldDebug *string

	ptrApiKey = flag.String("apiKey", "", "Your IBM Cloud API key")
	ptrServiceName = flag.String("serviceName", "", "The cloud service to use")
	ptrShouldDebug = flag.String("shouldDebug", "false", "Should output debug output")

	flag.Parse()

	if *ptrApiKey == "" {
		logMain.Fatal("Error: No API key set, use --apiKey")
	}

	if *ptrServiceName == "" {
		logMain.Fatal("Error: No cloud service set, use --serviceName")
	}

	switch strings.ToLower(*ptrShouldDebug) {
	case "true":
		shouldDebug = true
	case "false":
		shouldDebug = false
	default:
		logMain.Fatal("Error: shouldDebug is not true/false (%s)\n", *ptrShouldDebug)
	}

	var out io.Writer

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

	if shouldDebug { logMain.Printf("version = %v\n", version) }

	ctx, cancel := context.WithTimeout(context.TODO(), 2*time.Minute)
	defer cancel()

	var piSession *ibmpisession.IBMPISession
	var serviceGuid string
	var err error

	piSession, serviceGuid, err = createPiSession(ptrApiKey, ptrServiceName)
	if err != nil {
		logMain.Fatal("Error createPiSession: %v\n", err)
	}

	systemPoolClient := instance.NewIBMPISystemPoolClient(ctx, piSession, serviceGuid)
	if shouldDebug { logMain.Printf("systemPoolClient = %v\n", systemPoolClient) }

	systemPools, err := systemPoolClient.GetSystemPools()
	if err != nil {
		logMain.Fatal("Error systemPoolClient.GetSystemPools: %v\n", err)
	}
	if shouldDebug { logMain.Printf("systemPools = %v\n", systemPools) }

	var maxCoresAvailable float64
	var poolType string = "error"

	for _, systemPool := range systemPools {
		// https://github.com/IBM-Cloud/power-go-client/blob/master/power/models/system.go#L20
		// https://github.com/IBM-Cloud/power-go-client/blob/master/power/models/system_pool.go#L20

		// Helpful debug statement to save typing
		if shouldDebug {
			logMain.Printf("ValidateCapacityWithPools: pool %v, cores %v, memory %v\n", systemPool.Type, *systemPool.MaxCoresAvailable.Cores, *systemPool.MaxCoresAvailable.Memory)
		}

		if *systemPool.MaxCoresAvailable.Cores > maxCoresAvailable {
			poolType          = systemPool.Type
			maxCoresAvailable = *systemPool.MaxCoresAvailable.Cores
		}
	}
	if shouldDebug { logMain.Printf("poolType = %v, maxCoresAvailable = %v\n", poolType, maxCoresAvailable) }

	fmt.Printf("%v\n", poolType)
	os.Exit(0)
}
