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

// Based on:
// ibmcloud pi datacenter get dal10
//
// How to run:
// (cd test16/; echo "vet:"; go vet || exit 1; echo "build:"; go build *.go || exit 1; ./test15 --apiKey "${IBMCLOUD_API_KEY}" -region lon -zone lon06)

package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM-Cloud/bluemix-go"
	"github.com/IBM-Cloud/bluemix-go/authentication"
	"github.com/IBM-Cloud/bluemix-go/http"
	"github.com/IBM-Cloud/bluemix-go/rest"
	bxsession "github.com/IBM-Cloud/bluemix-go/session"
	"github.com/IBM-Cloud/power-go-client/ibmpisession"
	// https://github.com/IBM-Cloud/power-go-client/blob/master/clients/instance/ibm-pi-datacenters.go#L25
	"github.com/IBM-Cloud/power-go-client/clients/instance"
//	"github.com/IBM-Cloud/power-go-client/power/client/datacenters"
	"github.com/IBM-Cloud/power-go-client/power/models"
	"github.com/sirupsen/logrus"
	"io"
	gohttp "net/http"
	"os"
	"strings"
	"time"
)

var (
	shouldDebug = false
	log         *logrus.Logger

	Regions     = map[string][]string{
		"dal":      { "dal10",   "dal12"   },
		"eu-de":    { "eu-de-1", "eu-de-2" },
		"eu-gb":    { "eu-gb",   },
		"lon":      { "lon04",   "lon06"   },
		"mad":      { "mad02",   "mad04"   },
		"mon":      { "mon01"    },
		"osa":      { "osa21"    },
		"sao":      { "sao01",   "sao04"   },
		"syd":      { "syd04",   "syd05"   },
		"tok":      { "tok04"    },
		"tor":      { "tor01"    },
		"us-east":  { "us-east"  },
		"us-south": { "us-south" },
		"wdc":      { "wdc06",   "wdc07"   },
	}
)

const (
	// resource ID for Power Systems Virtual Server in the Global catalog.
	virtualServerResourceID = "f165dd34-3a40-423b-9d95-e90a23f724dd"
)

type User struct {
	ID         string
	Email      string
	Account    string
	cloudName  string `default:"bluemix"`
	cloudType  string `default:"public"`
	generation int    `default:"2"`
}

func fetchUserDetails(bxSession *bxsession.Session, generation int) (*User, error) {

	var bluemixToken string

	config := bxSession.Config
	user := User{}

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

func createPiSession (ptrApiKey *string, regionID string) (*ibmpisession.IBMPISession, error) {

	var (
		bxSession             *bxsession.Session
		tokenProviderEndpoint string = "https://iam.cloud.ibm.com"
		err                   error
	)

	bxSession, err = bxsession.New(&bluemix.Config{
		BluemixAPIKey:         *ptrApiKey,
		TokenProviderEndpoint: &tokenProviderEndpoint,
		Debug:                 false,
	})
	if err != nil {
		return nil, fmt.Errorf("Error bxsession.New: %v", err)
	}
	log.Printf("bxSession = %v\n", bxSession)

	tokenRefresher, err := authentication.NewIAMAuthRepository(bxSession.Config, &rest.Client{
		DefaultHeader: gohttp.Header{
			"User-Agent": []string{http.UserAgent()},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("Error authentication.NewIAMAuthRepository: %v", err)
	}
	log.Printf("tokenRefresher = %v\n", tokenRefresher)
	err = tokenRefresher.AuthenticateAPIKey(bxSession.Config.BluemixAPIKey)
	if err != nil {
		return nil, fmt.Errorf("Error tokenRefresher.AuthenticateAPIKey: %v", err)
	}

	user, err := fetchUserDetails(bxSession, 2)
	if err != nil {
		return nil, fmt.Errorf("Error fetchUserDetails: %v", err)
	}

	var authenticator core.Authenticator = &core.IamAuthenticator{
		ApiKey: *ptrApiKey,
	}

	err = authenticator.Validate()
	if err != nil {
		return nil, fmt.Errorf("authenticator.Validate: %v", err)
	}

	var (
		piSession    *ibmpisession.IBMPISession
		ibmpiOptions *ibmpisession.IBMPIOptions = &ibmpisession.IBMPIOptions{
			Authenticator: authenticator,
			Debug:         false,
			UserAccount:   user.Account,
			Zone:          regionID,
		}
	)

	piSession, err = ibmpisession.NewIBMPISession(ibmpiOptions)
	if err != nil {
		return nil, fmt.Errorf("Error ibmpisession.New: %v", err)
	}
	log.Printf("piSession = %v\n", piSession)

	return piSession, nil
}

func main() {

	var (
		out                 io.Writer
		ptrApiKey           *string
		ptrShouldDebug      *string
		ptrRegion           *string
		ptrZone             *string
		found               = false
		ctx                 context.Context
		piSession           *ibmpisession.IBMPISession
		client              *instance.IBMPIDatacentersClient
		datacenter          *models.Datacenter
		err                 error
	)

	ptrApiKey = flag.String("apiKey", "", "Your IBM Cloud API key")
	ptrShouldDebug = flag.String("shouldDebug", "false", "Should output debug output")
	ptrRegion = flag.String("region", "", "The PowerVS region to use")
	ptrZone = flag.String("zone", "", "The PowerVS zone to use")

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

	found = false
	for region, _ := range Regions {
		if *ptrRegion == region {
			found = true
		}
	}
	if !found {
		fmt.Printf("Error: region(%s) is not valid!\n", *ptrRegion)
		os.Exit(1)
	}

	found = false
	for _, zone := range Regions[*ptrRegion] {
		if *ptrZone == zone {
			found = true
		}
	}
	if !found {
		fmt.Printf("Error: zone(%s) is not valid!\n", *ptrZone)
		os.Exit(1)
	}

	log.Debugf("Begin")

	ctx, cancel := context.WithTimeout(context.TODO(), 15*time.Minute)
	defer cancel()
	log.Debugf("ctx = %v", ctx)

	piSession, err = createPiSession(ptrApiKey, *ptrRegion)
	if err != nil {
		err2 := fmt.Errorf("Error: createPiSession returns %v", err)
		fmt.Println(err2)
		os.Exit(1)
	}

	client = instance.NewIBMPIDatacenterClient(ctx, piSession, "")
	log.Debugf("client = %+v", client)

	datacenter, err = client.Get(*ptrZone)
	if err != nil {
		err2 := fmt.Errorf("Error: client.Get returns %v", err)
		fmt.Println(err2)
		os.Exit(1)
	}
	log.Debugf("datacenter = %+v", datacenter)

	fmt.Printf("datacenter.Capabilities[\"power-edge-router\"] = %+v\n", datacenter.Capabilities["power-edge-router"])

	fmt.Printf("datacenter.CapabilitiesDetails.SupportedSystems.General = %+v\n", datacenter.CapabilitiesDetails.SupportedSystems.General)
}
