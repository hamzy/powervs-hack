// Copyright 2026 IBM Corp
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
// (cd test18/; echo "vet:"; go vet || exit 1; echo "build:"; go build *.go || exit 1; ./test18 --apiKey "${IBMCLOUD_API_KEY}" --zone "${ZONE}" --cloudInstance "${INSTANCE}" --shouldDebug true)

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
		ptrZone             *string
		ptrCloudInstanceID  *string
		ctx                 context.Context
		piSession           *ibmpisession.IBMPISession
		dcClient            *instance.IBMPIDatacentersClient
		datacenter          *models.Datacenter
		ncClient            *instance.IBMPINetworkClient
		networks            *models.Networks
		dhcpNetwork         *models.NetworkReference
		ports               *models.NetworkPorts
		sgClient            *instance.IBMPINetworkSecurityGroupClient
		nsGroups            *models.NetworkSecurityGroups
		err                 error
	)

	ptrApiKey = flag.String("apiKey", "", "Your IBM Cloud API key")
	ptrShouldDebug = flag.String("shouldDebug", "false", "Should output debug output")
	ptrZone = flag.String("zone", "", "The PowerVS zone to use")
	ptrCloudInstanceID = flag.String("cloudInstance", "", "The PowerVS cloud instance ID to use")

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

	log.Debugf("Begin")
	log.Debugf("ptrZone = %s", *ptrZone)

	ctx, cancel := context.WithTimeout(context.TODO(), 15*time.Minute)
	defer cancel()
	log.Debugf("ctx = %v", ctx)

	piSession, err = createPiSession(ptrApiKey, *ptrZone)
	if err != nil {
		err2 := fmt.Errorf("Error: createPiSession returns %v", err)
		fmt.Println(err2)
		os.Exit(1)
	}

	dcClient = instance.NewIBMPIDatacenterClient(ctx, piSession, *ptrCloudInstanceID)
	log.Debugf("dcClient = %+v", dcClient)

	datacenter, err = dcClient.Get(*ptrZone)
	if err != nil {
		err2 := fmt.Errorf("Error: dcClient.Get returns %v", err)
		fmt.Println(err2)
		os.Exit(1)
	}
	log.Debugf("datacenter = %+v", datacenter)

	fmt.Printf("datacenter.Capabilities[\"network-security-groups\"] = %+v\n", datacenter.Capabilities["network-security-groups"])
	fmt.Printf("datacenter.CapabilitiesDetails.SupportedSystems.General = %+v\n", datacenter.CapabilitiesDetails.SupportedSystems.General)

	ncClient = instance.NewIBMPINetworkClient(ctx, piSession, *ptrCloudInstanceID)
	log.Debugf("ncClient = %+v", ncClient)

	networks, err = ncClient.GetAll()
	if err != nil {
		err2 := fmt.Errorf("Error: ncClient.GetAll returns %v", err)
		fmt.Println(err2)
		os.Exit(1)
	}

	for _, networkRef := range networks.Networks {
		log.Debugf("networkRef.Name = %+v", *networkRef.Name)
		log.Debugf("networkRef.NetworkID = %+v", *networkRef.NetworkID)
		log.Debugf("networkRef.Crn = %+v", networkRef.Crn)

		if strings.Contains(*networkRef.Name, "DHCP") {
			dhcpNetwork = networkRef
		}
	}
	log.Debugf("dhcpNetwork = %+v", dhcpNetwork)

	if dhcpNetwork != nil {
		ports, err = ncClient.GetAllPorts(*dhcpNetwork.NetworkID)
		if err != nil {
			err2 := fmt.Errorf("Error: ncClient.GetAllPorts returns %v", err)
			fmt.Println(err2)
			os.Exit(1)
		}

		for _, port := range ports.Ports {
			log.Debugf("port.Description = %+v", *port.Description)
			log.Debugf("port.IPAddress = %+v", *port.IPAddress)
			log.Debugf("port.MacAddress = %+v", *port.MacAddress)
		}
	}

	sgClient = instance.NewIBMIPINetworkSecurityGroupClient(ctx, piSession, *ptrCloudInstanceID)
	log.Debugf("sgClient = %+v", sgClient)

	nsGroups, err = sgClient.GetAll()
	if err != nil {
		err2 := fmt.Errorf("Error: sgClient.GetAll returns %v", err)
		fmt.Println(err2)
		os.Exit(1)
	}

	for _, nsGroup := range nsGroups.NetworkSecurityGroups {
		log.Debugf("nsGroup.Crn = %+v", *nsGroup.Crn)
		log.Debugf("nsGroup.Default = %+v", nsGroup.Default)
		log.Debugf("nsGroup.ID = %+v", *nsGroup.ID)
		log.Debugf("nsGroup.Name = %+v", *nsGroup.Name)

		for _, nsgMember := range nsGroup.Members {
			log.Debugf("nsGroup.Member.ID = %s", *nsgMember.ID)
			log.Debugf("nsGroup.Member.MacAddress = %s", nsgMember.MacAddress)
			log.Debugf("nsGroup.Member.NetworkInterfaceNetworkID = %s", nsgMember.NetworkInterfaceNetworkID)
			log.Debugf("nsGroup.Member.Target = %s", *nsgMember.Target)
			log.Debugf("nsGroup.Member.Type = %s", *nsgMember.Type)
		}

		for _, nsgRule := range nsGroup.Rules {
			log.Debugf("nsGroup.Rule.Action = %s", *nsgRule.Action)
			if nsgRule.DestinationPort != nil {
				log.Debugf("nsGroup.Rule.DestinationPort.Maximum = %d", nsgRule.DestinationPort.Maximum)
				log.Debugf("nsGroup.Rule.DestinationPort.Minimum = %d", nsgRule.DestinationPort.Minimum)
			}
			log.Debugf("nsGroup.Rule.ID = %s", *nsgRule.ID)
			log.Debugf("nsGroup.Rule.Protocol.Type = %s", nsgRule.Protocol.Type)
			if nsgRule.Protocol.IcmpType != nil {
				log.Debugf("nsGroup.Rule.Protocol.IcmpType = %s", *nsgRule.Protocol.IcmpType)
			}
			for _, tcpFlag := range nsgRule.Protocol.TCPFlags {
				log.Debugf("nsGroup.Rule.Protocol.TCPFlag = %s", tcpFlag)
			}
			if nsgRule.Remote != nil {
				log.Debugf("nsGroup.Rule.Remote.ID = %s", nsgRule.Remote.ID)
				log.Debugf("nsGroup.Rule.Remote.Type = %s", nsgRule.Remote.Type)
			}
			if nsgRule.SourcePort != nil {
				log.Debugf("nsGroup.Rule.SourcePort.Maximum = %d", nsgRule.SourcePort.Maximum)
				log.Debugf("nsGroup.Rule.SourcePort.Minimum = %d", nsgRule.SourcePort.Minimum)
			}
		}
	}
}
