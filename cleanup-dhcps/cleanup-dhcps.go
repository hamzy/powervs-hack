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
	"encoding/json"
	"flag"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/golang-jwt/jwt"
	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/platform-services-go-sdk/resourcecontrollerv2"
	"github.com/IBM-Cloud/bluemix-go"
	"github.com/IBM-Cloud/bluemix-go/api/resource/resourcev2/controllerv2"
	"github.com/IBM-Cloud/bluemix-go/authentication"
	"github.com/IBM-Cloud/bluemix-go/http"
	"github.com/IBM-Cloud/bluemix-go/rest"
	bxsession "github.com/IBM-Cloud/bluemix-go/session"
	"github.com/IBM-Cloud/power-go-client/clients/instance"
	"github.com/IBM-Cloud/power-go-client/ibmpisession"
	"github.com/IBM-Cloud/power-go-client/power/models"
	"github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"os"
	gohttp "net/http"
	"net/url"
	"regexp"
	"reflect"
	"strings"
)

var (
	shouldDebug  bool = false
	shouldDelete bool = false
	log          *logrus.Logger
)

const (
	// resource ID for Power Systems Virtual Server in the Global catalog.
	virtualServerResourceID = "f165dd34-3a40-423b-9d95-e90a23f724dd"
)

type PowerVSStruct struct {
	APIKey         string `json:"APIKey"`
	BaseDomain     string `json:"BaseDomain"`
	CISInstanceCRN string `json:"cisInstanceCRN"`
	Region         string `json:"region"`
	VPCRegion      string `json:"vpcRegion"`
	Zone           string `json:"zone"`
}
type Metadata struct {
	ClusterName string `json:"ClusterName"`
	ClusterID   string `json:"ClusterID"`
	InfraID     string `json:"InfraID"`
	PowerVS *PowerVSStruct
}

func readMetadata(fileName string) (*Metadata, error) {
	var data = Metadata{}
	var err error

	file, err := ioutil.ReadFile(fileName)
	if err != nil {
		return &data, fmt.Errorf("Error: ReadFile returns %v", err)
	}

	err = json.Unmarshal([]byte(file), &data)
	if err != nil {
		return &data, fmt.Errorf("Error: Unmarshal returns %v", err)
	}

	return &data, nil
}

// $ ibmcloud catalog service cloud-object-storage --output json | jq -r '.[].id'
// dff97f5c-bc5e-4455-b470-411c3edbe49c
const cosResourceID = "dff97f5c-bc5e-4455-b470-411c3edbe49c"

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

func getServiceGuid(ptrApiKey *string, ptrServiceGUID *string, ptrServiceName *string) (string, error) {

	var (
		authenticator core.Authenticator = &core.IamAuthenticator{
			ApiKey: *ptrApiKey,
		}
		controllerSvc         *resourcecontrollerv2.ResourceControllerV2
		resourceInstance      *resourcecontrollerv2.ResourceInstance
		err                   error
	)

	// Instantiate the service with an API key based IAM authenticator
	controllerSvc, err = resourcecontrollerv2.NewResourceControllerV2(&resourcecontrollerv2.ResourceControllerV2Options{
		Authenticator: authenticator,
		ServiceName:   "cloud-object-storage",
		URL:           "https://resource-controller.cloud.ibm.com",
	})
	if err != nil {
		log.Fatalf("Error: resourcecontrollerv2.NewResourceControllerV2 returns %v", err)
		return "", err
	}

	resourceInstance, err = findServiceInstance(controllerSvc, "", *ptrServiceGUID, *ptrServiceName)
	if err != nil {
		log.Fatalf("Error: findServiceInstance returns %v", err)
		return "", err
	}

	if resourceInstance == nil {
		if *ptrServiceGUID != "" {
			return "", fmt.Errorf("%s not found in list of service instances!", *ptrServiceGUID)
		} else {
			return "", fmt.Errorf("%s not found in list of service instances!", *ptrServiceName)
		}
	} else {
		return *resourceInstance.GUID, nil
	}

}

func findServiceInstance(controllerSvc *resourcecontrollerv2.ResourceControllerV2, resourceGroupID string, guid string, name string) (*resourcecontrollerv2.ResourceInstance, error) {

	var (
		options   *resourcecontrollerv2.ListResourceInstancesOptions
		resources *resourcecontrollerv2.ResourceInstancesList
		err       error
		perPage   int64 = 64
		moreData        = true
		nextURL   *string
	)

	options = controllerSvc.NewListResourceInstancesOptions()
	// options.SetType("resource_instance")
	options.SetResourceGroupID(resourceGroupID)
	options.SetResourcePlanID(virtualServerResourceID)
	options.SetLimit(perPage)

	for moreData {
		if options.Start != nil {
			if shouldDebug { log.Debugf("findServiceInstance: options = %+v, options.Limit = %v, options.Start = %v, options.ResourceGroupID = %v", options, *options.Limit, *options.Start, *options.ResourceGroupID) }
		} else {
			if shouldDebug { log.Debugf("findServiceInstance: options = %+v, options.Limit = %v, options.ResourceGroupID = %v", options, *options.Limit, *options.ResourceGroupID) }
		}

		resources, _, err = controllerSvc.ListResourceInstances(options)
		if err != nil {
			log.Fatalf("Error: ListResourceInstancesWithContext returns %v", err)
			return nil, err
		}

		if shouldDebug { log.Debugf("findServiceInstance: resources.RowsCount = %v", *resources.RowsCount) }

		for _, resource := range resources.Resources {
			var (
				getResourceOptions *resourcecontrollerv2.GetResourceInstanceOptions
				resourceInstance   *resourcecontrollerv2.ResourceInstance
				response           *core.DetailedResponse
			)

			getResourceOptions = controllerSvc.NewGetResourceInstanceOptions(*resource.ID)

			resourceInstance, response, err = controllerSvc.GetResourceInstance(getResourceOptions)
			if err != nil {
				log.Fatalf("Error: GetResourceInstance returns %v", err)
				return nil, err
			}
			if response != nil && response.StatusCode == gohttp.StatusNotFound {
				if shouldDebug { log.Debugf("findServiceInstance: gohttp.StatusNotFound") }
				continue
			} else if response != nil && response.StatusCode == gohttp.StatusInternalServerError {
				if shouldDebug { log.Debugf("findServiceInstance: gohttp.StatusInternalServerError") }
				continue
			}

			if resourceInstance.Type == nil || resourceInstance.GUID == nil {
				continue
			}
			if *resourceInstance.Type != "service_instance" && *resourceInstance.Type != "composite_instance" {
				continue
			}

			if guid != "" && strings.Contains(*resource.GUID, guid) {
				var (
					getOptions *resourcecontrollerv2.GetResourceInstanceOptions

					foundSi *resourcecontrollerv2.ResourceInstance
				)

				if shouldDebug { log.Debugf("listServiceInstances: FOUND GUID = %s", *resource.GUID) }

				getOptions = controllerSvc.NewGetResourceInstanceOptions(*resource.ID)

				foundSi, response, err = controllerSvc.GetResourceInstance(getOptions)
				if err != nil {
					log.Fatalf("Error: GetResourceInstanceWithContext: response = %v, err = %v", response, err)
					return nil, err
				}

				return foundSi, nil
			} else if name != "" && strings.Contains(*resource.Name, name) {
				var (
					getOptions *resourcecontrollerv2.GetResourceInstanceOptions

					foundSi *resourcecontrollerv2.ResourceInstance
				)

				if shouldDebug { log.Debugf("listServiceInstances: FOUND Name = %s", *resource.Name) }

				getOptions = controllerSvc.NewGetResourceInstanceOptions(*resource.ID)

				foundSi, response, err = controllerSvc.GetResourceInstance(getOptions)
				if err != nil {
					log.Fatalf("Error: GetResourceInstanceWithContext: response = %v, err = %v", response, err)
					return nil, err
				}

				return foundSi, nil
			} else {
				if shouldDebug { log.Debugf("listServiceInstances: SKIP Name = %s", *resource.Name) }
			}
		}

		// Based on: https://cloud.ibm.com/apidocs/resource-controller/resource-controller?code=go#list-resource-instances
		nextURL, err = core.GetQueryParam(resources.NextURL, "start")
		if err != nil {
			log.Fatalf("Error: GetQueryParam returns %v", err)
			return nil, err
		}
		if nextURL == nil {
			// log.Debugf("nextURL = nil")
			options.SetStart("")
		} else {
			// log.Debugf("nextURL = %v", *nextURL)
			options.SetStart(*nextURL)
		}

		moreData = *resources.RowsCount == perPage
	}

	return nil, nil
}

func createPiSession(ptrApiKey *string, serviceGuid string, ptrZone *string) (*ibmpisession.IBMPISession, error) {

	var bxSession *bxsession.Session
	var tokenProviderEndpoint string = "https://iam.cloud.ibm.com"
	var err error

	bxSession, err = bxsession.New(&bluemix.Config{
		BluemixAPIKey:         *ptrApiKey,
		TokenProviderEndpoint: &tokenProviderEndpoint,
		Debug:                 false,
	})
	if err != nil {
		return nil, fmt.Errorf("Error bxsession.New: %v", err)
	}
	if shouldDebug { log.Printf("bxSession = %+v", bxSession) }

	tokenRefresher, err := authentication.NewIAMAuthRepository(bxSession.Config, &rest.Client{
		DefaultHeader: gohttp.Header{
			"User-Agent": []string{http.UserAgent()},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("Error authentication.NewIAMAuthRepository: %v", err)
	}
	if shouldDebug { log.Printf("tokenRefresher = %+v", tokenRefresher) }
	err = tokenRefresher.AuthenticateAPIKey(bxSession.Config.BluemixAPIKey)
	if err != nil {
		return nil, fmt.Errorf("Error tokenRefresher.AuthenticateAPIKey: %v", err)
	}

	user, err := fetchUserDetails(bxSession, 2)
	if err != nil {
		return nil, fmt.Errorf("Error fetchUserDetails: %v", err)
	}

	ctrlv2, err := controllerv2.New(bxSession)
	if err != nil {
		return nil, fmt.Errorf("Error controllerv2.New: %v", err)
	}
	if shouldDebug { log.Printf("ctrlv2 = %+v", ctrlv2) }

	resourceClientV2 := ctrlv2.ResourceServiceInstanceV2()
	if err != nil {
		return nil, fmt.Errorf("Error ctrlv2.ResourceServiceInstanceV2: %v", err)
	}
	if shouldDebug { log.Printf("resourceClientV2 = %+v", resourceClientV2) }

	serviceInstance, err := resourceClientV2.GetInstance(serviceGuid)
	if err != nil {
		return nil, fmt.Errorf("Error resourceClientV2.GetInstance: %v", err)
	}
	if shouldDebug { log.Printf("serviceInstance = %+v", serviceInstance) }

	var authenticator = &core.IamAuthenticator{
			ApiKey: *ptrApiKey,
	}
	var piOptions = &ibmpisession.IBMPIOptions{
		Authenticator: authenticator,
		UserAccount:   user.Account,
		Zone:          *ptrZone,
		Debug:         false,
	}
	var piSession *ibmpisession.IBMPISession

	piSession, err = ibmpisession.NewIBMPISession(piOptions)
	if err != nil {
		return nil, fmt.Errorf("Error ibmpisession.New: %v", err)
	}
	if shouldDebug { log.Printf("piSession = %+v", piSession) }

	return piSession, nil

}

func main() {

	var (
		logMain *logrus.Logger = &logrus.Logger{
			Out: os.Stderr,
			Formatter: new(logrus.TextFormatter),
			Level: logrus.DebugLevel,
		}
		out               io.Writer

		data *Metadata = nil
		err  error

		// CLI parameters:
		ptrMetadaFilename *string
		ptrApiKey         *string
		ptrSearch         *string
		ptrZone           *string = nil
		ptrServiceGUID    *string = nil
		ptrServiceName    *string = nil
		ptrShouldDebug    *string
		ptrShouldDelete   *string
		needAPIKey        bool    = true
		needSearch        bool    = true
	)

	ptrMetadaFilename = flag.String("metadata", "", "The filename containing cluster metadata")
	ptrApiKey = flag.String("apiKey", "", "Your IBM Cloud API key")
	ptrSearch = flag.String("search", "", "The search string to match for deletes")
	ptrZone = flag.String("zone", "", "The zone to use")
	ptrServiceGUID = flag.String("ServiceGUID", "", "The service instance GUID to use")
	ptrServiceName = flag.String("ServiceName", "", "The service instance Name to use")
	ptrShouldDebug = flag.String("shouldDebug", "false", "Should output debug output")
	ptrShouldDelete = flag.String("shouldDelete", "false", "Should delete matching records")

	flag.Parse()

	switch strings.ToLower(*ptrShouldDebug) {
	case "true":
		shouldDebug = true
	case "false":
		shouldDebug = false
	default:
		logMain.Fatalf("Error: shouldDebug is not true/false (%s)", *ptrShouldDebug)
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

	if *ptrMetadaFilename != "" {
		data, err = readMetadata(*ptrMetadaFilename)
		if err != nil {
			log.Fatal(err)
		}

		if shouldDebug {
			log.Printf("ClusterName    = %v", data.ClusterName)
			log.Printf("ClusterID      = %v", data.ClusterID)
			log.Printf("InfraID        = %v", data.InfraID)
//			log.Printf("APIKey         = %v", data.PowerVS.APIKey)
			log.Printf("BaseDomain     = %v", data.PowerVS.BaseDomain)
			log.Printf("CISInstanceCRN = %v", data.PowerVS.CISInstanceCRN)
			log.Printf("Region         = %v", data.PowerVS.Region)
			log.Printf("VPCRegion      = %v", data.PowerVS.VPCRegion)
			log.Printf("Zone           = %v", data.PowerVS.Zone)
		}

		// Handle:
		// {
		//   "clusterName": "rdr-hamzy-test",
		//   "clusterID": "ffbb8a77-1ae7-445b-83ad-44cae63a8679",
		//   "infraID": "rdr-hamzy-test-rwmtj",
		//   "powervs": {
		//     "APIKey": "blah",
		//     "BaseDomain": "scnl-ibm.com",
		//     "cisInstanceCRN": "crn:v1:bluemix:public:internet-svcs:global:a/65b64c1f1c29460e8c2e4bbfbd893c2c:453c4cff-2ee0-4309-95f1-2e9384d9bb96::",
		//     "region": "lon",
		//     "vpcRegion": "eu-gb",
		//     "zone": "lon04"
		//   }
		// }
		// Handle:
		// {
		//   "clusterName": "rdr-hamzy-test",
		//   "clusterID": "11f1f0d9-bd35-4cd1-bc67-61f244d824c8",
		//   "infraID": "rdr-hamzy-test-xdh26",
		//   "powervs": {
		//     "cisInstanceCRN": "",
		//     "region": "lon",
		//     "zone": "lon04"
		//   }
		// }

		if data.PowerVS.APIKey != "" {
			ptrApiKey = &data.PowerVS.APIKey
			needAPIKey = false
		}

		ptrSearch = &data.InfraID
		needSearch = false

		ptrZone = &data.PowerVS.Zone
		// @TBD ptrServiceGUID ptrServiceName
	}
	if needAPIKey && *ptrApiKey == "" {
		log.Fatal("Error: No API key set, use -apiKey")
	}
	if needSearch && *ptrSearch == "" {
		log.Fatal("Error: No search term set, use -search")
	}
	switch strings.ToLower(*ptrShouldDelete) {
	case "true":
		shouldDelete = true
	case "false":
		shouldDelete = false
	default:
		log.Fatalf("Error: shouldDelete is not true/false (%s)", *ptrShouldDelete)
	}

	rSearch, _ := regexp.Compile(*ptrSearch)

	var (
		ctx         context.Context
		piSession   *ibmpisession.IBMPISession
		serviceGuid string
	)

	serviceGuid, err = getServiceGuid(ptrApiKey, ptrServiceGUID, ptrServiceName)
	if err != nil {
		log.Fatalf("Error: getServiceGuid: %v", err)
	}
	if shouldDebug { log.Debugf("serviceGuid = %s", serviceGuid) }

	piSession, err = createPiSession(ptrApiKey, serviceGuid, ptrZone)
	if err != nil {
		log.Fatalf("Error: createPiSession: %v", err)
	}

	var piDhcpClient *instance.IBMPIDhcpClient

	piDhcpClient = instance.NewIBMPIDhcpClient(context.Background(), piSession, serviceGuid)
	if shouldDebug { log.Printf("piDhcpClient = %+v", piDhcpClient) }

	cleanupDHCPs(rSearch, piDhcpClient)

	return

	// In case the cleanupXXX functions get moved, this gets rid of compile errors
	rSearch, _ = regexp.Compile("")

	log.Printf("%v", serviceGuid)
	log.Printf("%v", ctx)
	log.Printf("%v", rSearch)

}

func cleanupDHCPs (rSearch *regexp.Regexp, piDhcpClient *instance.IBMPIDhcpClient) {

	// https://github.com/IBM-Cloud/power-go-client/blob/v1.1.5/power/models/d_h_c_p_servers.go#L19
	var dhcpServers models.DHCPServers

	// https://github.com/IBM-Cloud/power-go-client/blob/v1.1.5/power/models/d_h_c_p_server.go#L18-L31
	var dhcpServer *models.DHCPServer

	// https://github.com/IBM-Cloud/power-go-client/blob/v1.1.5/power/models/d_h_c_p_server_detail.go#L20-L36
	var dhcpServerDetail *models.DHCPServerDetail
	var err error

	dhcpServers, err = piDhcpClient.GetAll()
	if err != nil {
		log.Fatalf("Failed to list DHCP servers: %v", err)
	}

	for _, dhcpServer = range dhcpServers {
		if dhcpServer.Network == nil {
			fmt.Printf("Found: DHCP: %s\n", *dhcpServer.ID)
		} else {
			fmt.Printf("Found: DHCP: %s %s\n", *dhcpServer.ID, *dhcpServer.Network.Name)
		}

		if false { if shouldDebug { spew.Printf("dhcpServer = %v", dhcpServer) } }

		if !rSearch.MatchString(*dhcpServer.ID) {
			continue
		}

		if !shouldDelete {
			continue
		}

		err = piDhcpClient.Delete(*dhcpServer.ID)
		if err != nil {
			log.Fatalf("Failed to delete DHCP id %s: %v", *dhcpServer.ID, err)
		}

		dhcpServerDetail, err = piDhcpClient.Get(*dhcpServer.ID)
		if err != nil {
			log.Fatalf("Failed to get DHCP detail: %v", err)
		}

		if false { if shouldDebug { spew.Printf("dhcpServerDetail =: %v", dhcpServerDetail) } }
	}

}
