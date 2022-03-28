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
	"github.com/golang-jwt/jwt"
	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/networking-go-sdk/dnsrecordsv1"
	"github.com/IBM/networking-go-sdk/zonesv1"
	"github.com/IBM/platform-services-go-sdk/resourcecontrollerv2"
	"github.com/IBM/platform-services-go-sdk/resourcemanagerv2"
	"github.com/IBM/vpc-go-sdk/vpcv1"
	"github.com/IBM-Cloud/bluemix-go"
	"github.com/IBM-Cloud/bluemix-go/api/resource/resourcev2/controllerv2"
	"github.com/IBM-Cloud/bluemix-go/authentication"
	"github.com/IBM-Cloud/bluemix-go/http"
	"github.com/IBM-Cloud/bluemix-go/rest"
	bxsession "github.com/IBM-Cloud/bluemix-go/session"
	"github.com/IBM-Cloud/power-go-client/clients/instance"
	"github.com/IBM-Cloud/power-go-client/ibmpisession"
	"io/ioutil"
	"log"
	gohttp "net/http"
	"net/url"
	"regexp"
	"reflect"
	"strings"
)

var shouldDebug = false
var shouldDelete = false

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

func getServiceGuid(ptrApiKey *string, ptrZone *string, ptrServiceName *string) (string, error) {

	var bxSession *bxsession.Session
	var tokenProviderEndpoint string = "https://iam.cloud.ibm.com"
	var err error
	var serviceGuid string = ""

	bxSession, err = bxsession.New(&bluemix.Config{
		BluemixAPIKey:         *ptrApiKey,
		TokenProviderEndpoint: &tokenProviderEndpoint,
		Debug:                 false,
	})
	if err != nil {
		return "", fmt.Errorf("Error bxsession.New: %v", err)
	}
	if shouldDebug { log.Printf("bxSession = %+v\n", bxSession) }

	tokenRefresher, err := authentication.NewIAMAuthRepository(bxSession.Config, &rest.Client{
		DefaultHeader: gohttp.Header{
			"User-Agent": []string{http.UserAgent()},
		},
	})
	if err != nil {
		return "", fmt.Errorf("Error authentication.NewIAMAuthRepository: %v", err)
	}
	if shouldDebug { log.Printf("tokenRefresher = %+v\n", tokenRefresher) }
	err = tokenRefresher.AuthenticateAPIKey(bxSession.Config.BluemixAPIKey)
	if err != nil {
		return "", fmt.Errorf("Error tokenRefresher.AuthenticateAPIKey: %v", err)
	}

	ctrlv2, err := controllerv2.New(bxSession)
	if err != nil {
		return "", fmt.Errorf("Error controllerv2.New: %v", err)
	}
	if shouldDebug { log.Printf("ctrlv2 = %+v\n", ctrlv2) }

	resourceClientV2 := ctrlv2.ResourceServiceInstanceV2()
	if err != nil {
		return "", fmt.Errorf("Error ctrlv2.ResourceServiceInstanceV2: %v", err)
	}
	if shouldDebug { log.Printf("resourceClientV2 = %+v\n", resourceClientV2) }

	svcs, err := resourceClientV2.ListInstances(controllerv2.ServiceInstanceQuery{
		Type: "service_instance",
	})
	if err != nil {
		return "", fmt.Errorf("Error resourceClientV2.ListInstances: %v", err)
	}

	for _, svc := range svcs {
		if shouldDebug {
			log.Printf("Guid = %v\n", svc.Guid)
			log.Printf("RegionID = %v\n", svc.RegionID)
			log.Printf("Name = %v\n", svc.Name)
			log.Printf("Crn = %v\n", svc.Crn)
		}
		if (ptrServiceName != nil) && (svc.Name == *ptrServiceName) {
			serviceGuid = svc.Guid
			break
		}
		if (ptrZone != nil) && (svc.RegionID == *ptrZone) {
			serviceGuid = svc.Guid
			break
		}
	}

	if serviceGuid == "" {
		return "", fmt.Errorf("%s not found in list of service instances!\n", *ptrServiceName)
	} else {
		return serviceGuid, nil
	}

}

func createPiSession(ptrApiKey *string, serviceGuid string, ptrZone *string, ptrServiceName *string) (*ibmpisession.IBMPISession, error) {

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
	if shouldDebug { log.Printf("bxSession = %+v\n", bxSession) }

	tokenRefresher, err := authentication.NewIAMAuthRepository(bxSession.Config, &rest.Client{
		DefaultHeader: gohttp.Header{
			"User-Agent": []string{http.UserAgent()},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("Error authentication.NewIAMAuthRepository: %v", err)
	}
	if shouldDebug { log.Printf("tokenRefresher = %+v\n", tokenRefresher) }
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
	if shouldDebug { log.Printf("ctrlv2 = %+v\n", ctrlv2) }

	resourceClientV2 := ctrlv2.ResourceServiceInstanceV2()
	if err != nil {
		return nil, fmt.Errorf("Error ctrlv2.ResourceServiceInstanceV2: %v", err)
	}
	if shouldDebug { log.Printf("resourceClientV2 = %+v\n", resourceClientV2) }

	serviceInstance, err := resourceClientV2.GetInstance(serviceGuid)
	if err != nil {
		return nil, fmt.Errorf("Error resourceClientV2.GetInstance: %v", err)
	}
	if shouldDebug { log.Printf("serviceInstance = %+v\n", serviceInstance) }

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
	if shouldDebug { log.Printf("piSession = %+v\n", piSession) }

	return piSession, nil

}

func main() {

	var data *Metadata = nil
	var err error

	// CLI parameters:
	var ptrMetadaFilename *string
	var ptrApiKey *string
	var ptrSearch *string
	var ptrZone *string = nil
	var ptrServiceName *string
	var ptrCISInstanceCRN *string
	var ptrDNSZone *string
	var ptrRegion *string
	var ptrShouldDebug *string
	var ptrShouldDelete *string
	var needAPIKey = true
	var needSearch = true
	var needRegion = true
	var needServiceName = true
	var needCISInstanceCRN = true
	var needDNSZone = true

	ptrMetadaFilename = flag.String("metadata", "", "The filename containing cluster metadata")
	ptrApiKey = flag.String("apiKey", "", "Your IBM Cloud API key")
	ptrSearch = flag.String("search", "", "The search string to match for deletes")
	ptrServiceName = flag.String("serviceName", "", "The cloud service to use")
	ptrCISInstanceCRN = flag.String("CISInstanceCRN", "", "ibmcloud cis instances --output json | jq -r '.[] | select (.name|test(\"powervs-ipi-cis\")) | .crn'")
	ptrDNSZone = flag.String("dnsZone", "", "The DNS zone Ex: scnl-ibm.com")
	ptrRegion = flag.String("region", "", "The region to use")
	ptrZone = flag.String("zone", "", "The zone to use")
	ptrShouldDebug = flag.String("shouldDebug", "false", "Should output debug output")
	ptrShouldDelete = flag.String("shouldDelete", "false", "Should delete matching records")

	flag.Parse()

	switch strings.ToLower(*ptrShouldDebug) {
	case "true":
		shouldDebug = true
	case "false":
		shouldDebug = false
	default:
		log.Fatal("Error: shouldDebug is not true/false (%s)\n", *ptrShouldDebug)
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

		ptrServiceName = nil
		ptrZone = &data.PowerVS.Zone
		needServiceName = false

		if data.PowerVS.CISInstanceCRN != "" {
			ptrCISInstanceCRN= &data.PowerVS.CISInstanceCRN
			needCISInstanceCRN = false
		}

		if data.PowerVS.BaseDomain != "" {
			ptrDNSZone = &data.PowerVS.BaseDomain
			needDNSZone = false
		}

		if data.PowerVS.VPCRegion != "" {
			ptrRegion = &data.PowerVS.VPCRegion
			needRegion = false
		}
	}
	if needAPIKey && *ptrApiKey == "" {
		log.Fatal("Error: No API key set, use -apiKey")
	}
	if needSearch && *ptrSearch == "" {
		log.Fatal("Error: No search term set, use -search")
	}
	if needServiceName && *ptrServiceName == "" {
		log.Fatal("Error: No cloud service set, use -serviceName")
	}
	if needCISInstanceCRN && *ptrCISInstanceCRN == "" {
		log.Fatal("Error: No CISInstanceCRN set, use -CISInstanceCRN")
	}
	if needDNSZone && *ptrDNSZone == "" {
		log.Fatal("Error: No DNS zone set, use -dnsZone")
	}
	if needRegion && *ptrRegion == "" {
		log.Fatal("Error: No region set, use -region")
	}
	switch strings.ToLower(*ptrShouldDelete) {
	case "true":
		shouldDelete = true
	case "false":
		shouldDelete = false
	default:
		log.Fatal("Error: shouldDelete is not true/false (%s)\n", *ptrShouldDelete)
	}

	rSearch, _ := regexp.Compile(*ptrSearch)

	var ctx context.Context
	var vpcService *vpcv1.VpcV1
	var controllerSvc *resourcecontrollerv2.ResourceControllerV2

	// Instantiate the service with an API key based IAM authenticator
	vpcService, err = vpcv1.NewVpcV1(&vpcv1.VpcV1Options{
		Authenticator: &core.IamAuthenticator{
			ApiKey: *ptrApiKey,
		},
		URL:  "https://" + *ptrRegion + ".iaas.cloud.ibm.com/v1",
	})
	if err != nil {
		log.Fatal("Error creating VPC Service.")
	}

	// Instantiate the service with an API key based IAM authenticator
	controllerSvc, err = resourcecontrollerv2.NewResourceControllerV2(&resourcecontrollerv2.ResourceControllerV2Options{
		Authenticator: &core.IamAuthenticator{
			ApiKey: *ptrApiKey,
		},
		ServiceName: "cloud-object-storage",
		URL: "https://resource-controller.cloud.ibm.com",
	})
	if err != nil {
		log.Fatal("Error creating ControllerV2 Service.")
	}

	var mgmtService *resourcemanagerv2.ResourceManagerV2

	// Instantiate the service with an API key based IAM authenticator
	mgmtService, err = resourcemanagerv2.NewResourceManagerV2(&resourcemanagerv2.ResourceManagerV2Options{
		Authenticator: &core.IamAuthenticator{
			ApiKey: *ptrApiKey,
		},
	})
	if err != nil {
		log.Fatal("Error creating ResourceManagerV2 Service.")
	}

	var zonesSvc *zonesv1.ZonesV1

	zonesSvc, err = zonesv1.NewZonesV1(&zonesv1.ZonesV1Options{
		Authenticator: &core.IamAuthenticator{
			ApiKey: *ptrApiKey,
		},
		Crn:           ptrCISInstanceCRN,
	})
	if err != nil {
		log.Fatalf("Failed to instantiate zonesSvc: %v", err)
	}

	// Get the Zone ID
	zoneOptions := zonesSvc.NewListZonesOptions()
	zoneResources, detailedResponse, err := zonesSvc.ListZonesWithContext(ctx, zoneOptions)
	if err != nil {
		log.Fatalf("Failed to list Zones: %v and the response is: %s", err, detailedResponse)
	}

	zoneID := ""
	for _, zone := range zoneResources.Result {
		if shouldDebug { log.Printf("Zone: %s\n", *zone.Name) }
		if strings.Contains(*ptrDNSZone, *zone.Name) {
			zoneID = *zone.ID
		}
	}

	var dnsRecordsService *dnsrecordsv1.DnsRecordsV1

	dnsRecordsService, err = dnsrecordsv1.NewDnsRecordsV1(&dnsrecordsv1.DnsRecordsV1Options{
		Authenticator: &core.IamAuthenticator{
			ApiKey: *ptrApiKey,
		},
		Crn:		ptrCISInstanceCRN,
		ZoneIdentifier:	&zoneID,
	})
	if err != nil {
		log.Fatalf("Failed to instantiate dnsRecordsService: %v", err)
	}

	var piSession *ibmpisession.IBMPISession
	var serviceGuid string

	serviceGuid, err = getServiceGuid(ptrApiKey, ptrZone, ptrServiceName)
	if err != nil {
		log.Fatal("Error: getServiceGuid: %v\n", err)
	}

	piSession, err = createPiSession(ptrApiKey, serviceGuid, ptrZone, ptrServiceName)
	if err != nil {
		log.Fatal("Error: createPiSession: %v\n", err)
	}

	var piInstanceClient *instance.IBMPIInstanceClient

	piInstanceClient = instance.NewIBMPIInstanceClient(context.Background(), piSession, serviceGuid)
	if shouldDebug { log.Printf("piInstanceClient = %+v\n", piInstanceClient) }

	var piImageClient *instance.IBMPIImageClient

	piImageClient = instance.NewIBMPIImageClient(context.Background(), piSession, serviceGuid)
	if shouldDebug { log.Printf("piImageClient = %+v\n", piImageClient) }

	var piJobClient *instance.IBMPIJobClient

	piJobClient = instance.NewIBMPIJobClient(context.Background(), piSession, serviceGuid)
	if shouldDebug { log.Printf("piJobClient = %+v\n", piJobClient) }

	var piCloudConnectionClient *instance.IBMPICloudConnectionClient

	piCloudConnectionClient = instance.NewIBMPICloudConnectionClient(context.Background(), piSession, serviceGuid)
	if shouldDebug { log.Printf("piCloudConnectionClient = %+v\n", piCloudConnectionClient) }

	var piDhcpClient *instance.IBMPIDhcpClient

	piDhcpClient = instance.NewIBMPIDhcpClient(context.Background(), piSession, serviceGuid)
	if shouldDebug { log.Printf("piDhcpClient = %+v\n", piDhcpClient) }

	return

	// In case the cleanupXXX functions get moved, this gets rid of compile errors
	rSearch, _ = regexp.Compile("")

	log.Printf("%v", piInstanceClient)
	log.Printf("%v", piImageClient)
	log.Printf("%v", piSession)
	log.Printf("%v", controllerSvc)
	log.Printf("%v", mgmtService)
	log.Printf("%v", dnsRecordsService)
	log.Printf("%v", vpcService)
	log.Printf("%v", serviceGuid)
	log.Printf("%v", ctx)
	log.Printf("%v", rSearch)

}
