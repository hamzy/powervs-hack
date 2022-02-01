package main

import (
	"fmt"
	"log"
	gohttp "net/http"
	"os"
	"time"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/networking-go-sdk/zonesv1"
	"github.com/IBM/platform-services-go-sdk/resourcecontrollerv2"
	"github.com/IBM-Cloud/bluemix-go"
	"github.com/IBM-Cloud/bluemix-go/authentication"
	"github.com/IBM-Cloud/bluemix-go/http"
	"github.com/IBM-Cloud/bluemix-go/rest"
	bxsession "github.com/IBM-Cloud/bluemix-go/session"
)

var (
	defaultTimeout = 15 * time.Minute
)

const (
	// cisServiceID is the Cloud Internet Services' catalog service ID.
	cisServiceID = "75874a60-cb12-11e7-948e-37ac098eb1b9"
	BaseDomain = "scnl-ibm.com"
)

func getCISInstanceCRN() (string, error) {
	var CISInstanceCRN string = ""
	var APIKey string
	var bxSession *bxsession.Session
	var err error
	var tokenProviderEndpoint string = "https://iam.cloud.ibm.com"
	var tokenRefresher *authentication.IAMAuthRepository
	var authenticator *core.IamAuthenticator
	var controllerSvc *resourcecontrollerv2.ResourceControllerV2
	var listInstanceOptions *resourcecontrollerv2.ListResourceInstancesOptions
	var listResourceInstancesResponse *resourcecontrollerv2.ResourceInstancesList
	var instance resourcecontrollerv2.ResourceInstance
	var zonesService *zonesv1.ZonesV1
	var listZonesOptions *zonesv1.ListZonesOptions
	var listZonesResponse *zonesv1.ListZonesResp

	if APIKey = os.Getenv("IBMCLOUD_API_KEY"); len(APIKey) == 0 {
		return CISInstanceCRN, fmt.Errorf("Error: getCISInstanceCRN: environment variable IBMCLOUD_API_KEY not set!")
	}
	bxSession, err = bxsession.New(&bluemix.Config{
		BluemixAPIKey:         APIKey,
		TokenProviderEndpoint: &tokenProviderEndpoint,
		Debug:                 false,
	})
	if err != nil {
		return CISInstanceCRN, fmt.Errorf("Error: getCISInstanceCRN: bxsession.New: %v", err)
	}
	tokenRefresher, err = authentication.NewIAMAuthRepository(bxSession.Config, &rest.Client{
		DefaultHeader: gohttp.Header{
			"User-Agent": []string{http.UserAgent()},
		},
	})
	if err != nil {
		return CISInstanceCRN, fmt.Errorf("Error: getCISInstanceCRN: authentication.NewIAMAuthRepository: %v", err)
	}
	err = tokenRefresher.AuthenticateAPIKey(bxSession.Config.BluemixAPIKey)
	if err != nil {
		return CISInstanceCRN, fmt.Errorf("Error: getCISInstanceCRN: tokenRefresher.AuthenticateAPIKey: %v", err)
	}
	authenticator = &core.IamAuthenticator{
		ApiKey: APIKey,
	}
	err = authenticator.Validate()
	if err != nil {
		return CISInstanceCRN, fmt.Errorf("Error: :getCISInstanceCRN: authenticator.Validate: %v", err)
	}
	// Instantiate the service with an API key based IAM authenticator
	controllerSvc, err = resourcecontrollerv2.NewResourceControllerV2(&resourcecontrollerv2.ResourceControllerV2Options{
		Authenticator: authenticator,
		ServiceName: "cloud-object-storage",
		URL: "https://resource-controller.cloud.ibm.com",
	})
	if err != nil {
		return CISInstanceCRN, fmt.Errorf("Error: getCISInstanceCRN: creating ControllerV2 Service: %v", err)
	}
	listInstanceOptions = controllerSvc.NewListResourceInstancesOptions()
	listInstanceOptions.SetResourceID(cisServiceID)
	listResourceInstancesResponse, _, err = controllerSvc.ListResourceInstances(listInstanceOptions)
	if err != nil {
		return CISInstanceCRN, fmt.Errorf("Error: getCISInstanceCRN: ListResourceInstances: %v", err)
	}
	for _, instance = range listResourceInstancesResponse.Resources {
		zonesService, err = zonesv1.NewZonesV1(&zonesv1.ZonesV1Options{
			Authenticator: authenticator,
			Crn:           instance.CRN,
		})
		if err != nil {
			return CISInstanceCRN, fmt.Errorf("Error: getCISInstanceCRN: NewZonesV1: %v", err)
		}
		listZonesOptions = zonesService.NewListZonesOptions()
		listZonesResponse, _, err = zonesService.ListZones(listZonesOptions)
		if listZonesResponse == nil {
			return CISInstanceCRN, fmt.Errorf("Error: getCISInstanceCRN: ListZones: %v", err)
		}
		for _, zone := range listZonesResponse.Result {
			if *zone.Status == "active" {
				if *zone.Name == BaseDomain {
					CISInstanceCRN = *instance.CRN
				}
			}
		}
	}

	return CISInstanceCRN, nil
}

func main() {
	var CISInstanceCRN string
	var err error

	CISInstanceCRN, err = getCISInstanceCRN()

	log.Printf("CISInstanceCRN= %v", CISInstanceCRN)
	log.Printf("err = %v", err)
}
