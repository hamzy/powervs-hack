package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/IBM-Cloud/bluemix-go"
	"github.com/IBM-Cloud/bluemix-go/authentication"
	"github.com/IBM-Cloud/bluemix-go/http"
	"github.com/IBM-Cloud/bluemix-go/rest"
	bxsession "github.com/IBM-Cloud/bluemix-go/session"
	"github.com/IBM-Cloud/power-go-client/clients/instance"
	"github.com/IBM-Cloud/power-go-client/ibmpisession"
	"github.com/IBM-Cloud/power-go-client/power/models"
	"github.com/IBM/platform-services-go-sdk/resourcecontrollerv2"
	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/ptr"
	"math"
	"io"
	"os"
	gohttp "net/http"
	"strings"
	"time"
)

var (
	shouldDebug bool   = false
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

func createPiSession (ptrApiKey *string, ptrServiceName *string, ptrServiceGUID *string) (*ibmpisession.IBMPISession, string, error) {

	var (
		bxSession             *bxsession.Session
		tokenProviderEndpoint string = "https://iam.cloud.ibm.com"
		err                   error
		controllerSvc         *resourcecontrollerv2.ResourceControllerV2
	)

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

	var authenticator core.Authenticator = &core.IamAuthenticator{
		ApiKey: *ptrApiKey,
	}

	err = authenticator.Validate()
	if err != nil {
		return nil, "", fmt.Errorf("authenticator.Validate: %v", err)
	}

	// Instantiate the service with an API key based IAM authenticator
	controllerSvc, err = resourcecontrollerv2.NewResourceControllerV2(&resourcecontrollerv2.ResourceControllerV2Options{
		Authenticator: authenticator,
		ServiceName:   "cloud-object-storage",
		URL:           "https://resource-controller.cloud.ibm.com",
	})
	if err != nil {
		return nil, "", fmt.Errorf("Error resourcecontrollerv2.NewResourceControllerV2: %v", err)
	}

	var (
		serviceGuid string = ""
		regionID    string = ""
		listOptions *resourcecontrollerv2.ListResourceInstancesOptions
		resources   *resourcecontrollerv2.ResourceInstancesList
		perPage     int64 = 64
		moreData          = true
		nextURL     *string
	)

	listOptions = controllerSvc.NewListResourceInstancesOptions()
//	listOptions.SetResourceGroupID(resourceGroupID)
	listOptions.SetResourcePlanID(virtualServerResourceID)
	listOptions.SetLimit(perPage)

	for moreData {
		log.Debugf("listOptions = %+v", listOptions)

		resources, _, err = controllerSvc.ListResourceInstances(listOptions)
		if err != nil {
			err2 := fmt.Errorf("Error: ListResourceInstancesWithContext returns %v", err)
			log.Debugf("%v", err2)
			return nil, "", err2
		}

		log.Debugf("resources.RowsCount = %v", *resources.RowsCount)

		for _, resource := range resources.Resources {
			var (
				getResourceOptions *resourcecontrollerv2.GetResourceInstanceOptions
				resourceInstance   *resourcecontrollerv2.ResourceInstance
				response           *core.DetailedResponse
			)

			getResourceOptions = controllerSvc.NewGetResourceInstanceOptions(*resource.ID)

			resourceInstance, response, err = controllerSvc.GetResourceInstance(getResourceOptions)
			if err != nil {
				err2 := fmt.Errorf("Error: GetResourceInstance returns %v", err)
				log.Debugf("%v", err2)
				return nil, "", err2
			}
			if response != nil && response.StatusCode == gohttp.StatusNotFound {
				log.Debugf("gohttp.StatusNotFound")
				continue
			} else if response != nil && response.StatusCode == gohttp.StatusInternalServerError {
				log.Debugf("gohttp.StatusInternalServerError")
				continue
			}

			if resourceInstance.Type == nil || resourceInstance.GUID == nil {
				continue
			}
			if *resourceInstance.Type != "service_instance" && *resourceInstance.Type != "composite_instance" {
				continue
			}

			if *ptrServiceName != "" && *resource.Name == *ptrServiceName {
				log.Debugf("FOUNDBYNAME Name = %s", *resource.Name)
				serviceGuid = *resource.GUID
				regionID = *resource.RegionID
				break
			} else if *ptrServiceGUID != "" && *resource.GUID == *ptrServiceGUID {
				log.Debugf("FOUNDBYGIUD Name = %s", *resource.Name)
				serviceGuid = *resource.GUID
				regionID = *resource.RegionID
				break
			} else {
				log.Debugf("SKIP Name = %s", *resource.Name)
			}
		}

		if serviceGuid != "" {
			break
		}

		// Based on: https://cloud.ibm.com/apidocs/resource-controller/resource-controller?code=go#list-resource-instances
		nextURL, err = core.GetQueryParam(resources.NextURL, "start")
		if err != nil {
			err2 := fmt.Errorf("Error: GetQueryParam returns %v", err)
			log.Debugf("%v", err2)
			return nil, "", err2
		}
		if nextURL == nil {
			listOptions.SetStart("")
		} else {
			listOptions.SetStart(*nextURL)
		}

		moreData = *resources.RowsCount == perPage
	}
	if serviceGuid == "" {
		if *ptrServiceName != "" {
			return nil, "", fmt.Errorf("%s name not found in list of service instances!\n", *ptrServiceName)
		}
		if *ptrServiceGUID != "" {
			return nil, "", fmt.Errorf("%s GUID not found in list of service instances!\n", *ptrServiceGUID)
		}
		return nil, "", fmt.Errorf("Should not be here finding list of service instances!\n")
	}
	log.Printf("serviceGuid = %v\n", serviceGuid)

	authenticator = &core.IamAuthenticator{
		ApiKey: *ptrApiKey,
	}

	err = authenticator.Validate()
	if err != nil {
		return nil, "", fmt.Errorf("authenticator.Validate: %v", err)
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
		return nil, "", fmt.Errorf("Error ibmpisession.New: %v", err)
	}
	log.Printf("piSession = %v\n", piSession)

	return piSession, serviceGuid, nil
}

func leftInContext(ctx context.Context) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return math.MaxInt64
	}

	duration := time.Until(deadline)

	return duration
}

func listDhcpServers(dhcpClient *instance.IBMPIDhcpClient) (int, error) {

	var (
		dhcpServers models.DHCPServers
		dhcpServer  *models.DHCPServer
		err         error
	)

	dhcpServers, err = dhcpClient.GetAll()
	if err != nil {
		return 0, fmt.Errorf("Error: dhcpClient.GetAll returns %v", err)
	}

	if shouldDebug { log.Debugf("listDhcpServers: len(dhcpServers) = %d", len(dhcpServers)) }

	for _, dhcpServer = range dhcpServers {
		if dhcpServer.ID == nil {
			if shouldDebug { log.Debugf("listDhcpServers: SKIP nil(ID)") }
			continue
		}
		if dhcpServer.Network == nil {
			if shouldDebug { log.Debugf("listDhcpServers: SKIP %s nil(Network)", *dhcpServer.ID) }
			continue
		}
		if shouldDebug { log.Debugf("listDhcpServers: FOUND %s %s", *dhcpServer.ID, *dhcpServer.Network.Name) }
	}

	return len(dhcpServers), nil
}

func findDhcpServer(dhcpName string, dhcpClient *instance.IBMPIDhcpClient) (*models.DHCPServerDetail, error) {

	var (
		dhcpServers      models.DHCPServers
		dhcpServer       *models.DHCPServer
		dhcpServerDetail *models.DHCPServerDetail
		err              error
	)

	dhcpServers, err = dhcpClient.GetAll()
	if err != nil {
		return nil, fmt.Errorf("Error: dhcpClient.GetAll returns %v", err)
	}

	if shouldDebug { log.Debugf("listDhcpServers: len(dhcpServers) = %d", len(dhcpServers)) }

	for _, dhcpServer = range dhcpServers {
		if dhcpServer.ID == nil {
			if shouldDebug { log.Debugf("listDhcpServers: SKIP nil(ID)") }
			continue
		}
		if dhcpServer.Network == nil {
			if shouldDebug { log.Debugf("listDhcpServers: SKIP %s nil(Network)", *dhcpServer.ID) }
			continue
		}
		if strings.Contains(*dhcpServer.Network.Name, dhcpName) {
			if shouldDebug { log.Debugf("findDhcpServer: FOUND %s %s", *dhcpServer.ID, *dhcpServer.Network.Name) }

			dhcpServerDetail, err = dhcpClient.Get(*dhcpServer.ID)
			if err != nil {
				return nil, fmt.Errorf("Error: dhcpClient.Get returns %v", err)
			}

			return dhcpServerDetail, nil
		}
		if shouldDebug { log.Debugf("findDhcpServer: SKIP %s %s", *dhcpServer.ID, *dhcpServer.Network.Name) }
	}

	return nil, nil
}

func createDhcpServer(ctx context.Context, dhcpName string, dhcpCidr string, dhcpClient *instance.IBMPIDhcpClient) error {

	var (
		createOptions *models.DHCPServerCreate
		dhcpServer    *models.DHCPServer
		err           error
	)

	createOptions = &models.DHCPServerCreate{
		Cidr:              ptr.To(dhcpCidr),
//		CloudConnectionID: GUID,
		Name:              ptr.To(dhcpName),
		SnatEnabled:       ptr.To(true),
	}
	log.Debugf("createDhcpServer: createOptions = %+v", createOptions)

	dhcpServer, err = dhcpClient.Create(createOptions)
	if err != nil {
		return fmt.Errorf("Error: dhcpClient.Create returns %v", err)
	}

	// NOTE: Create returns a *models.DHCPServer but we store a *models.DHCPServerDetail
	if shouldDebug { log.Debugf("addDhcpServer: dhcpServer = %+v", dhcpServer) }

	err = waitForDhcpServerCreate(ctx, dhcpClient, *dhcpServer.ID)
	if err != nil {
		return fmt.Errorf("Error: waitForDhcpServerCreate returns %v", err)
	}

	return nil
}

func waitForDhcpServerCreate(ctx context.Context, dhcpClient *instance.IBMPIDhcpClient, id string) error {

	var (
		err error
	)

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
		var (
			detail *models.DHCPServerDetail

			err2 error
		)

		detail, err2 = dhcpClient.Get(id)
		if err2 != nil {
			log.Fatalf("Error: Wait dhcpClient.Get: returns = %v", err2)
			return false, err2
		}
		log.Debugf("waitForDhcpServerCreate: Status = %s", *detail.Status)
		switch *detail.Status {
		case "ACTIVE":
			return true, nil
		case "BUILD":
			return false, nil
		default:
			return true, fmt.Errorf("waitForDhcpServerCreate: unknown state: %s", *detail.Status)
		}
	})
	if err != nil {
		log.Fatalf("Error: waitForDhcpServerCreate: ExponentialBackoffWithContext returns %v", err)
		return err
	}

	return nil
}

func waitForDhcpServerDelete(ctx context.Context, dhcpClient *instance.IBMPIDhcpClient, id string) error {

	var (
		err error
	)

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
		var (
			detail *models.DHCPServerDetail

			err2 error
		)

		detail, err2 = dhcpClient.Get(id)
		if err2 != nil {
			log.Fatalf("Error: Wait dhcpClient.Get: returns = %v", err2)
			return false, err2
		}
		log.Debugf("waitForDhcpServerDelete: Status = %s", *detail.Status)
		switch *detail.Status {
		case "ACTIVE":
			return false, nil
		case "BUILD":
			return false, nil
		default:
			return true, fmt.Errorf("waitForDhcpServerDelete: unknown state: %s", *detail.Status)
		}
	})
	if err != nil {
		log.Fatalf("Error: waitForDhcpServerDelete: ExponentialBackoffWithContext returns %v", err)
		return err
	}

	return nil
}

func main() {

	var (
		logMain *logrus.Logger = &logrus.Logger{
			Out: os.Stderr,
			Formatter: new(logrus.TextFormatter),
			Level: logrus.DebugLevel,
		}
		out               io.Writer
		ptrApiKey         *string
		ptrServiceName    *string
		ptrServiceGUID    *string
		ptrShouldDebug    *string
		piSession         *ibmpisession.IBMPISession
		serviceGuid       string
		ctx               context.Context
		dhcpClient        *instance.IBMPIDhcpClient
		numServers        int
		dhcpName          string = "rdr-hamzy-test-wdc06-bvb58"
		dhcpCidr          string = "192.168.220.0/24"
		err               error
	)

	ptrApiKey = flag.String("apiKey", "", "Your IBM Cloud API key")
	ptrServiceName = flag.String("serviceName", "", "The cloud service name to use")
	ptrServiceGUID = flag.String("serviceGUID", "", "The cloud service GUID to use")
	ptrShouldDebug = flag.String("shouldDebug", "false", "Should output debug output")

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

	if *ptrServiceName == "" && *ptrServiceGUID == "" {
		fmt.Println("Error: No cloud service set, use -serviceName or -serviceGUID")
		os.Exit(1)
	} else if *ptrServiceName != "" && *ptrServiceGUID != "" {
		fmt.Println("Error: Do not use both -serviceName and -serviceGUID together")
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.TODO(), 15*time.Minute)
	defer cancel()

	piSession, serviceGuid, err = createPiSession(ptrApiKey, ptrServiceName, ptrServiceGUID)
	if err != nil {
		err2 := fmt.Errorf("Error: GetQueryParam returns %v", err)
		fmt.Println(err2)
		os.Exit(1)
	}

	dhcpClient = instance.NewIBMPIDhcpClient(ctx, piSession, serviceGuid) 
	if shouldDebug { logMain.Printf("dhcpClient = %v", dhcpClient) }

	numServers, err = listDhcpServers(dhcpClient)
	if err != nil {
		err2 := fmt.Errorf("Error: listDhcpServers returns %v", err)
		fmt.Println(err2)
		os.Exit(1)
	}
	if shouldDebug { logMain.Printf("numServers = %v", numServers) }

	if numServers > 0 {
		var dhcpServer *models.DHCPServerDetail

		dhcpServer, err = findDhcpServer(dhcpName, dhcpClient)
		if err != nil {
			err2 := fmt.Errorf("Error: findDhcpServer returns %v", err)
			fmt.Println(err2)
			os.Exit(1)
		}

		if shouldDebug { logMain.Printf("dhcpServer = %v", dhcpServer) }

		err = dhcpClient.Delete(*dhcpServer.ID)
		if err != nil {
			err2 := fmt.Errorf("Error: dhcpClient.Delete returns %v", err)
			fmt.Println(err2)
			os.Exit(1)
		}

		err = waitForDhcpServerDelete(ctx, dhcpClient, *dhcpServer.ID)
		if err != nil {
			err2 := fmt.Errorf("Error: waitForDhcpServerDelete returns %v", err)
			fmt.Println(err2)
			os.Exit(1)
		}
	} else {
		err = createDhcpServer(ctx, dhcpName, dhcpCidr, dhcpClient)
		if err != nil {
			err2 := fmt.Errorf("Error: createDhcpServer returns %v", err)
			fmt.Println(err2)
			os.Exit(1)
		}
	}
}
