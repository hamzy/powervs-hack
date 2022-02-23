package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"
	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/networking-go-sdk/zonesv1"
	"github.com/IBM/platform-services-go-sdk/resourcecontrollerv2"
	"github.com/IBM/platform-services-go-sdk/resourcemanagerv2"
	"github.com/IBM/vpc-go-sdk/vpcv1"
	"github.com/pkg/errors"
)

func prettyPrint(i interface{}) string {
    s, _ := json.MarshalIndent(i, "", "\t")
    return string(s)
}

// Client makes calls to the PowerVS API.
type Client struct {
	managementAPI *resourcemanagerv2.ResourceManagerV2
	controllerAPI *resourcecontrollerv2.ResourceControllerV2
	vpcAPI        *vpcv1.VpcV1
	Authenticator *core.IamAuthenticator
}

// cisServiceID is the Cloud Internet Services' catalog service ID.
const cisServiceID = "75874a60-cb12-11e7-948e-37ac098eb1b9"

// DNSZoneResponse represents a DNS zone response.
type DNSZoneResponse struct {
	// Name is the domain name of the zone.
	Name string

	// ID is the zone's ID.
	ID string

	// CISInstanceCRN is the IBM Cloud Resource Name for the CIS instance where
	// the DNS zone is managed.
	CISInstanceCRN string

	// CISInstanceName is the display name of the CIS instance where the DNS zone
	// is managed.
	CISInstanceName string

	// ResourceGroupID is the resource group ID of the CIS instance.
	ResourceGroupID string
}

// NewClient initializes a client with a session.
func NewClient() (*Client, error) {
	apiKey := os.Getenv("IC_API_KEY")
	log.Printf("NewClient: apiKey = %v", apiKey)
	authenticator := &core.IamAuthenticator{
		ApiKey: apiKey,
//		URL :"https://iam.cloud.ibm.com",
	}
	log.Printf("NewClient: authenticator = %v", prettyPrint(&authenticator))

	client := &Client{
		Authenticator: authenticator,
	}

	if err := client.loadSDKServices(); err != nil {
		return nil, errors.Wrap(err, "failed to load IBM SDK services")
	}

	return client, nil
}

func (c *Client) loadSDKServices() error {
	servicesToLoad := []func() error{
		c.loadResourceManagementAPI,
		c.loadResourceControllerAPI,
		c.loadVPCV1API,
	}

	// Call all the load functions.
	for _, fn := range servicesToLoad {
		if err := fn(); err != nil {
			return err
		}
	}

	return nil
}

// GetDNSZoneIDByName gets the CIS zone ID from its domain name.
func (c *Client) GetDNSZoneIDByName(ctx context.Context, name string) (string, error) {

	zones, err := c.GetDNSZones(ctx)
	log.Printf("GetDNSZoneIDByName: %v %v", zones, err)
	if err != nil {
		return "", err
	}

	for _, z := range zones {
		if z.Name == name {
			return z.ID, nil
		}
	}

	return "", fmt.Errorf("DNS zone %q not found", name)
}

// GetDNSZones returns all of the active DNS zones managed by CIS.
func (c *Client) GetDNSZones(ctx context.Context) ([]DNSZoneResponse, error) {
	_, cancel := context.WithTimeout(ctx, 1*time.Minute)
	defer cancel()

	options := c.controllerAPI.NewListResourceInstancesOptions()
	options.SetResourceID(cisServiceID)

	listResourceInstancesResponse, _, err := c.controllerAPI.ListResourceInstances(options)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get cis instance")
	}

	var allZones []DNSZoneResponse
	for _, instance := range listResourceInstancesResponse.Resources {
		crnstr := instance.CRN
		zonesService, err := zonesv1.NewZonesV1(&zonesv1.ZonesV1Options{
			Authenticator: c.Authenticator,
			Crn:           crnstr,
		})
		if err != nil {
			return nil, errors.Wrap(err, "failed to list DNS zones")
		}

		options := zonesService.NewListZonesOptions()
		listZonesResponse, _, err := zonesService.ListZones(options)

		if listZonesResponse == nil {
			return nil, err
		}

		for _, zone := range listZonesResponse.Result {
			if *zone.Status == "active" {
				zoneStruct := DNSZoneResponse{
					Name:            *zone.Name,
					ID:              *zone.ID,
					CISInstanceCRN:  *instance.CRN,
					CISInstanceName: *instance.Name,
					ResourceGroupID: *instance.ResourceGroupID,
				}
				allZones = append(allZones, zoneStruct)
			}
		}
	}

	return allZones, nil
}

func (c *Client) loadResourceManagementAPI() error {
	options := &resourcemanagerv2.ResourceManagerV2Options{
		Authenticator: c.Authenticator,
	}
	resourceManagerV2Service, err := resourcemanagerv2.NewResourceManagerV2(options)
	if err != nil {
		return err
	}
	c.managementAPI = resourceManagerV2Service
	return nil
}

func (c *Client) loadResourceControllerAPI() error {
	options := &resourcecontrollerv2.ResourceControllerV2Options{
		Authenticator: c.Authenticator,
	}
	resourceControllerV2Service, err := resourcecontrollerv2.NewResourceControllerV2(options)
	if err != nil {
		return err
	}
	c.controllerAPI = resourceControllerV2Service
	return nil
}

func (c *Client) loadVPCV1API() error {
	vpcService, err := vpcv1.NewVpcV1(&vpcv1.VpcV1Options{
		Authenticator: c.Authenticator,
	})
	if err != nil {
		return err
	}
	c.vpcAPI = vpcService
	return nil
}

func main() {
	client, err := NewClient()
	if err != nil {
		log.Printf("failed to get IBM Cloud client: %v", err)
		os.Exit(1)
	}

	zoneID, err := client.GetDNSZoneIDByName(context.TODO(), "scnl-ibm.com")
	if err != nil {
		log.Printf("failed to get DNS zone ID: %v", err)
		os.Exit(1)
	}
	log.Printf("zoneID = %v", zoneID)
}
