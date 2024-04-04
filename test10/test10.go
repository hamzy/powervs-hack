package main

import (
	"fmt"
	"os"
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/sirupsen/logrus"
)

var (
	log *logrus.Logger = &logrus.Logger{
		Out:       os.Stderr,
		Formatter: new(logrus.TextFormatter),
		Level:     logrus.DebugLevel,
	}
)

func GetRegion(zone string) (region string, err error) {
	err = nil
	switch {
	case strings.HasPrefix(zone, "us-south"):
		region = "us-south"
	case strings.HasPrefix(zone, "dal"):
		region = "dal"
	case strings.HasPrefix(zone, "sao"):
		region = "sao"
	case strings.HasPrefix(zone, "us-east"):
		region = "us-east"
	case strings.HasPrefix(zone, "tor"):
		region = "tor"
	case strings.HasPrefix(zone, "eu-de-"):
		region = "eu-de"
	case strings.HasPrefix(zone, "lon"):
		region = "lon"
	case strings.HasPrefix(zone, "syd"):
		region = "syd"
	case strings.HasPrefix(zone, "tok"):
		region = "tok"
	case strings.HasPrefix(zone, "osa"):
		region = "osa"
	case strings.HasPrefix(zone, "mon"):
		region = "mon"
	case strings.HasPrefix(zone, "mad"):
		region = "mad"
	case strings.HasPrefix(zone, "wdc"):
		region = "wdc"
	default:
		return "", fmt.Errorf("region not found for the zone, talk to the developer to add the support into the tool: %s", zone)
	}
	return
}

// Region describes respective IBM Cloud COS region, VPC region and Zones associated with a region in Power VS.
type Region struct {
	Description  string
	VPCRegion    string
	COSRegion    string
	Zones        []string
	SysTypes     []string
	IPISupported bool
}

// Regions provides a mapping between Power VS and IBM Cloud VPC and IBM COS regions.
var Regions = FullRegions

// Switch the list of regions to all of the regions.
func UseFullRegions () {
	Regions = FullRegions
}

// Switch the list of regions to only the regions supported by the IPI installer.
func UseIPIRegions () {
	IPIRegions = make(map[string]Region)

	for region := range FullRegions {
		if FullRegions[region].IPISupported {
			IPIRegions[region] = Region{
				Description:  FullRegions[region].Description,
				VPCRegion:    FullRegions[region].VPCRegion,
				COSRegion:    FullRegions[region].COSRegion,
				Zones:        FullRegions[region].Zones,
				SysTypes:     FullRegions[region].SysTypes,
				IPISupported: FullRegions[region].IPISupported,
			}
		}
	}

	Regions = IPIRegions
}

var FullRegions = map[string]Region{
	"dal": {
		Description:  "Dallas, USA",
		VPCRegion:    "us-south",
		COSRegion:    "us-south",
		Zones:        []string{
			"dal10",
			"dal12",
		},
		SysTypes:     []string{"s922", "e980"},
		IPISupported: true,
	},
	"eu-de": {
		Description:  "Frankfurt, Germany",
		VPCRegion:    "eu-de",
		COSRegion:    "eu-de",
		Zones: []string{
			"eu-de-1",
			"eu-de-2",
		},
		SysTypes:     []string{"s922", "e980"},
		IPISupported: true,
	},
	"lon": {
		Description:  "London, UK.",
		VPCRegion:    "eu-gb",
		COSRegion:    "eu-gb",
		Zones: []string{
			"lon04",
			"lon06",
		},
		SysTypes:     []string{"s922", "e980"},
		IPISupported: false,
	},
	"mad": {
		Description:  "Madrid, Spain",
		VPCRegion:    "eu-es",
		COSRegion:    "eu-de",		// @HACK - PowerVS says COS not supported in this region
		Zones: []string{
			"mad02",
			"mad04",
		},
		SysTypes:     []string{"s1022"},
		IPISupported: true,
	},
	"mon": {
		Description:  "Montreal, Canada",
		VPCRegion:    "ca-tor",
		COSRegion:    "ca-tor",
		Zones:        []string{"mon01"},
		SysTypes:     []string{"s922", "e980"},
		IPISupported: false,
	},
	"osa": {
		Description:  "Osaka, Japan",
		VPCRegion:    "jp-osa",
		COSRegion:    "jp-osa",
		Zones:        []string{"osa21"},
		SysTypes:     []string{"s922", "e980"},
		IPISupported: false,
	},
	"syd": {
		Description:  "Sydney, Australia",
		VPCRegion:    "au-syd",
		COSRegion:    "au-syd",
		Zones: []string{
			"syd04",
			"syd05",
		},
		SysTypes:     []string{"s922", "e980"},
		IPISupported: false,
	},
	"sao": {
		Description:  "São Paulo, Brazil",
		VPCRegion:    "br-sao",
		COSRegion:    "br-sao",
		Zones:        []string{
			"sao01",
			"sao04",
		},
		SysTypes:     []string{"s922", "e980"},
		IPISupported: true,
	},
	"tok": {
		Description:  "Tokyo, Japan",
		VPCRegion:    "jp-tok",
		COSRegion:    "jp-tok",
		Zones:        []string{"tok04"},
		SysTypes:     []string{"s922", "e980"},
		IPISupported: false,
	},
	"us-east": {
		Description:  "Washington DC, USA",
		VPCRegion:    "us-east",
		COSRegion:    "us-east",
		Zones:        []string{"us-east"},
		SysTypes:     []string{}, // Missing
		IPISupported: false,
	},
	"wdc": {
		Description:  "Washington DC, USA",
		VPCRegion:    "us-east",
		COSRegion:    "us-east",
		Zones: []string{
			"wdc06",
			"wdc07",
		},
		SysTypes:     []string{"s922", "e980"},
		IPISupported: true,
	},
}

var IPIRegions = map[string]Region{}

// COSRegionForVPCRegion returns the corresponding COS region for the given VPC region
func COSRegionForVPCRegion(vpcRegion string) (string, error) {
	for r := range Regions {
		if vpcRegion == Regions[r].VPCRegion {
			return Regions[r].COSRegion, nil
		}
	}

	return "", fmt.Errorf("COS region corresponding to a VPC region %s not found ", vpcRegion)
}

// VPCRegionForPowerVSRegion returns the VPC region for the specified PowerVS region.
func VPCRegionForPowerVSRegion(region string) (string, error) {
	if r, ok := Regions[region]; ok {
		return r.VPCRegion, nil
	}

	return "", fmt.Errorf("VPC region corresponding to a PowerVS region %s not found ", region)
}

// COSRegionForPowerVSRegion returns the IBM COS region for the specified PowerVS region.
func COSRegionForPowerVSRegion(region string) (string, error) {
	if r, ok := Regions[region]; ok {
		return r.COSRegion, nil
	}

	return "", fmt.Errorf("COS region corresponding to a PowerVS region %s not found ", region)
}

// ValidateVPCRegion validates that given VPC region is known/tested.
func ValidateVPCRegion(region string) bool {
	for r := range Regions {
		if region == Regions[r].VPCRegion {
			return true
		}
	}
	return false
}

// ValidateCOSRegion validates that given COS region is known/tested.
func ValidateCOSRegion(region string) bool {
	for r := range Regions {
		if region == Regions[r].COSRegion {
			return true
		}
	}
	return false
}

// RegionShortNames returns the list of region names
func RegionShortNames() []string {
	var keys []string
	for r := range Regions {
		keys = append(keys, r)
	}
	return keys
}

// ValidateZone validates that the given zone is known/tested.
func ValidateZone(zone string) bool {
	for r := range Regions {
		for z := range Regions[r].Zones {
			if zone == Regions[r].Zones[z] {
				return true
			}
		}
	}
	return false
}

// ZoneNames returns the list of zone names.
func ZoneNames() []string {
	zones := []string{}
	for r := range Regions {
		for z := range Regions[r].Zones {
			zones = append(zones, Regions[r].Zones[z])
		}
	}
	return zones
}

// RegionFromZone returns the region name for a given zone name.
func RegionFromZone(zone string) string {
	for r := range Regions {
		for z := range Regions[r].Zones {
			if zone == Regions[r].Zones[z] {
				return r
			}
		}
	}
	return ""
}

// AvailableSysTypes returns the default system type for the zone.
func AvailableSysTypes(region string) ([]string, error) {
	knownRegion, ok := Regions[region]
	if !ok {
		return nil, fmt.Errorf("unknown region name provided")
	}
	return knownRegion.SysTypes, nil
}

// AllKnownSysTypes returns aggregated known system types from all regions.
func AllKnownSysTypes() sets.Set[string] {
	sysTypes := sets.New[string]()
	for _, region := range Regions {
		sysTypes.Insert(region.SysTypes...)
	}
	return sysTypes
}

func PrintRegions() {
	log.Debugf("Printing regions:\n")
	for region := range Regions {
		log.Debugf("region = %v\n", region)
		log.Debugf("Description: %v\n", Regions[region].Description)
	}
}

func main() {

	log.Debug("Testing default regions:")

	log.Debugf("FullRegions length = %d\n", len(FullRegions))
	for region := range FullRegions {
		log.Debugf("Description: %v\n", FullRegions[region].Description)
	}
	PrintRegions()

	UseIPIRegions ()

	log.Debugf("IPIRegions length = %d\n", len(IPIRegions))
	for region := range IPIRegions {
		log.Debugf("Description: %v\n", IPIRegions[region].Description)
	}
	PrintRegions()
}
