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

// (cd 3zoneocp/; /bin/rm go.*; go mod init example/user/3ZoneOcp; go mod tidy)
// (cd 3zoneocp/; echo "vet:"; go vet || exit 1; echo "build:"; go build *.go || exit 1; echo "run:"; ./3ZoneOcp -mode=create)

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/sirupsen/logrus"
)

var (
	log *logrus.Logger = &logrus.Logger{
		Out:       os.Stderr,
		Formatter: new(logrus.TextFormatter),
		Level:     logrus.DebugLevel,
	}

	zoneMap              map[string]RSV
	vpc                  *VPC
	si                   *ServiceInstance
	siMap                map[string]*ServiceInstance
	tg                   *TransitGateway
)

type Mode int

const (
	ModeCreate Mode = iota
	ModeDelete
)

func main() {

	var (
		args                 []string
		mode                 = ModeCreate
		filename             = "vars.json"
		jsonData             []byte
		defaults             Defaults
		err                  error
	)

	flag.Func("mode", "Either create or delete", func(flagValue string) error {
		for allowedKey, allowedValue := range map[string]Mode{
			"create": ModeCreate,
			"delete": ModeDelete,
		} {
			if flagValue == allowedKey {
				mode = allowedValue
				return nil
			}
		}
		return fmt.Errorf(`must be one of "create" or "delete"`)
	})

	flag.Parse()
	args = flag.Args()

	log.Debugf("main: args = %v", args)
	log.Debugf("main: mode = %d", mode)
	log.Debugf("main: region_specific_values = %+v", region_specific_values)

	_, err = os.Stat(filename)
	log.Debugf("main: os.Stat(\"%v\") = %v", filename, err)
	if err != nil {
		log.Fatalf("Error: when finding %s: %v", filename, err)
		panic(err)
	}

	// Read the json file
	jsonData, err = ioutil.ReadFile(filename)
	if err != nil {
		log.Fatalf("Error: when reading %s: %v", filename, err)
		panic(err)
	}

	// Return the default struct from the file data
	defaults, err = read_defaults(jsonData)
	if err != nil {
		log.Fatalf("Error: read_defaults returns %v", err)
		panic(err)
	}
	log.Debugf("main: defaults = %+v", defaults)

	zoneMap, err = RSVMapForRegion(defaults.Region)
	if err != nil {
		log.Fatalf("Error: RSVMapForRegion returns %v", err)
		panic(err)
	}

	// BEGIN HACK
	delete(zoneMap, "zone2")
	delete(zoneMap, "zone3")
	log.Debugf("main: zoneMap = %+v", zoneMap)
	// END HACK

	siMap = make(map[string]*ServiceInstance)

	createTransitGateway(mode, defaults)

	createVPC(mode, defaults)

	for zone := range zoneMap {
		log.Debugf("main: zone = %s", zone)

		createServiceInstance(mode, defaults, zone)
	}

	log.Debugf("main: siMap = %+v", siMap)

	// @TBD - Somewhat hacky
	switch mode {
	case ModeCreate:
		createTransitGatewayConnections(mode, defaults)
	}
}

func createVPC(mode Mode, defaults Defaults) {

	var (
		vpcOptions           VPCOptions
		createSubnetOptions  SubnetOptions
		addressPrefixOptions AddressPrefixOptions
		iface                RunnableObject
		rsv                  RSV
		err                  error
	)

	vpcOptions = VPCOptions{
		Mode:    mode,
		ApiKey:  defaults.ApiKey,
		Region:  defaults.Region,
		Name:    "rdr-hamzy-3zone-vpc", // defaults.VPCS[zone]["pvs_workspace_name"],
		GroupID: defaults.GroupID,
	}

	vpc, err = NewVPC(vpcOptions)
	if err != nil {
		log.Fatalf("Error: NewVPC returns %v", err)
	}
	log.Debugf("main: vpc = %+v", vpc)

	iface = vpc

	err = iface.Run()
	if err != nil {
		log.Fatalf("Error: vpc.Run returns %v", err)
	}

	for zone := range zoneMap {
		log.Debugf("createVPC: zone = %s", zone)

		rsv, err = RSVForRegionZone(defaults.Region, zone)
		log.Debugf("main: rsv = %+v, err = %v", rsv, err)

		// @TBD - Somewhat hacky
		switch mode {
		case ModeCreate:
			addressPrefixOptions = AddressPrefixOptions{
				Zone: rsv.VPCZoneName,
				CIDR: defaults.VPCS[zone]["vpc_zone_cidr"],
			}

			err = vpc.addAddressPrefixVPC(addressPrefixOptions)
			if err != nil {
				log.Fatalf("Error: addAddressPrefixVPC returns %v", err)
			}

			createSubnetOptions = SubnetOptions{
				Name:    fmt.Sprintf("%s-%s-subnet", vpc.options.Name, rsv.VPCZoneName),
				Zone:    rsv.VPCZoneName,
				GroupID: defaults.GroupID,
				CIDR:    defaults.VPCS[zone]["vpc_zone_cidr"],
			}

			err = vpc.addSubnet(createSubnetOptions)
			if err != nil {
				log.Fatalf("Error: addSubnet returns %v", err)
			}

			err = vpc.addPublicGateway(rsv.VPCZoneName)
			if err != nil {
				log.Fatalf("Error: addPublicGateway returns %v", err)
			}

			// BEGIN HACK
			err = vpc.createInstance(rsv.VPCZoneName)
			if err != nil {
				log.Fatalf("Error: vpc.createInstance returns %v", err)
				panic(err)
			}
			// END HACK
		case ModeDelete:
			// BEGIN HACK
			err = vpc.deleteInstance(rsv.VPCZoneName)
			if err != nil {
				log.Fatalf("Error: vpc.deleteInstance returns %v", err)
				panic(err)
			}
			// END HACK
		}
	}
}

func createServiceInstance(mode Mode, defaults Defaults, zone string) {

	var (
		siOptions ServiceInstanceOptions
		rsv       RSV
		iface     RunnableObject
		err       error
	)

	log.Debugf("main: zone = %s", zone)

	rsv, err = RSVForRegionZone(defaults.Region, zone)
	log.Debugf("createServiceInstance: rsv = %+v, err = %v", rsv, err)

	siOptions = ServiceInstanceOptions{
		Mode:    mode,
		ApiKey:  defaults.ApiKey,
		Region:  defaults.Region,
		Name:    defaults.VPCS[zone]["pvs_workspace_name"],
		Zone:    rsv.WSZoneName,
		GroupID: defaults.GroupID,
		CIDR:    defaults.VPCS[zone]["vpc_zone_cidr"],
		SshKey:  defaults.SshKey,
	}

	si, err = NewServiceInstance(siOptions)
	if err != nil {
		log.Fatalf("Error: NewServiceInstance returns %v", err)
	}
	iface = si

	err = iface.Run()
	if err != nil {
		log.Fatalf("Error: si.Run returns %v", err)
	}

	siMap[zone] = si
}

func createTransitGateway(mode Mode, defaults Defaults) {

	var (
		tgOptions            TransitGatewayOptions
		iface                RunnableObject
		err                  error
	)

	tgOptions = TransitGatewayOptions{
		Mode:   mode,
		ApiKey: defaults.ApiKey,
		Name:   "rdr-hamzy-3zone-tg", // defaults.VPCS[zone]["pvs_workspace_name"],
		Region: defaults.Region,
	}
	tg, err = NewTransitGateway(tgOptions)
	if err != nil {
		log.Fatalf("Error: NewTransitGateway returns %v", err)
	}
	log.Debugf("main: tg = %+v", tg)
	iface = tg

	err = iface.Run()
	if err != nil {
		log.Fatalf("Error: tg.Run returns %v", err)
	}
}

func createTransitGatewayConnections(mode Mode, defaults Defaults) {

	var (
		crn string
		err error
	)

	// @TBD - Somewhat hacky
	switch mode {
	case ModeCreate:
		crn, err = vpc.CRN()
		if err != nil {
			log.Fatalf("Error: vpc.CRN returns %v", err)
		}
		err = tg.AddTransitGatewayConnection(crn, NETWORK_TYPE_VPC)
		if err != nil {
			log.Fatalf("Error: tg.AddTransitGatewayConnection(%s) returns %v", crn, err)
		}

		for _, si := range siMap {
			crn, err = si.CRN()
			if err != nil {
				log.Fatalf("Error: si.CRN returns %v", err)
			}
			err = tg.AddTransitGatewayConnection(crn, NETWORK_TYPE_PVS)
			if err != nil {
				log.Fatalf("Error: tg.AddTransitGatewayConnection(%s) returns %v", crn, err)
			}
		}
	}
}
