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
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"

	"github.com/IBM-Cloud/power-go-client/power/models"
	"github.com/sirupsen/logrus"
	"k8s.io/utils/ptr"
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
	cos                  *CloudObjectStorage
)

type Mode int

const (
	ModeCreate Mode = iota
	ModeDelete
)

func main() {

	var (
		args     []string
		mode     = ModeCreate
		filename = "vars.json"
		jsonData []byte
		defaults Defaults
		err      error
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

	if true {
		err = setup1zone(mode, defaults)
		if err != nil {
			log.Fatalf("Error: setup1zone returns %v", err)
			panic(err)
		}
	} else {
		err = setup3zone(mode, defaults)
		if err != nil {
			log.Fatalf("Error: setup3zone returns %v", err)
			panic(err)
		}
	}
}

func setup1zone(mode Mode, defaults Defaults) error {

	var (
		exPath            string
		bBootstrapIgn     []byte
		bootstrapUserData string
		bucket            string
		key               string
		err               error
	)

	// 3 zones are predefined.  Delete two of them.
	delete(zoneMap, "zone2")
	delete(zoneMap, "zone3")

	log.Debugf("main: zoneMap = %+v, len(zoneMap) = %d", zoneMap, len(zoneMap))
	if len(zoneMap) != 1 {
		log.Fatalf("Error: setup1zone len(zoneMap) != 1")
		err = fmt.Errorf("Error: setup1zone len(zoneMap) != 1")
		return err
	}

	instantiateCloudObjectStorage(mode, defaults)
	if false {
		panic(fmt.Errorf("HAMZY"))
	}

	instantiateTransitGateway(mode, defaults)

	instantiateVPC(mode, defaults)

	siMap = make(map[string]*ServiceInstance)
	log.Debugf("main: siMap = %+v", siMap)

	for zone := range zoneMap {
		log.Debugf("main: zone = %s", zone)

		instantiateServiceInstance(mode, defaults, zone)
	}

	if len(siMap) != 1 {
		log.Fatalf("Error: setup1zone len(siMap) != 1")
		err = fmt.Errorf("Error: setup1zone len(siMap) != 1")
		return err
	}

	// @TBD - Somewhat hacky
	switch mode {
	case ModeCreate:
		createTransitGatewayConnections(mode, defaults)
	}

	var ipAddresses map[string]string

	ipAddresses = make(map[string]string)

	for siKey := range siMap {
		si := siMap[siKey]
		if !si.Valid() {
			continue
		}

		err = createTestPVM(mode, defaults, si)
		if err != nil {
			log.Fatalf("Error: createTestPVM returns %v", err)
			return err
		}

		ipAddress, err := si.GetInstanceIP()
		if err != nil {
			log.Fatalf("Error: si.GetInstanceIP returns %v", err)
			return err
		}
		ipAddresses[siKey] = ipAddress
	}

	for ipAddrKey := range ipAddresses {
		fmt.Printf("IP address for %s is %s\n", ipAddrKey, ipAddresses[ipAddrKey])
	}

	switch mode {
	case ModeCreate:
		err = createIgnitionFiles(defaults)
		if err != nil {
			log.Fatalf("Error: createIgnitionFiles returns %v", err)
			return err
		}

		exPath, err = executablePath()
		if err != nil {
			log.Fatalf("Error: executablePath returns %v", err)
			return err
		}

		exPath = exPath + "/tmp"

		bBootstrapIgn, err = os.ReadFile(exPath + "/bootstrap.ign")
		if err != nil {
			log.Fatalf("Error: os.ReadFile bootstrap.ign returns %v", err)
			return err
		}
		log.Debugf("setup1zone: bBootstrapIgn = %s", string(bBootstrapIgn))

		bootstrapUserData = base64.StdEncoding.EncodeToString(bBootstrapIgn)
		log.Debugf("setup1zone: bootstrapUserData = %s", bootstrapUserData)

		// @TODO
		bucket = "3zone-bootstrap.ign"
		key = "node-bootstrap"
		err = cos.CreateBucketFile(bucket, key, bootstrapUserData)
		if err != nil {
			log.Fatalf("Error: cos.CreateBucketFile returns %v", err)
			return err
		}

		bBootstrapIgn, err = cos.BucketKeyIgnition(bucket, key)
		if err != nil {
			log.Fatalf("Error: cos.BucketKeyIgnition returns %v", err)
			return err
		}
		log.Debugf("setup1zone: bBootstrapIgn = %s", string(bBootstrapIgn))

		bootstrapUserData = base64.StdEncoding.EncodeToString(bBootstrapIgn)
		log.Debugf("setup1zone: bootstrapUserData = %s", bootstrapUserData)

		err = createBoostrapPVM(mode, defaults, si, bootstrapUserData)
	case ModeDelete:
		// @TBD
		// err = deleteBootstrapPVM()
	}

	return nil
}

func createTestPVM(mode Mode, defaults Defaults, si *ServiceInstance) error {

	var (
		siName          string
		pvmInstanceName string
		networks        [1]models.PVMInstanceAddNetwork
		createNetworks  [1]*models.PVMInstanceAddNetwork
		imageId         string
		userData        string
		createOptions   models.PVMInstanceCreate
		instance        *models.PVMInstance
		err             error
	)

	siName, err = si.Name()
	if err != nil {
		log.Fatalf("Error: si.Name returns %v", err)
		return err
	}

	pvmInstanceName = fmt.Sprintf("%s-instance", siName)
	log.Debugf("createTestPVM: pvmInstanceName = %s", pvmInstanceName)

	instance, err = si.findPVMInstance(pvmInstanceName)
	if err != nil {
		log.Fatalf("Error: createTestPVM: findPVMInstance returns %v", err)
		return err
	}
	log.Debugf("createTestPVM: instance = %+v", instance)
	if instance != nil {
		return nil
	}

	// Is there a better way to do this?
	// @HACK
	if false {
		networks[0].NetworkID, err = si.GetNetworkID()
		if err != nil {
			log.Fatalf("Error: createTestPVM: si.GetNetworkID returns %v", err)
			return err
		}
	} else {
		networks[0].NetworkID, err = si.GetDhcpServerID()
		if err != nil {
			log.Fatalf("Error: createTestPVM: si.GetDhcpServerID returns %v", err)
			return err
		}
	}
	log.Debugf("createTestPVM: networks = %+v", networks)
	createNetworks[0] = &networks[0]

	if false {
		imageId = si.GetStockImageId()
		userData = base64.StdEncoding.EncodeToString([]byte(si.testCloudinitUserData()))
	} else {
		imageId = si.GetRhcosImageId()
		userData = base64.StdEncoding.EncodeToString([]byte(si.testIgnitionUserData()))
	}

	createOptions = models.PVMInstanceCreate{
		ImageID:    &imageId,
		Memory:     ptr.To(8.0),
		Networks:   createNetworks[:],
		ProcType:   ptr.To("shared"),
		Processors: ptr.To(1.0),
		ServerName: &pvmInstanceName,
		// SysType: ptr.To(""),
		UserData:   userData,
	}
	log.Debugf("createTestPVM: createOptions = %+v", createOptions)

	err = si.createPVMInstance(createOptions)
	if err != nil {
		log.Fatalf("Error: createPVMInstance returns %v", err)
		return err
	}

	return err
}

func createBoostrapPVM(mode Mode, defaults Defaults, si *ServiceInstance, bootstrapUserData string) error {

	var (
		siName          string
		pvmInstanceName string
		networks        [1]models.PVMInstanceAddNetwork
		createNetworks  [1]*models.PVMInstanceAddNetwork
		imageId         string
		createOptions   models.PVMInstanceCreate
		instance        *models.PVMInstance
		err             error
	)

	siName, err = si.Name()
	if err != nil {
		log.Fatalf("Error: si.Name returns %v", err)
		return err
	}

	pvmInstanceName = fmt.Sprintf("%s-bootstrap", siName)
	log.Debugf("createBoostrapPVM: pvmInstanceName = %s", pvmInstanceName)

	instance, err = si.findPVMInstance(pvmInstanceName)
	if err != nil {
		log.Fatalf("Error: createBoostrapPVM: findPVMInstance returns %v", err)
		return err
	}
	log.Debugf("createBoostrapPVM: instance = %+v", instance)
	if instance != nil {
		return nil
	}

	// Is there a better way to do this?
	// @HACK
	if false {
		networks[0].NetworkID, err = si.GetNetworkID()
		if err != nil {
			log.Fatalf("Error: createBoostrapPVM: si.GetNetworkID returns %v", err)
			return err
		}
	} else {
		networks[0].NetworkID, err = si.GetDhcpServerID()
		if err != nil {
			log.Fatalf("Error: createBoostrapPVM: si.GetDhcpServerID returns %v", err)
			return err
		}
	}
	createNetworks[0] = &networks[0]

	imageId = si.GetRhcosImageId()

	createOptions = models.PVMInstanceCreate{
		ImageID:    &imageId,
		Memory:     ptr.To(8.0),
		Networks:   createNetworks[:],
		ProcType:   ptr.To("shared"),
		Processors: ptr.To(1.0),
		ServerName: &pvmInstanceName,
		// SysType: ptr.To(""),
		UserData:   bootstrapUserData,
	}
	log.Debugf("createBoostrapPVM: createOptions = %+v", createOptions)

	err = si.createPVMInstance(createOptions)
	if err != nil {
		log.Fatalf("Error: createBoostrapPVM returns %v", err)
		return err
	}

	return err
}

func setup3zone(mode Mode, defaults Defaults) error {

	log.Debugf("main: zoneMap = %+v", zoneMap)

	siMap = make(map[string]*ServiceInstance)
	log.Debugf("main: siMap = %+v", siMap)

	instantiateCloudObjectStorage(mode, defaults)

	instantiateTransitGateway(mode, defaults)

	instantiateVPC(mode, defaults)

	for zone := range zoneMap {
		log.Debugf("main: zone = %s", zone)

		instantiateServiceInstance(mode, defaults, zone)
	}

	// @TBD - Somewhat hacky
	switch mode {
	case ModeCreate:
		createTransitGatewayConnections(mode, defaults)
	}

	var ipAddresses map[string]string

	ipAddresses = make(map[string]string)

	for siKey := range siMap {
		si := siMap[siKey]
		if !si.Valid() {
			continue
		}

		ipAddress, err := si.GetInstanceIP()
		if err != nil {
			log.Fatalf("Error: si.GetInstanceIP returns %v", err)
			return err
		}
		ipAddresses[siKey] = ipAddress
	}

	for ipAddrKey := range ipAddresses {
		fmt.Printf("IP address for %s is %s\n", ipAddrKey, ipAddresses[ipAddrKey])
	}

	return nil
}

func instantiateVPC(mode Mode, defaults Defaults) {

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
		log.Debugf("instantiateVPC: zone = %s", zone)

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

			err = vpc.setSubnetPublicGateway(rsv.VPCZoneName)
			if err != nil {
				log.Fatalf("Error: setSubnetPublicGateway returns %v", err)
			}

			if zone == "zone1" {
				// BEGIN HACK
				err = vpc.createInstance(rsv.VPCZoneName)
				if err != nil {
					log.Fatalf("Error: vpc.createInstance returns %v", err)
					panic(err)
				}
				// END HACK
			}
		}
	}
}

func instantiateServiceInstance(mode Mode, defaults Defaults, zone string) {

	var (
		siOptions ServiceInstanceOptions
		rsv       RSV
		iface     RunnableObject
		err       error
	)

	log.Debugf("main: zone = %s", zone)

	rsv, err = RSVForRegionZone(defaults.Region, zone)
	log.Debugf("instantiateServiceInstance: rsv = %+v, err = %v", rsv, err)

	siOptions = ServiceInstanceOptions{
		Mode:    mode,
		ApiKey:  defaults.ApiKey,
		Region:  defaults.Region,
		Name:    defaults.VPCS[zone]["pvs_workspace_name"],
		Zone:    rsv.WSZoneName,
		GroupID: defaults.GroupID,
		CIDR:    defaults.VPCS[zone]["pvs_dc_cidr"],
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

func instantiateTransitGateway(mode Mode, defaults Defaults) {

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

func instantiateCloudObjectStorage(mode Mode, defaults Defaults) {

	var (
		cosOptions CloudObjectStorageOptions
		iface      RunnableObject
		err        error
	)

	cosOptions = CloudObjectStorageOptions{
		Mode:    mode,
		ApiKey:  defaults.ApiKey,
		Name:    "rdr-hamzy-3zone-cos",
		GroupID: defaults.GroupID,
		Region:  defaults.Region,
	}
	cos, err = NewCloudObjectStorage(cosOptions)
	if err != nil {
		log.Fatalf("Error: NewCloudObjectStorage returns %v", err)
	}
	log.Debugf("main: cos = %+v", cos)
	iface = cos

	err = iface.Run()
	if err != nil {
		log.Fatalf("Error: cos.Run returns %v", err)
	}
}

func Exists(filename string) (bool, error) {

	var (
		err error
	)

	_, err = os.Stat(filename)
	if os.IsNotExist(err) {
		return false, nil
	}

	return err == nil, err
}

type InstallConfig struct {
	BaseDomain          string
	ClusterName         string
	Email               string
	PullSecret          string
	PowerVSRegion       string
	ResourceGroup       string
	ServiceInstanceGUID string
	SshKey              string
	VpcName             string
	Zone                string
}

func createInstallConfig(defaults Defaults, directory string) error {

	var (
		homeDirectory string

		filePullSecrets string

		pullSecrets []byte

		ic InstallConfig

		tmpl *template.Template

		f *os.File

		err error
	)

	homeDirectory, err = os.UserHomeDir()
	if err != nil {
		log.Fatalf("Error: os.UserHomeDir returns %v", err)
		return err
	}

	filePullSecrets = homeDirectory + "/.pullSecretCompact"
	if ok, err := Exists(filePullSecrets); ok {
		pullSecrets, err = os.ReadFile(filePullSecrets)
		if err != nil {
			log.Fatalf("Error: os.ReadFile(%s) returns %v", filePullSecrets, err)
			return err
		}
	} else {
		log.Fatalf("Error: File %s does not exist", filePullSecrets)
		return fmt.Errorf("Error: File %s does not exist", filePullSecrets)
	}

	if ok, err := Exists(directory + "/install-config.yaml"); ok {
		return err
	}

	ic = InstallConfig{
		BaseDomain:          defaults.BaseDomain,
		ClusterName:         defaults.ClusterName,
		Email:               defaults.Email,
		PullSecret:          string(pullSecrets),
		PowerVSRegion:       defaults.PowerVSRegion,
		ResourceGroup:       defaults.ResourceGroup,
		ServiceInstanceGUID: defaults.ServiceInstanceGUID,
		SshKey:              defaults.SshKey,
		VpcName:             defaults.VpcName,
		Zone:                defaults.Zone,
	}

	// https://pkg.go.dev/text/template#Template
	tmpl, err = template.New("test").Parse(`apiVersion: v1
baseDomain: "{{.BaseDomain}}"
compute:
- architecture: ppc64le
  hyperthreading: Enabled
  name: worker
  platform: {}
  replicas: 3
controlPlane:
  architecture: ppc64le
  hyperthreading: Enabled
  name: master
  platform: {}
  replicas: 3
metadata:
  creationTimestamp: null
  name: "{{.ClusterName}}"
networking:
  clusterNetwork:
  - cidr: 10.128.0.0/14
    hostPrefix: 23
  machineNetwork:
  - cidr: 192.168.220.0/24
  networkType: OVNKubernetes
  serviceNetwork:
  - 172.30.0.0/16
platform:
  powervs:
    userID: {{.Email}}
    powervsResourceGroup: {{.ResourceGroup}}
    region: {{.PowerVSRegion}}
    vpcName: {{.VpcName}}
    zone: {{.Zone}}
    serviceInstanceGUID: {{.ServiceInstanceGUID}}
featureSet: CustomNoUpgrade
featureGates:
   - ClusterAPIInstall=true
publish: External
pullSecret: '{{.PullSecret}}'
sshKey: |
  {{.SshKey}}`)
	if err != nil {
		log.Fatalf("Error: template.New.Parse returns %v", err)
		return err
	}

	f, err = os.Create(directory + "/install-config.yaml")
	if err != nil {
		log.Fatalf("Error: os.Create returns %v", err)
		return err
	}

	err = tmpl.Execute(os.Stdout, ic)
	if err != nil {
		log.Fatalf("Error: tmpl.Execute(1) returns %v", err)
		return err
	}

	err = tmpl.Execute(f, ic)
	if err != nil {
		log.Fatalf("Error: tmpl.Execute(2) returns %v", err)
		return err
	}

	err = f.Close()
	if err != nil {
		log.Fatalf("Error: f.Close returns %v", err)
		return err
	}

	return err
}

func executablePath() (string, error) {

	var (
		exPath string
		err    error
	)

	ex, err := os.Executable()
	if err != nil {
		log.Fatalf("Error: executablePath os.Executable returns %v", err)
		return "", err
	}
	exPath = filepath.Dir(ex)
	log.Debugf("executablePath: exPath = %s", exPath)

	return exPath, err
}

func createIgnitionFiles(defaults Defaults) error {

	var (
		ignitionFiles []string = []string {
			"master.ign",
			"worker.ign",
			"bootstrap.ign",
		}
		missingOne = false
		ok          bool
		exPath      string
		oiDirectory string
		cmd         *exec.Cmd
		err         error
	)

	ex, err := os.Executable()
	if err != nil {
		log.Fatalf("Error: createIgnitionFiles os.Executable returns %v", err)
		return err
	}
	exPath = filepath.Dir(ex)
	log.Debugf("createIgnitionFiles: exPath = %s", exPath)

	for _, filename := range ignitionFiles {
		if ok, err = Exists(filename); ok {
			log.Debugf("createIgnitionFiles: FOUND %s", filename)
			continue
		}
		if err != nil {
			log.Fatalf("Error: createIgnitionFiles Exists returns %v", err)
			return err
		}
		log.Debugf("createIgnitionFiles: MISSING %s", filename)
		missingOne = true
	}

	if !missingOne {
		return nil
	}

	// Does the openshift-install directory exist?
	oiDirectory = exPath + "/tmp"
	log.Debugf("createIgnitionFiles: oiDirectory = %s", oiDirectory)

	if _, err := os.Stat(oiDirectory); err == nil {
		// oiDirectory exists
	} else if errors.Is(err, os.ErrNotExist) {
		// oiDirectory does *not* exist
		err = os.Mkdir(oiDirectory, os.ModePerm)
		if err != nil {
			log.Fatalf("Error: createIgnitionFiles os.Mkdir returns %v", err)
			return err
		}
	} else {
		log.Fatalf("Error: createIgnitionFiles os.Stat(%s) returns %v", oiDirectory, err)
		return err
	}

	// Does the install-config.yaml file exist?
	err = createInstallConfig(defaults, oiDirectory)
	if err != nil {
		log.Fatalf("Error: createIgnitionFiles createInstallConfig returns %v", err)
		return err
	}

	// Run openshift-install
	cmd = exec.Command("openshift-install", "create", "ignition-configs", "--dir", oiDirectory)

	log.Debugf("createIgnitionFiles: cmd = %+v", cmd)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	if err != nil {
		log.Fatalf("Error: createIgnitionFiles cmd.Run returns %v", err)
		return err
	}

	return err
}
