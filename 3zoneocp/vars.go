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

package main

import (
	"encoding/json"
	"io/ioutil"
)

// https://www.digitalocean.com/community/tutorials/how-to-use-json-in-go
type JSON_Defaults struct {
	ApiKey              string `json:"ibmcloud_api_key"`
	SshKey              string `json:"pi_ssh_key"`
	OperSystem          string `json:"oper_system"`
	Architecture        string `json:"architecture"`
	Region              string `json:"region"`
	GroupID             string `json:"group"`

	BaseDomain          string `json:"BaseDomain"`
	CIS                 string `json:"CisInstanceCRN"`
	ClusterName         string `json:"ClusterName"`
	Email               string `json:"Email"`
	Image               string `json:"Image"`
	PowerVSRegion       string `json:"PowerVSRegion"`
	ResourceGroup       string `json:"ResourceGroup"`
	ServiceInstanceGUID string `json:"ServiceInstanceGUID"`
	VpcName             string `json:"VpcName"`
	Zone                string `json:"Zone"`

	//	VPCS            map[string]string	`json:"vpcs"`

	// https://eli.thegreenplace.net/2020/representing-json-structures-in-go/
	VPCS struct {
		Zone1 struct {
			PvsWorkspaceName string `json:"pvs_workspace_name"`
			PvsDcCidr        string `json:"pvs_dc_cidr"`
			VpcZoneCidr      string `json:"vpc_zone_cidr"`
		} `json:"zone1"`
		Zone2 struct {
			PvsWorkspaceName string `json:"pvs_workspace_name"`
			PvsDcCidr        string `json:"pvs_dc_cidr"`
			VpcZoneCidr      string `json:"vpc_zone_cidr"`
		} `json:"zone2"`
		Zone3 struct {
			PvsWorkspaceName string `json:"pvs_workspace_name"`
			PvsDcCidr        string `json:"pvs_dc_cidr"`
			VpcZoneCidr      string `json:"vpc_zone_cidr"`
		} `json:"zone3"`
	} `json:"vpcs"`
}

type Defaults struct {
	ApiKey              string
	SshKey              string
	OperSystem          string
	Architecture        string
	Region              string
	GroupID             string
	BaseDomain          string
	CIS                 string
	ClusterName         string
	Email               string
	Image               string
	PowerVSRegion       string
	ResourceGroup       string
	ServiceInstanceGUID string
	VpcName             string
	Zone                string
	VPCS                map[string]map[string]string
}

func read_defaults(jsonData []byte) (Defaults, error) {

	var (
		json_defaults JSON_Defaults
		defaults      Defaults
		err           error
	)

	err = json.Unmarshal(jsonData, &json_defaults)
	if err != nil {
		return Defaults{}, err
	}

	defaults.ApiKey = json_defaults.ApiKey
	defaults.SshKey = json_defaults.SshKey
	defaults.OperSystem = json_defaults.OperSystem
	defaults.Architecture = json_defaults.Architecture
	defaults.Region = json_defaults.Region
	defaults.GroupID = json_defaults.GroupID
	defaults.BaseDomain = json_defaults.BaseDomain
	defaults.CIS = json_defaults.CIS
	defaults.ClusterName = json_defaults.ClusterName
	defaults.Email = json_defaults.Email
	defaults.Image = json_defaults.Image
	defaults.PowerVSRegion = json_defaults.PowerVSRegion
	defaults.ResourceGroup = json_defaults.ResourceGroup
	defaults.ServiceInstanceGUID = json_defaults.ServiceInstanceGUID
	defaults.VpcName = json_defaults.VpcName
	defaults.Zone = json_defaults.Zone
	defaults.VPCS = make(map[string]map[string]string)
	defaults.VPCS["zone1"] = make(map[string]string)
	defaults.VPCS["zone2"] = make(map[string]string)
	defaults.VPCS["zone3"] = make(map[string]string)
	defaults.VPCS["zone1"]["pvs_workspace_name"] = json_defaults.VPCS.Zone1.PvsWorkspaceName
	defaults.VPCS["zone1"]["pvs_dc_cidr"] = json_defaults.VPCS.Zone1.PvsDcCidr
	defaults.VPCS["zone1"]["vpc_zone_cidr"] = json_defaults.VPCS.Zone1.VpcZoneCidr
	defaults.VPCS["zone2"]["pvs_workspace_name"] = json_defaults.VPCS.Zone2.PvsWorkspaceName
	defaults.VPCS["zone2"]["pvs_dc_cidr"] = json_defaults.VPCS.Zone2.PvsDcCidr
	defaults.VPCS["zone2"]["vpc_zone_cidr"] = json_defaults.VPCS.Zone2.VpcZoneCidr
	defaults.VPCS["zone3"]["pvs_workspace_name"] = json_defaults.VPCS.Zone3.PvsWorkspaceName
	defaults.VPCS["zone3"]["pvs_dc_cidr"] = json_defaults.VPCS.Zone3.PvsDcCidr
	defaults.VPCS["zone3"]["vpc_zone_cidr"] = json_defaults.VPCS.Zone3.VpcZoneCidr

	return defaults, err
}

func read_dictionary(filename string) ([]string, error) {

	var dictionary []string
	var err error

	content, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal("Error when opening file: ", err)
		panic(err)
	}

	err = json.Unmarshal(content, &dictionary)
	if err != nil {
		log.Fatal("Error during Unmarshal(): ", err)
		panic(err)
	}

	return dictionary, err

}
