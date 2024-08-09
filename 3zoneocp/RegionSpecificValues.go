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
	"fmt"
)

type RSV struct {
	DCName      string
	WSZoneName  string
	VPCZoneName string
}

var region_specific_values = map[string]map[string]RSV{
	"us-south": {
		"zone1": {
			DCName:      "dal10",
			WSZoneName:  "dal10",
			VPCZoneName: "us-south-1",
		},
		"zone2": {
			DCName:      "dal12",
			WSZoneName:  "dal12",
			VPCZoneName: "us-south-2",
		},
		"zone3": {
			DCName:      "dal13",
			WSZoneName:  "us-south",
			VPCZoneName: "us-south-3",
		},
	},
	"us-east": {
		"zone1": {
			DCName:      "wdc04",
			WSZoneName:  "us-east",
			VPCZoneName: "us-east-1",
		},
		"zone2": {
			DCName:      "wdc06",
			WSZoneName:  "wdc06",
			VPCZoneName: "us-east-2",
		},
		"zone3": {
			DCName:      "wdc07",
			WSZoneName:  "wdc07",
			VPCZoneName: "us-east-3",
		},
	},
}

func RSVMapForRegion(region string) (map[string]RSV, error) {

	var (
		zoneMap map[string]RSV
		ok      bool
	)

	if zoneMap, ok = region_specific_values[region]; !ok {
		return nil, fmt.Errorf("Region %s not in RSV map", region)
	}

	return zoneMap, nil
}

func RSVForRegionZone(region string, zone string) (RSV, error) {

	var (
		zoneMap map[string]RSV
		rsv     RSV
		ok      bool
	)

	if zoneMap, ok = region_specific_values[region]; !ok {
		return RSV{}, fmt.Errorf("Region %s not in RSV map", region)
	}

	if rsv, ok = zoneMap[zone]; !ok {
		return RSV{}, fmt.Errorf("Zone %s not in RSV map for region %s", zone, region)
	}

	return rsv, nil
}
