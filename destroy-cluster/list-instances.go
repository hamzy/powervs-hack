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
	"fmt"
	"github.com/ppc64le-cloud/pvsadm/pkg"
	"github.com/ppc64le-cloud/pvsadm/pkg/client"
	"os"
	"regexp"
)

func listInstances (rSearch *regexp.Regexp, pvmclient *client.PVMClient) {

	instances, err := pvmclient.InstanceClient.GetAll()
	if err != nil {
		fmt.Printf("Failed to get the instances, err: %v\n", err)
		return
	}

	for _, instance := range instances.PvmInstances {
		if rSearch.MatchString(*instance.ServerName) {
			fmt.Printf("instance.ServerName = %s\n", *instance.ServerName)
		}

//		*instance.PvmInstanceID
	}

}

func main() {
	opt := pkg.Options

	opt.APIKey      = os.Getenv("IBMCLOUD_API_KEY")
	opt.Environment = client.DefaultEnv
	opt.Debug       = false

	rSearch, _ := regexp.Compile(".*rdr-hamzy-test.*")

	c, err := client.NewClientWithEnv(opt.APIKey, opt.Environment, opt.Debug)
	if err != nil {
		fmt.Printf("Failed to create NewClientWithEnv with IBM cloud: %v\n", err)
		return
	}

	// $ ibmcloud pi service-list --json | jq -r '.[] | select (.Name|test("powervs-ipi-lon04")) | .CRN' | cut -d: -f8
	// e449d86e-c3a0-4c07-959e-8557fdf55482
	opt.InstanceID   = "e449d86e-c3a0-4c07-959e-8557fdf55482"
//	opt.InstanceName = "powervs-ipi-lon04"

	pvmclient, err := client.NewPVMClientWithEnv(c, opt.InstanceID, opt.InstanceName, opt.Environment)
	if err != nil {
		fmt.Printf ("Failed to create NewPVMClientWithEnv = %v", err);
		return
	}

	listInstances (rSearch, pvmclient)
}
