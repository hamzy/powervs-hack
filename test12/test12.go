package main

import (
	"encoding/json"
	"fmt"
	"os"

	machinev1 "github.com/openshift/api/machine/v1"
)

func main2() {
	var b1 = []byte(`{"apiVersion":"machine.openshift.io/v1","credentialsSecret":{"name":"powervs-credentials"},"image":{"name":"rhcos-rdr-hamzy-test-dal10-9ssqz","type":"Name"},"keyPairName":"rdr-hamzy-test-dal10-9ssqz-key","kind":"PowerVSMachineProviderConfig","memoryGiB":32,"metadata":{"creationTimestamp":null},"network":{"regex":"^DHCPSERVER.*rdr-hamzy-test-dal10-9ssqz.*_Private$","type":"RegEx"},"processorType":"Shared","processors":"0.5","serviceInstance":{"id":"5094c532-89b9-4c28-82ea-00e71be200c6","type":"ID"},"systemType":"s922","userDataSecret":{"name":"worker-user-data"}}`)

	fmt.Println(b1)

	spec := new(machinev1.PowerVSMachineProviderConfig)

	if err := json.Unmarshal(b1, &spec); err != nil {
		fmt.Printf("b1 err = %v", err)
	}

	fmt.Println(spec)

	var b2 = []byte(`{"apiVersion":"machine.openshift.io/v1","credentialsSecret":{"name":"powervs-credentials"},"image":{"name":"rhcos-rdr-hamzy-test-dal10-9ssqz","type":"Name"},"keyPairName":"rdr-hamzy-test-dal10-9ssqz-key","kind":"PowerVSMachineProviderConfig","loadBalancers":[{"name":"rdr-hamzy-test-dal10-9ssqz-loadbalancer-int","type":"Application"},{"name":"rdr-hamzy-test-dal10-9ssqz-loadbalancer","type":"Application"}],"memoryGiB":32,"metadata":{"creationTimestamp":null},"network":{"regex":"^DHCPSERVER.*rdr-hamzy-test-dal10-9ssqz.*_Private$","type":"RegEx"},"processorType":"Shared","processors":"0.5","serviceInstance":{"id":"5094c532-89b9-4c28-82ea-00e71be200c6","type":"ID"},"systemType":"s922","userDataSecret":{"name":"master-user-data"}}`)

	providerStatus := new(machinev1.PowerVSMachineProviderStatus)

	if err := json.Unmarshal(b2, &providerStatus); err != nil {
		fmt.Printf("b2 err = %v", err)
	}

	fmt.Println(providerStatus)
	fmt.Println(providerStatus.ServiceInstanceID)
}

func main() {
	var key = "dnsservices"
	var val = "https://api.dns-svcs.cloud.ibm.com"

	fmt.Printf("os.Getenv: %s\n", os.Getenv(key))

	if err := os.Setenv(key, val); err != nil {
		fmt.Printf("os.Setenv: err = %s", err)
	}

	fmt.Printf("os.Getenv: %s\n", os.Getenv(key))
}
