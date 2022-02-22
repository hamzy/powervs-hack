package main

import (
	"context"
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

func main() {
	updateDNSObjectWithZones()
	addCISCRNToInfraObject()
}


func updateDNSObjectWithZones() {
	cfg, err := config.GetConfig()
	if err != nil {
		klog.Fatalf("Error getting configuration: %v", err)
	}
	configv1.AddToScheme(scheme.Scheme)

	k8sClient, err := client.New(cfg, client.Options{Scheme: scheme.Scheme})
	if err != nil {
		klog.Fatalf("Error getting k8sClient: %v", err)
	}

	dnsConfig := &configv1.DNS{}
	if err := k8sClient.Get(context.Background(), types.NamespacedName{Name: "cluster"}, dnsConfig); err != nil {
		panic(fmt.Errorf("failed to get dns %v", err))
	}

	// zone id of scnl.com
	dnsConfig.Spec.PrivateZone = &configv1.DNSZone{
		ID:   "3e4c8a33b7373f077a1e50677d277b1f",
	}
	// zone id of scnl.com
	dnsConfig.Spec.PublicZone = &configv1.DNSZone{
		ID:   "3e4c8a33b7373f077a1e50677d277b1f",
	}

	if err := k8sClient.Update(context.Background(), dnsConfig); err != nil {
		panic(fmt.Errorf("failed to get dns %v", err))
	}
}

func addCISCRNToInfraObject() {
	cfg, err := config.GetConfig()
	if err != nil {
		klog.Fatalf("Error getting configuration: %v", err)
	}
	configv1.AddToScheme(scheme.Scheme)

	k8sClient, err := client.New(cfg, client.Options{Scheme: scheme.Scheme})
	if err != nil {
		klog.Fatalf("Error getting k8sClient: %v", err)
	}
	infraConfig := &configv1.Infrastructure{}
	if err := k8sClient.Get(context.Background(), types.NamespacedName{Name: "cluster"}, infraConfig); err != nil {
		panic(fmt.Errorf("failed to get infrastructure 'config': %v", err))
	}

	//This is CRN of powervs-ipi-cis
	infraConfig.Status.PlatformStatus.PowerVS.CISInstanceCRN = "crn:v1:bluemix:public:internet-svcs:global:a/65b64c1f1c29460e8c2e4bbfbd893c2c:453c4cff-2ee0-4309-95f1-2e9384d9bb96::"

	if err := k8sClient.Status().Update(context.Background(), infraConfig); err != nil {
		panic(fmt.Errorf("failed to update infra %v", err))
	}
}
