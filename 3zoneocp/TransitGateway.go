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
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/networking-go-sdk/transitgatewayapisv1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/utils/ptr"
)

type TransitGatewayNetworkType int

const (
	NETWORK_TYPE_PVS TransitGatewayNetworkType = iota
	NETWORK_TYPE_VPC
)

type TransitGatewayOptions struct {
	Mode   Mode
	ApiKey string
	Region string
	Name   string
}

type TransitGateway struct {
	options TransitGatewayOptions

	tgClient *transitgatewayapisv1.TransitGatewayApisV1

	ctx context.Context

	innerTg *transitgatewayapisv1.TransitGateway

	tgName string
}

func initTransitGateway(options TransitGatewayOptions) (*transitgatewayapisv1.TransitGatewayApisV1, error) {

	var (
		authenticator core.Authenticator = &core.IamAuthenticator{
			ApiKey: options.ApiKey,
		}

		versionDate = "2024-07-16"

		tgClient *transitgatewayapisv1.TransitGatewayApisV1

		err error
	)

	tgClient, err = transitgatewayapisv1.NewTransitGatewayApisV1(&transitgatewayapisv1.TransitGatewayApisV1Options{
		Authenticator: authenticator,
		Version:       ptr.To(versionDate),
	})
	if err != nil {
		log.Fatalf("Error: transitgatewayapisv1.NewTransitGatewayApisV1 returns %v", err)
		return nil, err
	}

	return tgClient, nil
}

func NewTransitGateway(tgOptions TransitGatewayOptions) (*TransitGateway, error) {

	var (
		tgName string

		tgClient *transitgatewayapisv1.TransitGatewayApisV1

		ctx context.Context

		err error
	)

	log.Debugf("NewTransitGateway: tgOptions = %+v", tgOptions)

	tgName = fmt.Sprintf("%s-tg", tgOptions.Name)

	tgClient, err = initTransitGateway(tgOptions)
	if err != nil {
		log.Fatalf("Error: NewTransitGateway: initTransitGateway returns %v", err)
		return nil, err
	}

	ctx = context.Background()
	log.Debugf("NewTransitGateway: ctx = %v", ctx)

	return &TransitGateway{
		options:  tgOptions,
		tgClient: tgClient,
		ctx:      ctx,
		innerTg:  nil,
		tgName:   tgName,
	}, nil
}

func (tg *TransitGateway) Run() error {

	var (
		foundTg *transitgatewayapisv1.TransitGateway

		err error
	)

	// Does it already exist?
	if tg.innerTg == nil {
		foundTg, err = tg.findTransitGateway()
		if err != nil {
			log.Fatalf("Error: findTransitGateway returns %v", err)
			return err
		} else {
			tg.innerTg = foundTg
		}
	}

	switch tg.options.Mode {
	case ModeCreate:
		err = tg.createTransitGateway()
	case ModeDelete:
		err = tg.deleteTransitGateway()
	default:
		return fmt.Errorf("TransitGateway options must be either Create or Delete (%d)", tg.options.Mode)
	}

	return err
}

func (tg *TransitGateway) CRN() (string, error) {

	if tg.innerTg == nil {
		return "", fmt.Errorf("TransitGateway does not exist to have a CRN")
	}

	return *tg.innerTg.Crn, nil
}

func (tg *TransitGateway) Name() (string, error) {

	if tg.innerTg == nil {
		return "", fmt.Errorf("TransitGateway does not exist to have a Name")
	}

	return *tg.innerTg.Name, nil
}

func (tg *TransitGateway) Valid() bool {

	if tg.innerTg == nil {
		return false
	}
	return true
}

func (tg *TransitGateway) findTransitGateway() (*transitgatewayapisv1.TransitGateway, error) {

	var (
		listTransitGatewaysOptions *transitgatewayapisv1.ListTransitGatewaysOptions
		gatewayCollection          *transitgatewayapisv1.TransitGatewayCollection
		gateway                    transitgatewayapisv1.TransitGateway
		response                   *core.DetailedResponse
		perPage                    int64 = 32
		moreData                         = true
		err                        error
	)

	listTransitGatewaysOptions = tg.tgClient.NewListTransitGatewaysOptions()
	listTransitGatewaysOptions.Limit = &perPage

	for moreData {
		// https://github.com/IBM/networking-go-sdk/blob/master/transitgatewayapisv1/transit_gateway_apis_v1.go#L184
		gatewayCollection, response, err = tg.tgClient.ListTransitGatewaysWithContext(tg.ctx, listTransitGatewaysOptions)
		if err != nil {
			return nil, fmt.Errorf("failed to list transit gateways: %w and the respose is: %s", err, response)
		}

		for _, gateway = range gatewayCollection.TransitGateways {
			if strings.Contains(*gateway.Name, tg.tgName) {
				var (
					getOptions *transitgatewayapisv1.GetTransitGatewayOptions

					foundTg *transitgatewayapisv1.TransitGateway
				)

				getOptions = tg.tgClient.NewGetTransitGatewayOptions(*gateway.ID)

				foundTg, response, err = tg.tgClient.GetTransitGatewayWithContext(tg.ctx, getOptions)
				if err != nil {
					log.Fatalf("Error: GetTransitGateway: response = %v, err = %v", response, err)
					return nil, err
				}

				log.Debugf("findTransitGateway: FOUND Name = %s", *gateway.Name)

				return foundTg, nil
			} else {
				log.Debugf("findTransitGateway: SKIP Name = %s", *gateway.Name)
			}
		}

		if gatewayCollection.First != nil {
			log.Debugf("findTransitGateway: First = %+v", *gatewayCollection.First.Href)
		} else {
			log.Debugf("findTransitGateway: First = nil")
		}
		if gatewayCollection.Limit != nil {
			log.Debugf("findTransitGateway: Limit = %v", *gatewayCollection.Limit)
		}
		if gatewayCollection.Next != nil {
			start, err := gatewayCollection.GetNextStart()
			if err != nil {
				log.Debugf("findTransitGateway: err = %v", err)
				return nil, fmt.Errorf("findTransitGateway: failed to GetNextStart: %w", err)
			}
			if start != nil {
				log.Debugf("findTransitGateway: start = %v", *start)
				listTransitGatewaysOptions.SetStart(*start)
			}
		} else {
			log.Debugf("findTransitGateway: Next = nil")
			moreData = false
		}
	}

	return nil, nil
}

func (tg *TransitGateway) createTransitGateway() error {

	var (
		createTransitGatewayOptions *transitgatewayapisv1.CreateTransitGatewayOptions

		response *core.DetailedResponse

		err error
	)

	if tg.innerTg == nil {
		// https://raw.githubusercontent.com/IBM/networking-go-sdk/master/transitgatewayapisv1/transit_gateway_apis_v1.go
		createTransitGatewayOptions = tg.tgClient.NewCreateTransitGatewayOptions(
			tg.options.Region,
			tg.tgName,
		)

		tg.innerTg, response, err = tg.tgClient.CreateTransitGatewayWithContext(tg.ctx, createTransitGatewayOptions)
		if err != nil {
			log.Fatalf("Error: CreateTransitGatewayWithContext: response = %v, err = %v", response, err)
			return err
		}

		err = tg.waitForTransitGatewayReady()
		if err != nil {
			log.Fatalf("Error: waitForTransitGatewayReady: err = %v", err)
			return err
		}
	}

	return nil
}

func (tg *TransitGateway) deleteTransitGateway() error {

	var (
		deleteTransitGatewayOptions *transitgatewayapisv1.DeleteTransitGatewayOptions

		response *core.DetailedResponse

		err error
	)

	if tg.innerTg != nil {
		err = tg.deleteTransitGatewayConnections()
		if err != nil {
			log.Fatalf("Error: deleteTransitGatewayConnections: err = %v", err)
			return err
		}

		deleteTransitGatewayOptions = tg.tgClient.NewDeleteTransitGatewayOptions(*tg.innerTg.ID)

		response, err = tg.tgClient.DeleteTransitGatewayWithContext(tg.ctx, deleteTransitGatewayOptions)
		if err != nil {
			log.Fatalf("Error: DeleteTransitGatewayWithContext: response = %v, err = %v", response, err)
			return err
		}
	}

	return nil
}

func (tg *TransitGateway) waitForTransitGatewayReady() error {

	var (
		getOptions *transitgatewayapisv1.GetTransitGatewayOptions

		foundTg *transitgatewayapisv1.TransitGateway

		response *core.DetailedResponse

		err error
	)

	if tg.innerTg == nil {
		return fmt.Errorf("waitForTransitGatewayReady innerTg is nil")
	}

	getOptions = tg.tgClient.NewGetTransitGatewayOptions(*tg.innerTg.ID)

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(tg.ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(tg.ctx, backoff, func(context.Context) (bool, error) {
		var err2 error

		foundTg, response, err2 = tg.tgClient.GetTransitGatewayWithContext(tg.ctx, getOptions)
		if err != nil {
			log.Fatalf("Error: Wait GetResourceInstanceWithContext: response = %v, err = %v", response, err2)
			return false, err2
		}
		log.Debugf("waitForTransitGatewayReady: Status = %s", *foundTg.Status)
		switch *foundTg.Status {
		case transitgatewayapisv1.TransitGateway_Status_Available:
			return true, nil
		case transitgatewayapisv1.TransitGateway_Status_Pending:
			return false, nil
		case transitgatewayapisv1.TransitGateway_Status_Deleting:
			return true, fmt.Errorf("waitForTransitGatewayReady: deleting status")
		case transitgatewayapisv1.TransitGateway_Status_Failed:
			return true, fmt.Errorf("waitForTransitGatewayReady: failed status")
		case transitgatewayapisv1.TransitGateway_Status_Suspended:
			return true, fmt.Errorf("waitForTransitGatewayReady: suspended status")
		case transitgatewayapisv1.TransitGateway_Status_Suspending:
			return true, fmt.Errorf("waitForTransitGatewayReady: suspending status")
		default:
			return true, fmt.Errorf("waitForTransitGatewayReady: unknown status: %s", *foundTg.Status)
		}
	})
	if err != nil {
		log.Fatalf("Error: ExponentialBackoffWithContext returns %v", err)
		return err
	}

	return nil
}

func (tg *TransitGateway) waitForTransitGatewayConnectionReady(id string) error {

	var (
		getOptions *transitgatewayapisv1.GetTransitGatewayConnectionOptions

		foundConnection *transitgatewayapisv1.TransitGatewayConnectionCust

		response *core.DetailedResponse

		err error
	)

	if tg.innerTg == nil {
		return fmt.Errorf("waitForTransitGatewayConnectionReady innerTg is nil")
	}

	getOptions = tg.tgClient.NewGetTransitGatewayConnectionOptions(*tg.innerTg.ID, id)

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(tg.ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(tg.ctx, backoff, func(context.Context) (bool, error) {
		var err2 error

		foundConnection, response, err2 = tg.tgClient.GetTransitGatewayConnectionWithContext(tg.ctx, getOptions)
		if err != nil {
			log.Fatalf("Error: Wait waitForTransitGatewayConnectionReady: response = %v, err = %v", response, err2)
			return false, err2
		}
		if foundConnection == nil {
			log.Debugf("waitForTransitGatewayConnectionReady: foundConnection is nil")
			return true, nil
		}
		log.Debugf("waitForTransitGatewayConnectionReady: Status = %s", *foundConnection.Status)
		switch *foundConnection.Status {
		case transitgatewayapisv1.TransitGatewayConnectionCust_Status_Attached:
			return true, nil
		case transitgatewayapisv1.TransitGatewayConnectionCust_Status_Deleting:
			return false, nil
		case transitgatewayapisv1.TransitGatewayConnectionCust_Status_Pending:
			return false, nil
		case transitgatewayapisv1.TransitGatewayConnectionCust_Status_Detached:
			return true, fmt.Errorf("waitForTransitGatewayConnectionReady: detached status")
		case transitgatewayapisv1.TransitGatewayConnectionCust_Status_Detaching:
			return true, fmt.Errorf("waitForTransitGatewayConnectionReady: detaching status")
		case transitgatewayapisv1.TransitGatewayConnectionCust_Status_Failed:
			return true, fmt.Errorf("waitForTransitGatewayConnectionReady: failed status")
		case transitgatewayapisv1.TransitGatewayConnectionCust_Status_Suspended:
			return true, fmt.Errorf("waitForTransitGatewayConnectionReady: suspended status")
		case transitgatewayapisv1.TransitGatewayConnectionCust_Status_Suspending:
			return true, fmt.Errorf("waitForTransitGatewayConnectionReady: suspending status")
		default:
			return true, fmt.Errorf("waitForTransitGatewayConnectionReady: unknown status: %s", *foundConnection.Status)
		}
	})
	if err != nil {
		log.Fatalf("Error: ExponentialBackoffWithContext returns %v", err)
		return err
	}

	return nil
}

func (tg *TransitGateway) AddTransitGatewayConnection(crn string, networkType TransitGatewayNetworkType) error {

	log.Debugf("AddTransitGatewayConnection: crn = %s", crn)

	var (
		listConnectionsOptions                *transitgatewayapisv1.ListConnectionsOptions
		transitConnectionCollections          *transitgatewayapisv1.TransitConnectionCollection
		transitConnection                     transitgatewayapisv1.TransitConnection
		response                              *core.DetailedResponse
		err                                   error
		perPage                               int64 = 32
		moreData                                    = true
		found                                       = false
		createTransitGatewayConnectionOptions *transitgatewayapisv1.CreateTransitGatewayConnectionOptions
		tgc                                   *transitgatewayapisv1.TransitGatewayConnectionCust
		pvsCount                              = 1
		vpcCount                              = 1
		name                                  string
	)

	if tg.innerTg == nil {
		return fmt.Errorf("AddTransitGatewayConnection innerTg is nil")
	}

	listConnectionsOptions = tg.tgClient.NewListConnectionsOptions()
	listConnectionsOptions.SetLimit(perPage)

	for moreData {
		transitConnectionCollections, response, err = tg.tgClient.ListConnectionsWithContext(tg.ctx, listConnectionsOptions)
		if err != nil {
			log.Debugf("AddTransitGatewayConnection: ListTransitGatewayConnectionsWithContext returns %v and the response is: %s", err, response)
			return err
		}
		for _, transitConnection = range transitConnectionCollections.Connections {
			if *tg.innerTg.ID != *transitConnection.TransitGateway.ID {
				log.Debugf("AddTransitGatewayConnection: SKIP %s %s %s", *transitConnection.ID, *transitConnection.Name, *transitConnection.TransitGateway.ID)
				continue
			}

			if  *transitConnection.NetworkID == crn {
				log.Debugf("AddTransitGatewayConnection: EXISTING %s, %s, %s", *transitConnection.ID, *transitConnection.Name, *transitConnection.TransitGateway.ID)
				found = true
				return nil
			}

			log.Debugf("AddTransitGatewayConnection: OTHER %s, %s, %s, %s", *transitConnection.ID, *transitConnection.Name, *transitConnection.TransitGateway.ID, *transitConnection.NetworkID)

			switch *transitConnection.NetworkType {
			case transitgatewayapisv1.CreateTransitGatewayConnectionOptions_NetworkType_PowerVirtualServer:
				pvsCount++
			case transitgatewayapisv1.CreateTransitGatewayConnectionOptions_NetworkType_Vpc:
				vpcCount++
			}
			log.Debugf("AddTransitGatewayConnection: pvsCount = %d, vpcCount = %d", pvsCount, vpcCount)
		}

		if transitConnectionCollections.First != nil {
			log.Debugf("AddTransitGatewayConnection: First = %+v", *transitConnectionCollections.First)
		} else {
			log.Debugf("AddTransitGatewayConnection: First = nil")
		}
		if transitConnectionCollections.Limit != nil {
			log.Debugf("AddTransitGatewayConnection: Limit = %v", *transitConnectionCollections.Limit)
		}
		if transitConnectionCollections.Next != nil {
			start, err := transitConnectionCollections.GetNextStart()
			if err != nil {
				log.Debugf("AddTransitGatewayConnection: err = %v", err)
				return fmt.Errorf("AddTransitGatewayConnection: failed to GetNextStart: %w", err)
			}
			if start != nil {
				log.Debugf("AddTransitGatewayConnection: start = %v", *start)
				listConnectionsOptions.SetStart(*start)
			}
		} else {
			log.Debugf("AddTransitGatewayConnection: Next = nil")
			moreData = false
		}
	}

	if !found {
		var (
			nt string
		)

		switch networkType {
		case NETWORK_TYPE_PVS:
			nt = transitgatewayapisv1.CreateTransitGatewayConnectionOptions_NetworkType_PowerVirtualServer
			name = fmt.Sprintf("tg-pvs-connection-%d", pvsCount)
		case NETWORK_TYPE_VPC:
			nt = transitgatewayapisv1.CreateTransitGatewayConnectionOptions_NetworkType_Vpc
			name = fmt.Sprintf("tg-vpc-connection-%d", vpcCount)
		default:
			return fmt.Errorf("AddTransitGatewayConnection: unknown type: %d", networkType)
		}

		log.Debugf("AddTransitGatewayConnection: ADDING %s %s %s", *tg.innerTg.ID, name, crn)

		createTransitGatewayConnectionOptions = tg.tgClient.NewCreateTransitGatewayConnectionOptions(
			*tg.innerTg.ID,
			nt,
		)
		createTransitGatewayConnectionOptions.SetName(name)
		createTransitGatewayConnectionOptions.SetNetworkID(crn)

		tgc, response, err = tg.tgClient.CreateTransitGatewayConnectionWithContext(tg.ctx, createTransitGatewayConnectionOptions)
		if err != nil {
			log.Debugf("AddTransitGatewayConnection: CreateTransitGatewayConnectionWithContext returns %v and the response is: %s", err, response)
			return err
		}
		log.Debugf("AddTransitGatewayConnection: tgc = %+v", tgc)
	}

	return nil
}

func (tg *TransitGateway) deleteTransitGatewayConnections() error {

	var (
		listConnectionsOptions                *transitgatewayapisv1.ListConnectionsOptions
		transitConnectionCollections          *transitgatewayapisv1.TransitConnectionCollection
		transitConnection                     transitgatewayapisv1.TransitConnection
		deleteTransitGatewayConnectionOptions *transitgatewayapisv1.DeleteTransitGatewayConnectionOptions
		response                              *core.DetailedResponse
		err                                   error
		perPage                               int64 = 32
		moreData                                    = true
	)

	if tg.innerTg == nil {
		return fmt.Errorf("deleteTransitGatewayConnections innerTg is nil")
	}

	listConnectionsOptions = tg.tgClient.NewListConnectionsOptions()
	listConnectionsOptions.SetLimit(perPage)
	listConnectionsOptions.SetNetworkID("")

	for moreData {
		transitConnectionCollections, response, err = tg.tgClient.ListConnectionsWithContext(tg.ctx, listConnectionsOptions)
		if err != nil {
			log.Debugf("deleteTransitGatewayConnections: ListConnectionsWithContext returns %v and the response is: %s", err, response)
			return err
		}
		for _, transitConnection = range transitConnectionCollections.Connections {
			if *tg.innerTg.ID != *transitConnection.TransitGateway.ID {
				log.Debugf("deleteTransitGatewayConnections: SKIP %s %s %s", *transitConnection.ID, *transitConnection.Name, *transitConnection.TransitGateway.ID)
				continue
			}

			log.Debugf("deleteTransitGatewayConnections: FOUND: %s, %s, %s", *transitConnection.ID, *transitConnection.Name, *transitConnection.TransitGateway.Name)

			deleteTransitGatewayConnectionOptions = tg.tgClient.NewDeleteTransitGatewayConnectionOptions(
				*transitConnection.TransitGateway.ID,
				*transitConnection.ID,
			)

			response, err = tg.tgClient.DeleteTransitGatewayConnectionWithContext(tg.ctx, deleteTransitGatewayConnectionOptions)
			if err != nil {
				log.Fatalf("deleteTransitGatewayConnections: DeleteTransitGatewayConnectionWithContext returns %v with response %v", err, response)
				return err
			}

			err = tg.waitForTransitGatewayConnectionReady(*transitConnection.ID)
			if err != nil {
				log.Fatalf("deleteTransitGatewayConnections: waitForTransitGatewayConnectionReady returns %v", err)
				return err
			}
		}

		if transitConnectionCollections.First != nil {
			log.Debugf("deleteTransitGatewayConnections: First = %+v", *transitConnectionCollections.First)
		} else {
			log.Debugf("deleteTransitGatewayConnections: First = nil")
		}
		if transitConnectionCollections.Limit != nil {
			log.Debugf("deleteTransitGatewayConnections: Limit = %v", *transitConnectionCollections.Limit)
		}
		if transitConnectionCollections.Next != nil {
			start, err := transitConnectionCollections.GetNextStart()
			if err != nil {
				log.Debugf("deleteTransitGatewayConnections: err = %v", err)
				return fmt.Errorf("deleteTransitGatewayConnections: failed to GetNextStart: %w", err)
			}
			if start != nil {
				log.Debugf("deleteTransitGatewayConnections: start = %v", *start)
				listConnectionsOptions.SetStart(*start)
			}
		} else {
			log.Debugf("deleteTransitGatewayConnections: Next = nil")
			moreData = false
		}
	}

	return nil
}
