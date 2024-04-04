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
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/golang-jwt/jwt"
	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM-Cloud/bluemix-go"
	"github.com/IBM-Cloud/bluemix-go/api/resource/resourcev2/controllerv2"
	"github.com/IBM-Cloud/bluemix-go/authentication"
	"github.com/IBM-Cloud/bluemix-go/http"
	"github.com/IBM-Cloud/bluemix-go/rest"
	bxsession "github.com/IBM-Cloud/bluemix-go/session"
	"github.com/IBM-Cloud/power-go-client/clients/instance"
	"github.com/IBM-Cloud/power-go-client/ibmpisession"
	"github.com/IBM-Cloud/power-go-client/power/models"
	"io/ioutil"
	"log"
	gohttp "net/http"
	"net/url"
	"regexp"
	"reflect"
	"strings"
)

func main() {

	var (
		getKeyOptions *vpcv1.GetKeyOptions
		err           error
	)

	getKeyOptions = vpcSvc.NewGetKeyOptions(item.id)

	_, _, err = vpcSvc.GetKey(getKeyOptions)
	if err != nil {
		deletePendingItems(item.typeName, []cloudResource{item})
		Logger.Infof("HAMZY Deleted Cloud sshKey %q", item.name)
		return nil
	}

	Logger.Debugf("Deleting Cloud sshKey %q", item.name)

	err = keyClient.Delete(item.id)
	if err != nil {
		return errors.Wrapf(err, "failed to delete sshKey %s", item.name)
	}
}
