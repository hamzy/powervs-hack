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
	"github.com/sirupsen/logrus"
	"os"
	regionutils "github.com/ppc64le-cloud/powervs-utils"
)

var (
	log *logrus.Logger = &logrus.Logger{
		Out:       os.Stderr,
		Formatter: new(logrus.TextFormatter),
		Level:     logrus.DebugLevel,
	}
)

func test_regions() {
	var (
		test_regions = [...]string {
			"us-south",
			"eu-gb",
		}
		test_region string
	)

	for _, test_region = range test_regions {
		if regionutils.ValidateVPCRegion(test_region) {
			log.Debugf("Region %s is found", test_region)
		} else {
			log.Debugf("Region %s is not found", test_region)
		}
	}
}

func main() {

	log.Debug("Testing default regions:")
	test_regions()

	regionutils.UseIPIRegions()

	log.Debug("Testing IPI regions:")
	test_regions()
}
