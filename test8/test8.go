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
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"os"
)

func main() {

	var log *logrus.Logger = &logrus.Logger{
		Out:       os.Stderr,
		Formatter: new(logrus.TextFormatter),
		Level:     logrus.DebugLevel,
	}
	var err error = fmt.Errorf("Hello world")

	log.Debugf("first = %v", err)

	err = errors.Wrap(
		nil,
		"failed disabling bootstrap load balancing",
	)

	log.Debugf("second = %v", err)

	err = fmt.Errorf(
		"failed disabling bootstrap load balancing: %w",
		nil,
	)

	log.Debugf("third = %v", err)
}
