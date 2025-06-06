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

type SkeletonOptions struct {
	Mode Mode
}

type Skeleton struct {
	options SkeletonOptions
}

func NewSkeleton(dnsOptions SkeletonOptions) (*Skeleton, error) {

	log.Debugf("NewSkeleton: dnsOptions = %+v", dnsOptions)

	return &Skeleton{
		options: dnsOptions,
	}, nil
}

func (sk *Skeleton) Run() error {

	var (
		err error
	)

	switch sk.options.Mode {
	case ModeCreate:
		err = sk.createSkeleton()
	case ModeDelete:
		err = sk.deleteSkeleton()
	default:
		return fmt.Errorf("Skeleton options must be either Create or Delete (%d)", sk.options.Mode)
	}

	return err
}

func (sk *Skeleton) CRN() (string, error) {

	return "", nil
}

func (sk *Skeleton) Name() (string, error) {

	return "", nil
}

func (sk *Skeleton) Valid() bool {

	return true
}

func (sk *Skeleton) createSkeleton() error {

	var (
		err error
	)

	return err
}

func (sk *Skeleton) deleteSkeleton() error {

	var (
		err error
	)

	return err
}
