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

func NewSkeleton(siOptions SkeletonOptions) (*Skeleton, error) {

	log.Debugf("NewSkeleton: siOptions = %+v", siOptions)

	return &Skeleton{
		options: siOptions,
	}, nil
}

func (si *Skeleton) Run() error {

	var (
		err error
	)

	switch si.options.Mode {
	case ModeCreate:
		err = si.createSkeleton()
	case ModeDelete:
		err = si.deleteSkeleton()
	default:
		return fmt.Errorf("Skeleton options must be either Create or Delete (%d)", si.options.Mode)
	}

	return err
}

func (si *Skeleton) createSkeleton() error {

	var (
		err error
	)

	return err
}

func (si *Skeleton) deleteSkeleton() error {

	var (
		err error
	)

	return err
}
