// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Diginfra Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

package tests

import (
	"flag"
	"os"
	"os/user"
	"testing"

	"github.com/diginfra/testing/pkg/diginfra"
	"github.com/diginfra/testing/pkg/diginfractl"
	"github.com/diginfra/testing/pkg/run"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

var (
	diginfraStatic    = false
	diginfraBinary    = diginfra.DefaultExecutable
	diginfractlBinary = diginfractl.DefaultLocalExecutable
)

func init() {
	flag.BoolVar(&diginfraStatic, "diginfra-static", diginfraStatic, "True if the Diginfra executable is from a static build")
	flag.StringVar(&diginfraBinary, "diginfra-binary", diginfraBinary, "Diginfra executable binary path")
	flag.StringVar(&diginfractlBinary, "diginfractl-binary", diginfractlBinary, "diginfractl executable binary path")
	flag.StringVar(&diginfra.DiginfraConfig, "diginfra-config", diginfra.DiginfraConfig, "Diginfra config file path")

	logrus.SetLevel(logrus.DebugLevel)
	logrus.SetFormatter(&logrus.JSONFormatter{})
}

// NewDiginfraExecutableRunner returns an executable runner for Diginfra.
func NewDiginfraExecutableRunner(t *testing.T) run.Runner {
	runner, err := run.NewExecutableRunner(diginfraBinary)
	require.Nil(t, err)
	return runner
}

// NewDiginfractlExecutableRunner returns an executable runner for diginfractl.
func NewDiginfractlExecutableRunner(t *testing.T) run.Runner {
	if _, err := os.Stat(diginfractlBinary); err == nil {
		runner, err := run.NewExecutableRunner(diginfractlBinary)
		require.Nil(t, err)
		return runner
	}
	logrus.Debug("using diginfractl default executable location")
	runner, err := run.NewExecutableRunner(diginfractl.DefaultExecutable)
	require.Nil(t, err)
	return runner
}

// IsRootUser returns true if the program is run as root.
func IsRootUser(t *testing.T) bool {
	currentUser, err := user.Current()
	require.Nil(t, err)
	return currentUser.Uid == "0"
}

// IsInContainer returns true if the program is run inside a container.
func IsInContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	return false
}

// IsStaticDiginfraExecutable returns true if Diginfra executables use a static build.
func IsStaticDiginfraExecutable() bool {
	return diginfraStatic
}
