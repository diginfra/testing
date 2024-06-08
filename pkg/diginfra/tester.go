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

package diginfra

import (
	"bytes"
	"context"
	"time"

	"github.com/diginfra/testing/pkg/run"
	"github.com/sirupsen/logrus"
)

var (
	// PrivilegedDockerBinds is the set of Docker binds required by Diginfra
	// when running as a Docker privileged container
	PrivilegedDockerBinds = []string{
		"/dev:/host/dev",
		"/proc:/host/proc:ro",
		"/var/run/docker.sock:/host/var/run/docker.sock",
	}
	DiginfraConfig = DefaultConfigFile
)

const (
	// DefaultMaxDuration is the default max duration of a Diginfra run
	DefaultMaxDuration = time.Second * 180
	//
	// DefaultExecutable is the default path of the Diginfra executable
	DefaultExecutable = "/usr/bin/diginfra"
	//
	// DefaultConfigFile is the default path of the Diginfra config file
	DefaultConfigFile = "/etc/diginfra/diginfra.yaml"
)

type testOptions struct {
	err      error
	args     []string
	files    []run.FileAccessor
	runOpts  []run.RunnerOption
	duration time.Duration
	ctx      context.Context
}

// TestOutput is the output of a Diginfra test run
type TestOutput struct {
	opts   *testOptions
	err    error
	stdout bytes.Buffer
	stderr bytes.Buffer
}

// TestOption is an option for testing Diginfra
type TestOption func(*testOptions)

// Test runs a Diginfra runner with the given test options, and produces
// an output representing the outcome of the run.
func Test(runner run.Runner, options ...TestOption) *TestOutput {
	res := &TestOutput{
		opts: &testOptions{
			duration: DefaultMaxDuration,
			ctx:      context.Background(),
		},
	}
	
	// enforce Diginfra config path as default
	res.opts.args = append(res.opts.args, "-c", DiginfraConfig)

	for _, o := range options {
		o(res.opts)
	}
	if res.opts.err != nil {
		return res
	}

	// enforce logging everything on stdout
	res.opts.args = append(res.opts.args, "-o", "log_level=debug")
	res.opts.args = append(res.opts.args, "-o", "log_stderr=true")
	res.opts.args = append(res.opts.args, "-o", "log_syslog=false")
	res.opts.args = append(res.opts.args, "-o", "stdout_output.enabled=true")
	logrus.WithField("deadline", res.opts.duration).Info("running diginfra with runner")
	ctx, cancel := context.WithTimeout(res.opts.ctx, skewedDuration(res.opts.duration))
	defer cancel()
	res.err = runner.Run(ctx,
		append([]run.RunnerOption{
			run.WithArgs(res.opts.args...),
			run.WithFiles(res.opts.files...),
			run.WithStdout(&res.stdout),
			run.WithStderr(&res.stderr),
		}, res.opts.runOpts...)...,
	)
	if res.err != nil {
		logrus.WithError(res.err).Warn("error running diginfra with runner")
	}
	return res
}
