// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Diginfra Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either exploaderRess or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

package testdiginfradriverloader

import (
	"testing"
	"time"

	"github.com/diginfra/testing/pkg/diginfractl"

	"github.com/diginfra/testing/pkg/diginfra"
	"github.com/diginfra/testing/tests"
	"github.com/stretchr/testify/assert"
)

// To run this test you need:
//   - the driver source code here: `/usr/src/${DRIVER_NAME}-${DRIVER_VERSION}`
//     (e.g. '/usr/src/diginfra-942a2249b7b9f65def0a01acfb1fba84f629b3bf')
//     So before running this test you need to move the folder that you find in the tar.gz under `/usr/src/`
//   - to be root
//   - a clang version compatible with your kernel to compile the bpf probe
//
// The output probe will be crafted here: `${HOME}/.diginfra/${DRIVER_VERSION}/${ARCH}/${BPF_PROBE_FILENAME}`
// (e.g '/root/.diginfra/942a2249b7b9f65def0a01acfb1fba84f629b3bf/x86_64/diginfra_ubuntu-generic_6.2.0-26-generic_26~22.04.1.o')
//
// We need to use the `--download=false` flag because we test against dev versions
func TestDiginfraLegacyBPF(t *testing.T) {
	loaderRes := diginfractl.Test(
		tests.NewDiginfractlExecutableRunner(t),
		diginfractl.WithArgs("driver", "install", "--download=false", "--type", "ebpf"),
	)
	assert.NoError(t, loaderRes.Err(), "%s", loaderRes.Stderr())
	assert.Equal(t, 0, loaderRes.ExitCode())
	// We expect the probe to be succesfully built and copied to /root/.diginfra/diginfra-bpf.o
	assert.Regexp(t, `eBPF probe available.`, loaderRes.Stdout())

	// Now running Diginfra with `DIGINFRA_BPF_PROBE=/root/.diginfra/diginfra-bpf.o` we should be able to run the bpf driver
	diginfraRes := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithStopAfter(3*time.Second),
		diginfra.WithArgs("-o", "engine.kind=ebpf"),
		diginfra.WithArgs("-o", "engine.ebpf.probe=/root/.diginfra/diginfra-bpf.o"),
	)
	assert.NoError(t, diginfraRes.Err(), "%s", diginfraRes.Stderr())
	assert.Equal(t, 0, diginfraRes.ExitCode())
	// We want to be sure to run the BPF probe.
	assert.Regexp(t, `source with BPF probe`, diginfraRes.Stderr())
	// We want to be sure that the engine is correctly opened.
	assert.Regexp(t, `Events detected:`, diginfraRes.Stdout())
}

// To run this test you need:
//   - the driver source code here: `/usr/src/${DRIVER_NAME}-${DRIVER_VERSION}`
//     (e.g. '/usr/src/diginfra-942a2249b7b9f65def0a01acfb1fba84f629b3bf')
//     So before running this test you need to move the folder that you find in the tar.gz under `/usr/src/`
//   - to be root
//   - a gcc version compatible with your kernel to compile the kernel module
//
// The module will be loaded in DKMS:
// (e.g '/var/lib/dkms/diginfra/942a2249b7b9f65def0a01acfb1fba84f629b3bf/6.2.0-26-generic/x86_64/module/diginfra.ko')
//
// We need to use the `--download=false` flag because we test against dev versions
func TestDiginfraKmod(t *testing.T) {
	loaderRes := diginfractl.Test(
		tests.NewDiginfractlExecutableRunner(t),
		diginfractl.WithArgs("driver", "install", "--download=false", "--type", "kmod"),
	)
	assert.NoError(t, loaderRes.Err(), "%s", loaderRes.Stderr())
	assert.Equal(t, 0, loaderRes.ExitCode())
	// We expect the module to be loaded in dkms
	assert.Regexp(t, `kernel module available.`, loaderRes.Stdout())

	// Now running Diginfra we should be able to run the kernel module
	diginfraRes := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithStopAfter(3*time.Second),
		diginfra.WithArgs("-o", "engine.kind=kmod"),
	)
	assert.NoError(t, diginfraRes.Err(), "%s", diginfraRes.Stderr())
	assert.Equal(t, 0, diginfraRes.ExitCode())
	// We want to be sure to run the Kernel module.
	assert.Regexp(t, `source with Kernel module`, diginfraRes.Stderr())
	// We want to be sure that the engine is correctly opened.
	assert.Regexp(t, `Events detected:`, diginfraRes.Stdout())
}

// This test doesn't need the diginfra-driver-loader but we put it here
// together with the other engines.
func TestDiginfraModernBpf(t *testing.T) {
	// Now running Diginfra we should be able to run the kernel module
	diginfraRes := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithStopAfter(3*time.Second),
		diginfra.WithArgs("-o", "engine.kind=modern_ebpf"),
	)
	assert.NoError(t, diginfraRes.Err(), "%s", diginfraRes.Stderr())
	assert.Equal(t, 0, diginfraRes.ExitCode())
	// We want to be sure to run the Kernel module.
	assert.Regexp(t, `source with modern BPF probe`, diginfraRes.Stderr())
	// We want to be sure that the engine is correctly opened.
	assert.Regexp(t, `Events detected:`, diginfraRes.Stdout())
}
