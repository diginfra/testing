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

package testdiginfra

import (
	"github.com/diginfra/testing/pkg/run"
	"github.com/diginfra/testing/tests/data/rules"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/diginfra/testing/pkg/diginfra"
	"github.com/diginfra/testing/tests"
	"github.com/diginfra/testing/tests/data/configs"

	"github.com/stretchr/testify/assert"
)

// todo(jasondellaluce): implement tests for the non-covered Diginfra config fields:
//   watch_config_files, libs_logger, buffered_outputs, syscall_event_timeouts,
//   syslog_output, file_output, stdout_output, webserver, program_output,
//   http_output, metadata_download, output_timeout, outputs
//
// todo(jasondellaluce): test Diginfra behavior on environment variables and their
// priorities in combination with their args/configs/cmds counterparts:
//   DIGINFRA_K8S_API, DIGINFRA_K8S_API_CERT, DIGINFRA_MESOS_API, DIGINFRA_HOSTNAME,
//   DIGINFRA_GRPC_HOSTNAME, DIGINFRA_BPF_PROBE, HOME (used for bpf probe)
//
// todo(jasondellaluce): implement tests for Diginfra reaction to signals:
//   SIGINT, SIGUSR1, SIGHUP
//
// todo(jasondellaluce): implement tests for other non-covered Diginfra things:
//   - collection of live events with kmod, bpf, modern-bpf, gvisor, userspace
//   - collection of live events with multiple event sources active at the same
//   - stress test with event generator, checking memory usage and event drops

// checkConfig skips a test if the default configuration filepath
// is not available in the local filesystem.
func checkConfig(t *testing.T) {
	if _, err := os.Stat(diginfra.DiginfraConfig); err != nil {
		t.Skipf("could not find Diginfra config at %s: %s", diginfra.DiginfraConfig, err.Error())
	}
}

// checkNotStaticExecutable is Diginfra executables use a static binary build.
func checkNotStaticExecutable(t *testing.T) {
	if tests.IsStaticDiginfraExecutable() {
		t.Skipf("test not available for static Diginfra builds")
	}
}

func TestDiginfra_Miscs_StartupFail(t *testing.T) {
	runner := tests.NewDiginfraExecutableRunner(t)
	t.Run("empty-config", func(t *testing.T) {
		res := diginfra.Test(runner, diginfra.WithConfig(configs.EmptyConfig))
		assert.Error(t, res.Err(), "%s", res.Stderr())
		assert.Equal(t, res.ExitCode(), 1)
		assert.Contains(t, res.Stderr(), "You must specify at least one rules file")
	})
}

func TestDiginfra_Miscs_HotReload(t *testing.T) {
	cwd, err := os.Getwd()
	assert.NoError(t, err)
	path := filepath.Join(cwd, "hot_reload_enabled.yaml")
	_ = os.WriteFile(path, []byte(`watch_config_files: true`), 0700)
	hotReloadCfg := run.NewLocalFileAccessor(path, path)

	t.Cleanup(func() {
		_ = os.Remove(path)
	})

	go func() {
		time.Sleep(2 * time.Second)
		f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0700)
		_, _ = f.WriteString("  \n\n")
		_ = f.Close()
	}()

	diginfraRes := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithConfig(hotReloadCfg),
		diginfra.WithRules(rules.SingleRule),
		diginfra.WithStopAfter(5*time.Second),
		diginfra.WithArgs("-o", "engine.kind=nodriver"),
	)
	assert.NoError(t, diginfraRes.Err(), "%s", diginfraRes.Stderr())
	assert.Equal(t, 0, diginfraRes.ExitCode())
	// We want to be sure that the hot reload was triggered
	assert.Regexp(t, `SIGHUP received, restarting...`, diginfraRes.Stderr())
}

func TestDiginfra_Miscs_PrometheusMetricsNoDriver(t *testing.T) {
	var (
		wg         sync.WaitGroup
		metricsErr error
	)
	wg.Add(1)

	go func() {
		defer wg.Done()
		time.Sleep(2 * time.Second)
		_, metricsErr = http.Get("http://127.0.0.1:8765/metrics")
	}()

	diginfraRes := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithPrometheusMetrics(),
		diginfra.WithRules(rules.SingleRule),
		diginfra.WithStopAfter(5*time.Second),
		diginfra.WithArgs("-o", "engine.kind=nodriver"),
	)
	assert.NoError(t, diginfraRes.Err(), "%s", diginfraRes.Stderr())
	assert.Equal(t, 0, diginfraRes.ExitCode())

	wg.Wait()

	assert.NoError(t, metricsErr)
}
