package testdummy

import (
	"github.com/diginfra/testing/pkg/diginfra"
	"github.com/diginfra/testing/pkg/run"
	"github.com/diginfra/testing/tests"
	"github.com/diginfra/testing/tests/data/plugins"
	"github.com/diginfra/testing/tests/data/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"sync"
	"testing"
	"time"
)

func runDiginfraWithDummy(t *testing.T, r run.Runner, opts ...diginfra.TestOption) *diginfra.TestOutput {
	config, err := diginfra.NewPluginConfig(
		"plugin-config.yaml",
		&diginfra.PluginConfigInfo{
			Name:       "dummy",
			Library:    plugins.DummyPlugin.Name(),
			OpenParams: `'{"start": 1, "maxEvents": 2000000000}'`,
		},
	)
	require.Nil(t, err)
	options := []diginfra.TestOption{
		diginfra.WithEnabledSources("dummy"),
		diginfra.WithConfig(config),
		diginfra.WithExtraFiles(plugins.DummyPlugin),
	}
	options = append(options, opts...)
	return diginfra.Test(r, options...)
}

func TestDummy_PrometheusMetrics(t *testing.T) {
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

	diginfraRes := runDiginfraWithDummy(t,
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
