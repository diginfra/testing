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
	"testing"

	"github.com/diginfra/testing/pkg/diginfra"
	"github.com/diginfra/testing/tests"
	"github.com/diginfra/testing/tests/data/captures"
	"github.com/diginfra/testing/tests/data/configs"
	"github.com/diginfra/testing/tests/data/rules"
	"github.com/stretchr/testify/assert"
)

func TestDiginfra_Config_RuleMatchingFirst(t *testing.T) {
	t.Parallel()
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithRules(rules.ShadowingRules),
		diginfra.WithConfig(configs.RuleMatchingFirst),
		diginfra.WithCaptureFile(captures.TracesPositiveReadSensitiveFileUntrusted),
		diginfra.WithOutputJSON(),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
	assert.Equal(t, 1, res.Detections().Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_1").Count())
}

func TestDiginfra_Config_RuleMatchingAll(t *testing.T) {
	t.Parallel()
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithRules(rules.ShadowingRules),
		diginfra.WithConfig(configs.RuleMatchingAll),
		diginfra.WithCaptureFile(captures.TracesPositiveReadSensitiveFileUntrusted),
		diginfra.WithOutputJSON(),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
	assert.Equal(t, 2, res.Detections().Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_1").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_2").Count())
}

func TestDiginfra_Config_RuleMatchingWrongValue(t *testing.T) {
	t.Parallel()
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithRules(rules.ShadowingRules),
		diginfra.WithConfig(configs.RuleMatchingWrongValue),
		diginfra.WithCaptureFile(captures.TracesPositiveReadSensitiveFileUntrusted),
		diginfra.WithOutputJSON(),
	)
	assert.NotNil(t, res.Stderr())
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Contains(t, res.Stderr(), "Unknown rule matching strategy")
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Config_Metrics_Enabled(t *testing.T) {
	t.Parallel()
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithRules(rules.ShadowingRules),
		diginfra.WithConfig(configs.MetricsEnabled),
		diginfra.WithCaptureFile(captures.TracesPositiveReadSensitiveFileUntrusted),
		diginfra.WithOutputJSON(),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}
