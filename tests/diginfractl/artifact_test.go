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

package testdiginfractl

import (
	"strings"
	"testing"

	"github.com/diginfra/testing/pkg/diginfra"
	"github.com/diginfra/testing/pkg/diginfractl"
	"github.com/diginfra/testing/pkg/run"
	"github.com/diginfra/testing/tests"
	"github.com/diginfra/testing/tests/data/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiginfractl_Artifact_InstallPlugin(t *testing.T) {
	t.Parallel()

	t.Run("fail-missing-arg", func(t *testing.T) {
		t.Parallel()
		runner := tests.NewDiginfractlExecutableRunner(t)
		res := diginfractl.Test(
			runner,
			diginfractl.WithArgs("artifact", "install"),
			diginfractl.WithPluginsDir(runner.WorkDir()+"/plugins"),
			diginfractl.WithRulesFilesDir(runner.WorkDir()+"/rulesfiles"),
			diginfractl.WithConfig(run.NewStringFileAccessor("config.yaml", "")),
		)
		assert.Error(t, res.Err(), "%s", res.Stdout())
		assert.NotZero(t, res.ExitCode())
		assert.Contains(t, res.Stdout(), "no artifacts to install")
	})

	t.Run("fail-invalid-artifact", func(t *testing.T) {
		t.Parallel()
		runner := tests.NewDiginfractlExecutableRunner(t)
		res := diginfractl.Test(
			runner,
			diginfractl.WithArgs("artifact", "install", "some_invalid_artifact"),
			diginfractl.WithPluginsDir(runner.WorkDir()+"/plugins"),
			diginfractl.WithRulesFilesDir(runner.WorkDir()+"/rulesfiles"),
			diginfractl.WithConfig(run.NewStringFileAccessor("config.yaml", "")),
		)
		assert.Error(t, res.Err(), "%s", res.Stdout())
		assert.NotZero(t, res.ExitCode())
		assert.Contains(t, res.Stdout(), "cannot find some_invalid_artifact")
	})

	t.Run("install-plugin", func(t *testing.T) {
		require.Nil(t, run.WorkDir(func(sharedWorkDir string) {
			res := diginfractl.Test(
				tests.NewDiginfractlExecutableRunner(t),
				diginfractl.WithArgs("artifact", "install", "dummy"),
				diginfractl.WithPluginsDir(sharedWorkDir+"/plugins"),
				diginfractl.WithRulesFilesDir(sharedWorkDir+"/rulesfiles"),
				diginfractl.WithConfig(run.NewStringFileAccessor("config.yaml", "")),
			)
			assert.NoError(t, res.Err(), "%s", res.Stdout()+"\n"+res.Stderr())
			assert.Zero(t, res.ExitCode())
			assert.Contains(t, res.Stdout(), "Artifact successfully installed")
			assert.FileExists(t, sharedWorkDir+"/plugins/libdummy.so")
		}))
	})

	t.Run("install-rules-with-deps", func(t *testing.T) {
		require.Nil(t, run.WorkDir(func(sharedWorkDir string) {
			res := diginfractl.Test(
				tests.NewDiginfractlExecutableRunner(t),
				diginfractl.WithArgs("artifact", "install", "cloudtrail-rules"),
				diginfractl.WithPluginsDir(sharedWorkDir+"/plugins"),
				diginfractl.WithRulesFilesDir(sharedWorkDir+"/rulesfiles"),
				diginfractl.WithConfig(run.NewStringFileAccessor("config.yaml", "")),
			)
			assert.NoError(t, res.Err(), "%s", res.Stdout()+"\n"+res.Stderr())
			assert.Zero(t, res.ExitCode())
			assert.Contains(t, res.Stdout(), "Artifact successfully installed")
			assert.FileExists(t, sharedWorkDir+"/rulesfiles/aws_cloudtrail_rules.yaml")
			assert.FileExists(t, sharedWorkDir+"/plugins/libcloudtrail.so")
			assert.FileExists(t, sharedWorkDir+"/plugins/libjson.so")
		}))
	})

	t.Run("install-for-diginfra", func(t *testing.T) {
		require.Nil(t, run.WorkDir(func(sharedWorkDir string) {
			res := diginfractl.Test(
				tests.NewDiginfractlExecutableRunner(t),
				diginfractl.WithArgs("artifact", "install", "cloudtrail-rules"),
				diginfractl.WithPluginsDir(sharedWorkDir+"/plugins"),
				diginfractl.WithRulesFilesDir(sharedWorkDir+"/rulesfiles"),
				diginfractl.WithConfig(run.NewStringFileAccessor("config.yaml", "")),
			)
			require.Nil(t, res.Err(), "%s", res.Stdout())
			require.Zero(t, res.ExitCode())

			// craft a configuration for the plugin
			config, err := diginfra.NewPluginConfig(
				"plugin-config.yaml",
				&diginfra.PluginConfigInfo{
					Name:    "cloudtrail",
					Library: plugins.CloudtrailPlugin.Name(),
				},
				&diginfra.PluginConfigInfo{
					Name:    "json",
					Library: plugins.JSONPlugin.Name(),
				},
			)
			require.Nil(t, err)

			// launch Diginfra with the installed plugin and validate its ruleset
			jsonFile := run.NewLocalFileAccessor("libjson.so", sharedWorkDir+"/plugins/libjson.so")
			cloudtrailFile := run.NewLocalFileAccessor("libcloudtrail.so", sharedWorkDir+"/plugins/libcloudtrail.so")
			rulesFile := run.NewLocalFileAccessor("aws_rules.yaml", sharedWorkDir+"/rulesfiles/aws_cloudtrail_rules.yaml")
			resDiginfra := diginfra.Test(
				tests.NewDiginfraExecutableRunner(t),
				diginfra.WithOutputJSON(),
				diginfra.WithConfig(config),
				diginfra.WithExtraFiles(jsonFile, cloudtrailFile),
				diginfra.WithRulesValidation(rulesFile),
				diginfra.WithEnabledSources("aws_cloudtrail"),
			)
			assert.Nil(t, resDiginfra.Err(), "%s", resDiginfra.Stderr())
			assert.Equal(t, 0, resDiginfra.ExitCode())
			assert.True(t, resDiginfra.RuleValidation().At(0).Successful)
			assert.Zero(t, resDiginfra.RuleValidation().AllWarnings().Count())
		}))
	})
}

func TestDiginfractl_Artifact_Info(t *testing.T) {
	t.Parallel()

	t.Run("fail-missing-arg", func(t *testing.T) {
		t.Parallel()
		runner := tests.NewDiginfractlExecutableRunner(t)
		res := diginfractl.Test(
			runner,
			diginfractl.WithArgs("artifact", "info"),
			diginfractl.WithPluginsDir(runner.WorkDir()+"/plugins"),
			diginfractl.WithRulesFilesDir(runner.WorkDir()+"/rulesfiles"),
			diginfractl.WithConfig(run.NewStringFileAccessor("config.yaml", "")),
		)
		assert.Error(t, res.Err(), "%s", res.Stderr())
		assert.NotZero(t, res.ExitCode())
		assert.Contains(t, res.Stdout(), "requires at least 1 arg(s), only received 0")
	})

	t.Run("info-plugin", func(t *testing.T) {
		t.Parallel()
		runner := tests.NewDiginfractlExecutableRunner(t)
		require.Nil(t, run.WorkDir(func(sharedWorkDir string) {
			res := diginfractl.Test(
				runner,
				diginfractl.WithArgs("artifact", "info", "dummy"),
				diginfractl.WithPluginsDir(sharedWorkDir+"/plugins"),
				diginfractl.WithRulesFilesDir(sharedWorkDir+"/rulesfiles"),
				diginfractl.WithConfig(run.NewStringFileAccessor("config.yaml", "")),
			)
			assert.NoError(t, res.Err(), "%s", res.Stdout()+"\n"+res.Stderr())
			assert.Zero(t, res.ExitCode())
			assert.Regexp(t, `.*REF[\s]+TAGS.*`, res.Stdout())
			assert.Regexp(t, `.*ghcr.io\/diginfra\/plugins\/plugin\/dummy[\s]*(latest[\s]*,[\s]*)?[\s]+([0-9]+(.[0-9]+)?(.[0-9]+)?[\s]*,[\s]*)+[\s]*(latest)?.*`, res.Stdout())
			assert.NoFileExists(t, sharedWorkDir+"/plugins/libdummy.so")
		}))
	})

	t.Run("info-rules", func(t *testing.T) {
		t.Parallel()
		runner := tests.NewDiginfractlExecutableRunner(t)
		require.Nil(t, run.WorkDir(func(sharedWorkDir string) {
			res := diginfractl.Test(
				runner,
				diginfractl.WithArgs("artifact", "info", "cloudtrail-rules"),
				diginfractl.WithPluginsDir(sharedWorkDir+"/plugins"),
				diginfractl.WithRulesFilesDir(sharedWorkDir+"/rulesfiles"),
				diginfractl.WithConfig(run.NewStringFileAccessor("config.yaml", "")),
			)
			assert.NoError(t, res.Err(), "%s", res.Stdout()+"\n"+res.Stderr())
			assert.Zero(t, res.ExitCode())
			assert.Regexp(t, `.*REF[\s]+TAGS.*`, res.Stdout())
			assert.Regexp(t, `.*ghcr.io\/diginfra\/plugins\/ruleset\/cloudtrail[\s]*(latest[\s]*,[\s]*)?[\s]+([0-9]+(.[0-9]+)?(.[0-9]+)?[\s]*,[\s]*)+[\s]*(latest)?.*`, res.Stdout())
			assert.NoFileExists(t, sharedWorkDir+"/plugins/libcloudtrail.so")
			assert.NoFileExists(t, sharedWorkDir+"/rulesfiles/aws_cloudtrail_rules.yaml")
		}))
	})
}

func TestDiginfractl_Artifact_List(t *testing.T) {
	t.Parallel()

	t.Run("list-all", func(t *testing.T) {
		t.Parallel()
		runner := tests.NewDiginfractlExecutableRunner(t)
		require.Nil(t, run.WorkDir(func(sharedWorkDir string) {
			res := diginfractl.Test(
				runner,
				diginfractl.WithArgs("artifact", "list"),
				diginfractl.WithPluginsDir(runner.WorkDir()+"/plugins"),
				diginfractl.WithRulesFilesDir(runner.WorkDir()+"/rulesfiles"),
				diginfractl.WithConfig(run.NewStringFileAccessor("config.yaml", "")),
			)
			assert.NoError(t, res.Err(), "%s", res.Stdout()+"\n"+res.Stderr())
			assert.Zero(t, res.ExitCode())
			assert.GreaterOrEqual(t, len(strings.Split(res.Stdout(), "\n")), 2)
			assert.Regexp(t, `.*INDEX[\s]+ARTIFACT[\s]+TYPE[\s]+REGISTRY[\s]+REPOSITORY.*`, res.Stdout())
			assert.Regexp(t, `.*diginfra[\s]+dummy[\s]+plugin[\s]+ghcr.io[\s]+diginfra/plugins/plugin/dummy.*`, res.Stdout())
		}))
	})

	t.Run("list-plugins", func(t *testing.T) {
		t.Parallel()
		runner := tests.NewDiginfractlExecutableRunner(t)
		require.Nil(t, run.WorkDir(func(sharedWorkDir string) {
			res := diginfractl.Test(
				runner,
				diginfractl.WithArgs("artifact", "list", "--type=plugin"),
				diginfractl.WithPluginsDir(runner.WorkDir()+"/plugins"),
				diginfractl.WithRulesFilesDir(runner.WorkDir()+"/rulesfiles"),
				diginfractl.WithConfig(run.NewStringFileAccessor("config.yaml", "")),
			)
			assert.NoError(t, res.Err(), "%s", res.Stdout()+"\n"+res.Stderr())
			assert.Zero(t, res.ExitCode())
			assert.GreaterOrEqual(t, len(strings.Split(res.Stdout(), "\n")), 2)
			assert.Regexp(t, `.*INDEX[\s]+ARTIFACT[\s]+TYPE[\s]+REGISTRY[\s]+REPOSITORY.*`, res.Stdout())
			assert.Regexp(t, `.*diginfra[\s]+dummy[\s]+plugin[\s]+ghcr.io[\s]+diginfra/plugins/plugin/dummy.*`, res.Stdout())
			assert.NotRegexp(t, `.*diginfra.*rulesfile[\s]+ghcr.io.*`, res.Stdout())
		}))
	})

	t.Run("list-rules", func(t *testing.T) {
		t.Parallel()
		runner := tests.NewDiginfractlExecutableRunner(t)
		require.Nil(t, run.WorkDir(func(sharedWorkDir string) {
			res := diginfractl.Test(
				runner,
				diginfractl.WithArgs("artifact", "list", "--type=rulesfile"),
				diginfractl.WithPluginsDir(runner.WorkDir()+"/plugins"),
				diginfractl.WithRulesFilesDir(runner.WorkDir()+"/rulesfiles"),
				diginfractl.WithConfig(run.NewStringFileAccessor("config.yaml", "")),
			)
			assert.NoError(t, res.Err(), "%s", res.Stdout()+"\n"+res.Stderr())
			assert.Zero(t, res.ExitCode())
			assert.GreaterOrEqual(t, len(strings.Split(res.Stdout(), "\n")), 2)
			assert.Regexp(t, `.*INDEX[\s]+ARTIFACT[\s]+TYPE[\s]+REGISTRY[\s]+REPOSITORY.*`, res.Stdout())
			assert.Regexp(t, `.*diginfra[\s]+cloudtrail-rules[\s]+rulesfile[\s]+ghcr.io[\s]+diginfra/plugins/ruleset/cloudtrail.*`, res.Stdout())
			assert.NotRegexp(t, `.*diginfra.*plugin[\s]+ghcr.io.*`, res.Stdout())
		}))
	})
}

func TestDiginfractl_Artifact_Search(t *testing.T) {
	t.Parallel()

	t.Run("fail-missing-arg", func(t *testing.T) {
		t.Parallel()
		runner := tests.NewDiginfractlExecutableRunner(t)
		res := diginfractl.Test(
			runner,
			diginfractl.WithArgs("artifact", "search"),
			diginfractl.WithPluginsDir(runner.WorkDir()+"/plugins"),
			diginfractl.WithRulesFilesDir(runner.WorkDir()+"/rulesfiles"),
			diginfractl.WithConfig(run.NewStringFileAccessor("config.yaml", "")),
		)
		assert.Error(t, res.Err(), "%s", res.Stderr())
		assert.NotZero(t, res.ExitCode())
		assert.Contains(t, res.Stdout(), "requires at least 1 arg(s), only received 0")
	})

	t.Run("seach-dummy", func(t *testing.T) {
		t.Parallel()
		require.Nil(t, run.WorkDir(func(sharedWorkDir string) {
			res := diginfractl.Test(
				tests.NewDiginfractlExecutableRunner(t),
				diginfractl.WithArgs("artifact", "search", "dummy"),
				diginfractl.WithPluginsDir(sharedWorkDir+"/plugins"),
				diginfractl.WithRulesFilesDir(sharedWorkDir+"/rulesfiles"),
				diginfractl.WithConfig(run.NewStringFileAccessor("config.yaml", "")),
			)
			assert.NoError(t, res.Err(), "%s", res.Stdout()+"\n"+res.Stderr())
			assert.Zero(t, res.ExitCode())
			assert.Regexp(t, `.*INDEX[\s]+ARTIFACT[\s]+TYPE[\s]+REGISTRY[\s]+REPOSITORY.*`, res.Stdout())
			assert.Regexp(t, `.*diginfra[\s]+dummy[\s]+plugin[\s]+ghcr.io[\s]+diginfra/plugins/plugin/dummy.*`, res.Stdout())
			assert.Regexp(t, `.*diginfra[\s]+dummy_c[\s]+plugin[\s]+ghcr.io[\s]+diginfra/plugins/plugin/dummy_c.*`, res.Stdout())
			assert.NoFileExists(t, sharedWorkDir+"/plugins/libdummy.so")
			assert.NoFileExists(t, sharedWorkDir+"/plugins/libdummy_c.so")
		}))
	})

	t.Run("seach-dummy-maximum-score", func(t *testing.T) {
		t.Parallel()
		require.Nil(t, run.WorkDir(func(sharedWorkDir string) {
			res := diginfractl.Test(
				tests.NewDiginfractlExecutableRunner(t),
				diginfractl.WithArgs("artifact", "search", "dummy", "--min-score=1"),
				diginfractl.WithPluginsDir(sharedWorkDir+"/plugins"),
				diginfractl.WithRulesFilesDir(sharedWorkDir+"/rulesfiles"),
				diginfractl.WithConfig(run.NewStringFileAccessor("config.yaml", "")),
			)
			assert.NoError(t, res.Err(), "%s", res.Stdout()+"\n"+res.Stderr())
			assert.Zero(t, res.ExitCode())
			assert.Regexp(t, `.*INDEX[\s]+ARTIFACT[\s]+TYPE[\s]+REGISTRY[\s]+REPOSITORY.*`, res.Stdout())
			assert.Regexp(t, `.*diginfra[\s]+dummy[\s]+plugin[\s]+ghcr.io[\s]+diginfra/plugins/plugin/dummy.*`, res.Stdout())
			assert.Regexp(t, `.*diginfra[\s]+dummy_c[\s]+plugin[\s]+ghcr.io[\s]+diginfra/plugins/plugin/dummy_c.*`, res.Stdout())
			assert.NoFileExists(t, sharedWorkDir+"/plugins/libdummy.so")
		}))
	})

	t.Run("search-all", func(t *testing.T) {
		t.Parallel()
		runner := tests.NewDiginfractlExecutableRunner(t)
		resList := diginfractl.Test(
			runner,
			diginfractl.WithArgs("artifact", "list"),
			diginfractl.WithPluginsDir(runner.WorkDir()+"/plugins"),
			diginfractl.WithRulesFilesDir(runner.WorkDir()+"/rulesfiles"),
			diginfractl.WithConfig(run.NewStringFileAccessor("config.yaml", "")),
		)
		resSearch := diginfractl.Test(
			runner,
			diginfractl.WithArgs("artifact", "search", ""),
			diginfractl.WithPluginsDir(runner.WorkDir()+"/plugins"),
			diginfractl.WithRulesFilesDir(runner.WorkDir()+"/rulesfiles"),
			diginfractl.WithConfig(run.NewStringFileAccessor("config.yaml", "")),
		)
		assert.Nil(t, resList.Err(), "%s", resList.Stdout())
		assert.Nil(t, resSearch.Err(), "%s", resSearch.Stdout())
		assert.Zero(t, resList.ExitCode())
		assert.Zero(t, resSearch.ExitCode())
		listLines := strings.Split(resSearch.Stdout(), "\n")
		searchLines := strings.Split(resSearch.Stdout(), "\n")
		for _, line := range listLines {
			found := false
			for _, searchline := range searchLines {
				if line == searchline {
					found = true
				}
			}
			assert.True(t, found, "empty search must have same output as list")
		}
	})
}
