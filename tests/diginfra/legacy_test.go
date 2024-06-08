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

// NOTE: this file is a 1-1 porting of the legacy regression tests
// implemented in python that we historically have in diginfra/diginfra
// (see: https://github.com/diginfra/diginfra/tree/059a28184d1d4f498f5b0bd53ffe10d6fedf35c2/test).
// The porting has been 90% automated with a migration script
// (see: https://github.com/diginfra/testing/blob/32ce0c31eb8fa098a689f1888a4f11b984ae26d8/migration/main.go).
//
// Data files used for running the tests is generated on-the-fly by using
// `go generate` and are pulled from the same sources used in the python tests.
// Those files include rules, configurations, and captures files downloaded from
// both download.diginfra.org and the checked-in diginfra/diginfra source code.
//
// These tests only implements the legacy tests on the Diginfra executable, namely:
// - diginfra_tests.yaml
// - diginfra_traces.yaml
// - diginfra_tests_exceptions.yaml
//

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	grpcOutputs "github.com/diginfra/client-go/pkg/api/outputs"
	"github.com/diginfra/client-go/pkg/client"

	"github.com/diginfra/testing/pkg/diginfra"
	"github.com/diginfra/testing/pkg/run"
	"github.com/diginfra/testing/tests"
	"github.com/diginfra/testing/tests/data/captures"
	"github.com/diginfra/testing/tests/data/configs"
	"github.com/diginfra/testing/tests/data/outputs"
	"github.com/diginfra/testing/tests/data/rules"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiginfra_Legacy_EngineVersionMismatch(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRulesValidation(rules.EngineVersionMismatch),
	)
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.NotNil(t, res.RuleValidation().AllErrors().
		OfCode("LOAD_ERR_VALIDATE").
		OfItemType("required_engine_version"))
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_MacroOverriding(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithRules(rules.SingleRule, rules.OverrideMacro),
		diginfra.WithCaptureFile(captures.CatWrite),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_Endswith(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.Endswith),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_DisabledAndEnabledRules1(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithRules(rules.SingleRule),
		diginfra.WithDisabledTags("a"),
		diginfra.WithEnabledTags("a"),
		diginfra.WithCaptureFile(captures.CatWrite),
	)
	assert.Regexp(t, `Error: You can not specify both disabled .-D/-T. and enabled .-t. rules`, res.Stderr())
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_StdoutOutputStrict(t *testing.T) {
	t.Parallel()
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithConfig(configs.StdoutOutput),
		diginfra.WithRules(rules.SingleRule),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "time_format_iso_8601=true"),
	)

	assert.Equal(t, 0, res.ExitCode())
	expectedContent, err := outputs.SingleRuleWithCatWriteText.Content()
	assert.Nil(t, err)
	scanner := bufio.NewScanner(bytes.NewReader(expectedContent))
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		assert.Contains(t, res.Stdout(), scanner.Text())
	}
	assert.Nil(t, scanner.Err())
}

func TestDiginfra_Legacy_StdoutOutputJsonStrict(t *testing.T) {
	t.Parallel()
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithConfig(configs.StdoutOutput),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.SingleRuleWithTags),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "time_format_iso_8601=true"),
		diginfra.WithArgs("-o", "json_include_output_property=true"),
		diginfra.WithArgs("-o", "json_include_tags_property=true"),
		diginfra.WithEnvVars(map[string]string{"DIGINFRA_HOSTNAME": "test-diginfra-hostname"}),
	)

	assert.Equal(t, 0, res.ExitCode())
	expectedContent, err := outputs.SingleRuleWithCatWriteJSON.Content()
	assert.Nil(t, err)
	scanner := bufio.NewScanner(bytes.NewReader(expectedContent))
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		assert.Contains(t, res.Stdout(), scanner.Text())
	}
	assert.Nil(t, scanner.Err())
}

func TestDiginfra_Legacy_ListAppendFalse(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithRules(rules.ListAppendFalse),
		diginfra.WithCaptureFile(captures.CatWrite),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_MacroAppend(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.MacroAppend),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_ListSubstring(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithRules(rules.ListSubstring),
		diginfra.WithCaptureFile(captures.CatWrite),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_InvalidNotArray(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRulesValidation(rules.InvalidNotArray),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		OfCode("LOAD_ERR_YAML_VALIDATE").
		OfItemType("rules content").
		OfMessage("Rules content is not yaml array of objects"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_InvalidEngineVersionNotNumber(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRulesValidation(rules.InvalidEngineVersionNotNumber),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		OfCode("LOAD_ERR_YAML_VALIDATE").
		OfItemType("required_engine_version").
		OfMessage("Unable to parse engine version 'not-a-number' as a semver string. Expected \"x.y.z\" semver format."), res.Stdout())
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_InvalidOverwriteRuleMultipleDocs(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRulesValidation(rules.InvalidOverwriteRuleMultipleDocs),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		OfCode("LOAD_ERR_VALIDATE").
		OfItemType("rule").
		OfItemName("some rule").
		OfMessage("Undefined macro 'bar' used in filter."))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_DisabledRulesUsingSubstring(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithRules(rules.EmptyRules, rules.SingleRule),
		diginfra.WithDisabledRules("open_from"),
		diginfra.WithCaptureFile(captures.CatWrite),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_DetectSkipUnknownNoevt(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.SkipUnknownEvt),
		diginfra.WithCaptureFile(captures.CatWrite),
	)
	assert.Equal(t, 8, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("INFO").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_ListAppend(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.ListAppend),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_RuleAppendSkipped(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithMinRulePriority("ERROR"),
		diginfra.WithRules(rules.SingleRule, rules.AppendSingleRule),
		diginfra.WithCaptureFile(captures.CatWrite),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_SkipUnknownError(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRulesValidation(rules.SkipUnknownError),
	)
	assert.Equal(t, 1, res.RuleValidation().AllErrors().Count())
	assert.NotNil(t, res.RuleValidation().AllErrors().
		OfCode("LOAD_ERR_COMPILE_CONDITION").
		OfItemType("rule").
		OfItemName("Contains Unknown Event And Not Skipping (field)").
		OfMessage("filter_check called with nonexistent field proc.nobody"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_MultipleRulesOverriding(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithRules(rules.SingleRule, rules.OverrideRule),
		diginfra.WithCaptureFile(captures.CatWrite),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_InvalidAppendMacro(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRulesValidation(rules.InvalidBaseMacro, rules.InvalidAppendMacro),
	)
	assert.True(t, res.RuleValidation().At(0).Successful)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		OfCode("LOAD_ERR_COMPILE_CONDITION").
		OfItemType("macro").
		OfItemName("some_macro").
		OfMessage("unexpected token after 'execve', expecting 'or', 'and'"))
	assert.NotNil(t, res.RuleValidation().AllWarnings().
		OfCode("LOAD_UNUSED_MACRO").
		OfItemType("macro").
		OfItemName("some_macro").
		OfMessage("Macro not referred to by any other rule/macro"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_InvalidMissingListName(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRulesValidation(rules.InvalidMissingListName),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		OfCode("LOAD_ERR_YAML_VALIDATE").
		OfItemType("list").
		OfMessage("Mapping for key 'list' is empty"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_DisabledTagsB(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.TaggedRules),
		diginfra.WithDisabledTags("b"),
		diginfra.WithCaptureFile(captures.OpenMultipleFiles),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_1").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_2").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_3").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_4").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_5").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_6").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_7").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_8").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_9").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_10").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_11").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_12").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_13").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_RunTagsC(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.TaggedRules),
		diginfra.WithEnabledTags("c"),
		diginfra.WithCaptureFile(captures.OpenMultipleFiles),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_1").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_2").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_3").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_4").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_5").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_6").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_7").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_8").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_9").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_10").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_11").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_12").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_13").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_RunTagsAbc(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.TaggedRules),
		diginfra.WithEnabledTags("a", "b", "c"),
		diginfra.WithCaptureFile(captures.OpenMultipleFiles),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_1").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_2").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_3").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_4").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_5").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_6").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_7").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_8").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_9").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_10").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_11").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_12").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_13").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_RuleAppend(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.RuleAppend),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_ListOverriding(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithRules(rules.SingleRule, rules.OverrideList),
		diginfra.WithCaptureFile(captures.CatWrite),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_ListSubBare(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.ListSubBare),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_InvalidOverwriteMacroMultipleDocs(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRulesValidation(rules.InvalidOverwriteMacroMultipleDocs),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		OfCode("LOAD_ERR_VALIDATE").
		OfItemType("macro").
		OfItemName("some_macro").
		OfMessage("Undefined macro 'foo' used in filter."))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_DisabledTagsA(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.TaggedRules),
		diginfra.WithDisabledTags("a"),
		diginfra.WithCaptureFile(captures.OpenMultipleFiles),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_1").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_2").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_3").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_4").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_5").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_6").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_7").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_8").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_9").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_10").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_11").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_12").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_13").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_InvalidYamlParseError(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRulesValidation(rules.InvalidYamlParseError),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		OfCode("LOAD_ERR_YAML_PARSE").
		OfItemType("rules content").
		OfMessage("yaml-cpp: error at line 1, column 11: illegal map value"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_InvalidRuleWithoutOutput(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRulesValidation(rules.InvalidRuleWithoutOutput),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		OfCode("LOAD_ERR_YAML_VALIDATE").
		OfItemType("rule").
		OfItemName("no output rule").
		OfMessage("Item has no mapping for key 'output'"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_Syscalls(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.Syscalls),
		diginfra.WithCaptureFile(captures.Syscall),
		diginfra.WithAllEvents(),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("INFO").Count())
	assert.Equal(t, 2, res.Detections().OfRule("detect_madvise").Count())
	assert.Equal(t, 2, res.Detections().OfRule("detect_open").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_BuiltinRulesNoWarnings(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithRules(rules.LegacyDiginfraRules_v1_0_1),
		diginfra.WithCaptureFile(captures.Empty),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_RunTagsA(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.TaggedRules),
		diginfra.WithEnabledTags("a"),
		diginfra.WithCaptureFile(captures.OpenMultipleFiles),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_1").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_2").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_3").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_4").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_5").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_6").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_7").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_8").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_9").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_10").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_11").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_12").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_13").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_MonitorSyscallDropsNone(t *testing.T) {
	t.Parallel()
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithConfig(configs.DropsNone),
		diginfra.WithRules(rules.SingleRule),
		diginfra.WithCaptureFile(captures.PingSendto),
	)
	assert.NotRegexp(t, `event drop detected: 9 occurrences`, res.Stderr())
	assert.NotRegexp(t, `num times actions taken: 9`, res.Stderr())
	assert.NotRegexp(t, `Diginfra internal: syscall event drop`, res.Stderr())
	assert.NotRegexp(t, `Diginfra internal: syscall event drop`, res.Stdout())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_MonitorSyscallDropsIgnore(t *testing.T) {
	t.Parallel()
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithConfig(configs.DropsIgnore),
		diginfra.WithRules(rules.SingleRule),
		diginfra.WithCaptureFile(captures.PingSendto),
	)
	assert.Regexp(t, `event drop detected: 9 occurrences`, res.Stderr())
	assert.Regexp(t, `num times actions taken: 9`, res.Stderr())
	assert.NotRegexp(t, `Diginfra internal: syscall event drop`, res.Stderr())
	assert.NotRegexp(t, `Diginfra internal: syscall event drop`, res.Stdout())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_MonitorSyscallDropsThresholdOor(t *testing.T) {
	t.Parallel()
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithConfig(configs.DropsThresholdOor),
		diginfra.WithRules(rules.SingleRule),
		diginfra.WithCaptureFile(captures.PingSendto),
	)
	assert.Regexp(t, `syscall event drops threshold must be a double in the range`, res.Stderr())
	assert.NotRegexp(t, `event drop detected: 9 occurrences`, res.Stderr())
	assert.NotRegexp(t, `num times actions taken: 9`, res.Stderr())
	assert.NotRegexp(t, `Diginfra internal: syscall event drop`, res.Stderr())
	assert.NotRegexp(t, `Diginfra internal: syscall event drop`, res.Stdout())
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_MultipleRulesSuppressInfo(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithMinRulePriority("WARNING"),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.SingleRule, rules.DoubleRule),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithAllEvents(),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NotZero(t, res.Detections().OfPriority("ERROR").Count())
	assert.Equal(t, 8, res.Detections().OfRule("open_from_cat").Count())
	assert.Equal(t, 1, res.Detections().OfRule("exec_from_cat").Count())
	assert.Equal(t, 0, res.Detections().OfRule("access_from_cat").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_ListSubMid(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.ListSubMid),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_InvalidListWithoutItems(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRulesValidation(rules.InvalidListWithoutItems),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		OfCode("LOAD_ERR_YAML_VALIDATE").
		OfItemType("list").
		OfItemName("bad_list").
		OfMessage("Item has no mapping for key 'items'"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_DisabledRulesUsingEnabledFlag(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithRules(rules.SingleRuleEnabledFlag),
		diginfra.WithCaptureFile(captures.CatWrite),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_DisabledRuleUsingFalseEnabledFlagOnly(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithRules(rules.DisabledRuleUsingEnabledFlagOnly),
		diginfra.WithCaptureFile(captures.CatWrite),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_InvalidRuleOutput(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRulesValidation(rules.InvalidRuleOutput),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		OfCode("LOAD_ERR_COMPILE_OUTPUT").
		OfItemType("rule").
		OfItemName("rule_with_invalid_output").
		OfMessage("invalid formatting token not_a_real_field"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_FileOutputStrict(t *testing.T) {
	t.Parallel()
	run.WorkDir(func(workDir string) {
		outFilePath := workDir + "/file_output.txt"
		res := diginfra.Test(
			tests.NewDiginfraExecutableRunner(t),
			diginfra.WithConfig(configs.FileOutput),
			diginfra.WithRules(rules.SingleRule),
			diginfra.WithCaptureFile(captures.CatWrite),
			diginfra.WithArgs("-o", "time_format_iso_8601=true"),
			diginfra.WithArgs("-o", "file_output.filename="+outFilePath),
		)

		outFile := run.NewLocalFileAccessor(outFilePath, outFilePath)
		actualContent, err1 := outFile.Content()
		expectedContent, err2 := outputs.SingleRuleWithCatWriteText.Content()
		assert.Nil(t, err1)
		assert.Nil(t, err2)
		assert.Equal(t, string(expectedContent), string(actualContent))
		assert.Equal(t, 0, res.ExitCode())
	})
}

func TestDiginfra_Legacy_RunTagsBc(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.TaggedRules),
		diginfra.WithEnabledTags("b", "c"),
		diginfra.WithCaptureFile(captures.OpenMultipleFiles),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_1").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_2").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_3").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_4").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_5").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_6").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_7").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_8").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_9").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_10").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_11").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_12").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_13").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_MonitorSyscallDropsIgnoreAndLog(t *testing.T) {
	t.Parallel()
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithConfig(configs.DropsIgnoreLog),
		diginfra.WithRules(rules.SingleRule),
		diginfra.WithCaptureFile(captures.PingSendto),
	)
	assert.Regexp(t, `syscall event drop action "log" does not make sense with the "ignore" action`, res.Stderr())
	assert.NotRegexp(t, `event drop detected: 9 occurrences`, res.Stderr())
	assert.NotRegexp(t, `num times actions taken: 9`, res.Stderr())
	assert.NotRegexp(t, `Diginfra internal: syscall event drop`, res.Stderr())
	assert.NotRegexp(t, `Diginfra internal: syscall event drop`, res.Stdout())
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_MonitorSyscallDropsThresholdNeg(t *testing.T) {
	t.Parallel()
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithConfig(configs.DropsThresholdNeg),
		diginfra.WithRules(rules.SingleRule),
		diginfra.WithCaptureFile(captures.PingSendto),
	)
	assert.Regexp(t, `syscall event drops threshold must be a double in the range`, res.Stderr())
	assert.NotRegexp(t, `event drop detected: 9 occurrences`, res.Stderr())
	assert.NotRegexp(t, `num times actions taken: 9`, res.Stderr())
	assert.NotRegexp(t, `Diginfra internal: syscall event drop`, res.Stderr())
	assert.NotRegexp(t, `Diginfra internal: syscall event drop`, res.Stdout())
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_MultipleRulesLastEmpty(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.SingleRule, rules.EmptyRules),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_ListSubWhitespace(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.ListSubWhitespace),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_InvalidMacroWithoutCondition(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRulesValidation(rules.InvalidMacroWithoutCondition),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		OfCode("LOAD_ERR_YAML_VALIDATE").
		OfItemType("macro").
		OfItemName("bad_macro").
		OfMessage("Item has no mapping for key 'condition'"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_CatchallOrder(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.CatchallOrder),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("INFO").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_dev_null").Count())
	assert.Equal(t, 6, res.Detections().OfRule("dev_null").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_ListSubFront(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.ListSubFront),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_ListOrder(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.ListOrder),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_InvalidMissingMacroName(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRulesValidation(rules.InvalidMissingMacroName),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		OfCode("LOAD_ERR_YAML_VALIDATE").
		OfItemType("macro").
		OfMessage("Mapping for key 'macro' is empty"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_DisabledTagsAbc(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.TaggedRules),
		diginfra.WithDisabledTags("a", "b", "c"),
		diginfra.WithCaptureFile(captures.OpenMultipleFiles),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_1").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_2").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_3").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_4").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_5").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_6").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_7").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_8").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_9").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_10").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_11").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_12").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_13").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_SkipUnknownPrefix(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithRules(rules.SkipUnknownPrefix),
		diginfra.WithCaptureFile(captures.CatWrite),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_MonitorSyscallDropsLog(t *testing.T) {
	t.Parallel()
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithConfig(configs.DropsLog),
		diginfra.WithRules(rules.SingleRule),
		diginfra.WithCaptureFile(captures.PingSendto),
	)
	assert.Regexp(t, `event drop detected: 9 occurrences`, res.Stderr())
	assert.Regexp(t, `num times actions taken: 9`, res.Stderr())
	assert.Regexp(t, `Diginfra internal: syscall event drop`, res.Stderr())
	assert.NotRegexp(t, `Diginfra internal: syscall event drop`, res.Stdout())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_InvalidOverwriteRule(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRulesValidation(rules.InvalidBaseRule, rules.InvalidOverwriteRule),
	)
	assert.True(t, res.RuleValidation().At(0).Successful)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		OfCode("LOAD_ERR_VALIDATE").
		OfItemType("rule").
		OfItemName("some rule").
		OfMessage("Undefined macro 'bar' used in filter."))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_DisabledTagsC(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.TaggedRules),
		diginfra.WithDisabledTags("c"),
		diginfra.WithCaptureFile(captures.OpenMultipleFiles),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_1").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_2").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_3").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_4").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_5").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_6").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_7").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_8").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_9").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_10").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_11").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_12").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_13").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_RunTagsD(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.TaggedRules),
		diginfra.WithEnabledTags("d"),
		diginfra.WithCaptureFile(captures.OpenMultipleFiles),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_1").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_2").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_3").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_4").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_5").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_6").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_7").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_8").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_9").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_10").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_11").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_12").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_13").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_MacroAppendFalse(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithRules(rules.MacroAppendFalse),
		diginfra.WithCaptureFile(captures.CatWrite),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_InvalidAppendMacroMultipleDocs(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRulesValidation(rules.InvalidAppendMacroMultipleDocs),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		OfCode("LOAD_ERR_COMPILE_CONDITION").
		OfItemType("macro").
		OfItemName("some_macro").
		OfMessage("unexpected token after 'execve', expecting 'or', 'and'"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_DisabledRules(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithRules(rules.EmptyRules, rules.SingleRule),
		diginfra.WithDisabledRules("open_from_cat"),
		diginfra.WithCaptureFile(captures.CatWrite),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_MultipleRules(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.SingleRule, rules.DoubleRule),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithAllEvents(),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NotZero(t, res.Detections().OfPriority("INFO").Count())
	assert.NotZero(t, res.Detections().OfPriority("ERROR").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_MultipleDocs(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.SingleRule, rules.DoubleRule),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithAllEvents(),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NotZero(t, res.Detections().OfPriority("INFO").Count())
	assert.NotZero(t, res.Detections().OfPriority("ERROR").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_NestedListOverriding(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithRules(rules.SingleRule, rules.OverrideNestedList),
		diginfra.WithCaptureFile(captures.CatWrite),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_MacroOrder(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.MacroOrder),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_InvalidAppendRuleWithoutCondition(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRulesValidation(rules.InvalidAppendRuleWithoutCondition),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		OfCode("LOAD_ERR_VALIDATE").
		OfItemType("rule").
		OfItemName("no condition rule").
		OfMessage("Appended rule must have exceptions or condition property"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_SkipUnknownUnspecError(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRulesValidation(rules.SkipUnknownUnspec),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		OfCode("LOAD_ERR_COMPILE_CONDITION").
		OfItemType("rule").
		OfItemName("Contains Unknown Event And Unspecified").
		OfMessage("filter_check called with nonexistent field proc.nobody"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_MonitorSyscallDropsAlert(t *testing.T) {
	t.Parallel()
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithConfig(configs.DropsAlert),
		diginfra.WithRules(rules.SingleRule),
		diginfra.WithCaptureFile(captures.PingSendto),
	)
	assert.Regexp(t, `event drop detected: 9 occurrences`, res.Stderr())
	assert.Regexp(t, `num times actions taken: 9`, res.Stderr())
	assert.NotRegexp(t, `Diginfra internal: syscall event drop`, res.Stderr())
	assert.Regexp(t, `Diginfra internal: syscall event drop`, res.Stdout())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_MonitorSyscallDropsExit(t *testing.T) {
	t.Parallel()
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithConfig(configs.DropsExit),
		diginfra.WithRules(rules.SingleRule),
		diginfra.WithCaptureFile(captures.PingSendto),
	)
	assert.Regexp(t, `event drop detected: 1 occurrences`, res.Stderr())
	assert.Regexp(t, `num times actions taken: 1`, res.Stderr())
	assert.Regexp(t, `Diginfra internal: syscall event drop`, res.Stderr())
	assert.Regexp(t, `Exiting.`, res.Stderr())
	assert.NotRegexp(t, `Diginfra internal: syscall event drop`, res.Stdout())
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_DisabledTagsAb(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.TaggedRules),
		diginfra.WithDisabledTags("a", "b"),
		diginfra.WithCaptureFile(captures.OpenMultipleFiles),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_1").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_2").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_3").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_4").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_5").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_6").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_7").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_8").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_9").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_10").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_11").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_12").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_13").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_RunTagsB(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.TaggedRules),
		diginfra.WithEnabledTags("b"),
		diginfra.WithCaptureFile(captures.OpenMultipleFiles),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_1").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_2").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_3").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_4").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_5").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_6").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_7").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_8").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_9").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_10").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_11").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_12").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_13").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_RuleAppendFalse(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithRules(rules.RuleAppendFalse),
		diginfra.WithCaptureFile(captures.CatWrite),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_RuleOrder(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.RuleOrder),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_InvalidNotYaml(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRulesValidation(rules.InvalidNotYaml),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		OfCode("LOAD_ERR_YAML_VALIDATE").
		OfItemType("rules content").
		OfMessage("Rules content is not yaml"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_InvalidOverwriteMacro(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRulesValidation(rules.InvalidBaseMacro, rules.InvalidOverwriteMacro),
	)
	assert.True(t, res.RuleValidation().At(0).Successful)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		OfCode("LOAD_ERR_VALIDATE").
		OfItemType("macro").
		OfItemName("some_macro").
		OfMessage("Undefined macro 'foo' used in filter."))
	assert.NotNil(t, res.RuleValidation().AllWarnings().
		OfCode("LOAD_UNUSED_MACRO").
		OfItemType("macro").
		OfItemName("some_macro").
		OfMessage("Macro not referred to by any other rule/macro"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_InvalidMissingRuleName(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRulesValidation(rules.InvalidMissingRuleName),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		OfCode("LOAD_ERR_YAML_VALIDATE").
		OfItemType("rule").
		OfMessage("Mapping for key 'rule' is empty"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_RuleNamesWithSpaces(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.RuleNamesWithSpaces),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_MultipleRulesFirstEmpty(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.EmptyRules, rules.SingleRule),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_ProgramOutputStrict(t *testing.T) {
	t.Parallel()
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithConfig(configs.ProgramOutput),
		diginfra.WithRules(rules.SingleRule),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "time_format_iso_8601=true"),
		diginfra.WithArgs("-o", "program_output.program=cat"),
		diginfra.WithArgs("-o", "stdout_output.enabled=false"),
	)

	assert.Equal(t, 0, res.ExitCode())
	expectedContent, err := outputs.SingleRuleWithCatWriteText.Content()
	assert.Nil(t, err)
	scanner := bufio.NewScanner(bytes.NewReader(expectedContent))
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		assert.Contains(t, res.Stdout(), scanner.Text())
	}
	assert.Nil(t, scanner.Err())
}

func TestDiginfra_Legacy_InvalidAppendRule(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRulesValidation(rules.InvalidBaseRule, rules.InvalidAppendRule),
	)
	assert.True(t, res.RuleValidation().At(0).Successful)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		OfCode("LOAD_ERR_COMPILE_CONDITION").
		OfItemType("rule").
		OfItemName("some rule").
		OfMessage("unexpected token after 'open', expecting 'or', 'and'"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_InvalidAppendRuleMultipleDocs(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRulesValidation(rules.InvalidAppendRuleMultipleDocs),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		OfCode("LOAD_ERR_COMPILE_CONDITION").
		OfItemType("rule").
		OfItemName("some rule").
		OfMessage("unexpected token after 'open', expecting 'or', 'and'"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_DisabledAndEnabledRules2(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithRules(rules.SingleRule),
		diginfra.WithDisabledRules("open.*"),
		diginfra.WithEnabledTags("a"),
		diginfra.WithCaptureFile(captures.CatWrite),
	)
	assert.Regexp(t, `Error: You can not specify both disabled .-D/-T. and enabled .-t. rules`, res.Stderr())
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_RunTagsAb(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.TaggedRules),
		diginfra.WithEnabledTags("a", "b"),
		diginfra.WithCaptureFile(captures.OpenMultipleFiles),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_1").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_2").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_3").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_4").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_5").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_6").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_7").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_8").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_9").Count())
	assert.Equal(t, 1, res.Detections().OfRule("open_10").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_11").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_12").Count())
	assert.Equal(t, 0, res.Detections().OfRule("open_13").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_ValidateSkipUnknownNoevt(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRulesValidation(rules.SkipUnknownEvt),
	)
	assert.Equal(t, 3, res.RuleValidation().AllWarnings().Count())
	ruleWarnings := res.RuleValidation().AllWarnings().
		OfCode("LOAD_UNKNOWN_FILTER").
		OfItemType("rule")
	assert.NotNil(t, ruleWarnings.
		OfItemName("Contains Unknown Event And Skipping (field)").
		OfMessage("filter_check called with nonexistent field proc.nobody"), res.Stderr())
	assert.NotNil(t, ruleWarnings.
		OfItemName("Contains Unknown Event And Skipping (evt type)").
		OfMessage("unknown event type some_invalid_event"), res.Stderr())
	assert.NotNil(t, ruleWarnings.
		OfItemName("Contains Unknown Event And Skipping (output)").
		OfMessage("invalid formatting token proc.nobody"), res.Stderr())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_ListSubEnd(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.ListSubEnd),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_InvalidArrayItemNotObject(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRulesValidation(rules.InvalidArrayItemNotObject),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		OfCode("LOAD_ERR_YAML_VALIDATE").
		OfItemType("rules content item").
		OfMessage("Unexpected element type. Each element should be a yaml associative array."))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_RuleExceptionSecondItem(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.ExceptionsRuleExceptionSecondItem),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_RuleExceptionAppendMultipleValues(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.ExceptionsRuleExceptionAppendMultiple),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_RuleExceptionAppendComp(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.ExceptionsRuleExceptionAppendComp),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_RuleExceptionSingleField(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.ExceptionsRuleExceptionSingleField),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_RuleExceptionNewAppendNoField(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRulesValidation(rules.ExceptionsRuleExceptionNewNoFieldAppend),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		OfCode("LOAD_ERR_VALIDATE").
		OfItemType("exception").
		OfItemName("proc_cmdline").
		OfMessage("Rule exception must have fields property with a list of fields"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_RuleExceptionAppendOneValue(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.ExceptionsRuleExceptionAppendOneValue),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_RuleExceptionQuoted(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.ExceptionsRuleExceptionQuoted),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_RuleExceptionAppendThirdItem(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.ExceptionsRuleExceptionAppendThirdItem),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_RuleExceptionSingleFieldAppend(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.ExceptionsRuleExceptionSingleFieldAppend),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_RuleExceptionNewSingleFieldAppend(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.ExceptionsRuleExceptionNewSingleFieldAppend),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_RuleExceptionUnknownFields(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRulesValidation(rules.ExceptionsItemUnknownFields),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		OfCode("LOAD_ERR_VALIDATE").
		OfItemType("exception").
		OfItemName("ex1").
		OfMessage("'not.exist' is not a supported filter field"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_RuleExceptionSecondValue(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.ExceptionsRuleExceptionSecondValue),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_RuleExceptionValuesList(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.ExceptionsRuleExceptionValuesList),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_RuleExceptionAppendFieldsValuesLenMismatch(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRulesValidation(rules.ExceptionsAppendItemFieldsValuesLenMismatch),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		OfCode("LOAD_ERR_VALIDATE").
		OfItemType("exception").
		OfItemName("ex1").
		OfMessage("Fields and values lists must have equal length"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_RuleExceptionAppendItemNotInRule(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRulesValidation(rules.ExceptionsAppendItemNotInRule),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		OfCode("LOAD_ERR_VALIDATE").
		OfItemType("exception").
		OfItemName("ex2").
		OfMessage("Rule exception must have fields property with a list of fields"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_RuleExceptionThirdItem(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.ExceptionsRuleExceptionThirdItem),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_RuleExceptionNoFields(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRulesValidation(rules.ExceptionsItemNoFields),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		OfCode("LOAD_ERR_YAML_VALIDATE").
		OfItemType("exception").
		OfItemName("ex1").
		OfMessage("Item has no mapping for key 'fields'"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_RuleExceptionAppendNoName(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRulesValidation(rules.ExceptionsAppendItemNoName),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		OfCode("LOAD_ERR_YAML_VALIDATE").
		OfItemType("exception").
		OfMessage("Item has no mapping for key 'name'"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_RuleExceptionCompsFieldsLenMismatch(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRulesValidation(rules.ExceptionsItemCompsFieldsLenMismatch),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		OfCode("LOAD_ERR_VALIDATE").
		OfItemType("exception").
		OfItemName("ex1").
		OfMessage("Fields and comps lists must have equal length"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_RuleExceptionNoValues(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.ExceptionsRuleExceptionNoValues),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_RuleExceptionAppendSecondValue(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.ExceptionsRuleExceptionAppendSecondValue),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_RuleExceptionNoName(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRulesValidation(rules.ExceptionsItemNoName),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		OfCode("LOAD_ERR_YAML_VALIDATE").
		OfItemType("exception").
		OfMessage("Item has no mapping for key 'name'"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_RuleExceptionComp(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.ExceptionsRuleExceptionComp),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_RuleExceptionValuesListref(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.ExceptionsRuleExceptionValuesListref),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_RuleExceptionNewSecondFieldAppend(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.ExceptionsRuleExceptionNewSecondFieldAppend),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_RuleExceptionUnknownComp(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRulesValidation(rules.ExceptionsItemUnknownComp),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		OfCode("LOAD_ERR_VALIDATE").
		OfItemType("exception").
		OfItemName("ex1").
		OfMessage("'no-comp' is not a supported comparison operator"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_RuleExceptionFieldsValuesLenMismatch(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRulesValidation(rules.ExceptionsItemFieldsValuesLenMismatch),
	)
	assert.NotNil(t, res.RuleValidation().AllErrors().
		OfCode("LOAD_ERR_VALIDATE").
		OfItemType("exception").
		OfItemName("ex1").
		OfMessage("Fields and values lists must have equal length"))
	assert.Error(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 1, res.ExitCode())
}

func TestDiginfra_Legacy_RuleExceptionOneValue(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.ExceptionsRuleExceptionOneValue),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_RuleExceptionAppendSecondItem(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.ExceptionsRuleExceptionAppendSecondItem),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_RuleExceptionValuesListrefNoparens(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.ExceptionsRuleExceptionValuesListrefNoparens),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_ReadSensitiveFileUntrusted(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.LegacyDiginfraRules_v1_0_1),
		diginfra.WithCaptureFile(captures.TracesPositiveReadSensitiveFileUntrusted),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().OfRule("Read sensitive file untrusted").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_KernelUpgrade(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.LegacyDiginfraRules_v1_0_1),
		diginfra.WithCaptureFile(captures.TracesNegativeKernelUpgrade),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_CreateFilesBelowDev(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.LegacyDiginfraRules_v1_0_1),
		diginfra.WithCaptureFile(captures.TracesPositiveCreateFilesBelowDev),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("ERROR").Count())
	assert.Equal(t, 1, res.Detections().OfRule("Create files below dev").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_ReadSensitiveFileAfterStartup(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.LegacyDiginfraRules_v1_0_1),
		diginfra.WithCaptureFile(captures.TracesPositiveReadSensitiveFileAfterStartup),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.Equal(t, 1, res.Detections().OfRule("Read sensitive file untrusted").Count())
	assert.Equal(t, 1, res.Detections().OfRule("Read sensitive file trusted after startup").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_RunShellUntrusted(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.LegacyDiginfraRules_v1_0_1),
		diginfra.WithCaptureFile(captures.TracesPositiveRunShellUntrusted),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().OfPriority("DEBUG").Count())
	assert.Equal(t, 0, res.Detections().OfRule("Run shell untrusted").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_ChangeThreadNamespace(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.LegacyDiginfraRules_v1_0_1),
		diginfra.WithCaptureFile(captures.TracesPositiveChangeThreadNamespace),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().OfPriority("NOTICE").Count())
	assert.Equal(t, 0, res.Detections().OfRule("Change thread namespace").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_MkdirBinaryDirs(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.LegacyDiginfraRules_v1_0_1),
		diginfra.WithCaptureFile(captures.TracesPositiveMkdirBinaryDirs),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("ERROR").Count())
	assert.Equal(t, 1, res.Detections().OfRule("Mkdir binary dirs").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_SystemBinariesNetworkActivity(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.LegacyDiginfraRules_v1_0_1),
		diginfra.WithCaptureFile(captures.TracesPositiveSystemBinariesNetworkActivity),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("NOTICE").Count())
	assert.Equal(t, 1, res.Detections().OfRule("System procs network activity").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_WriteRpmDatabase(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.LegacyDiginfraRules_v1_0_1),
		diginfra.WithCaptureFile(captures.TracesPositiveWriteRpmDatabase),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("ERROR").Count())
	assert.Equal(t, 1, res.Detections().OfRule("Write below rpm database").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_DockerCompose(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.LegacyDiginfraRules_v1_0_1),
		diginfra.WithCaptureFile(captures.TracesNegativeDockerCompose),
		diginfra.WithAllEvents(),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("NOTICE").Count())
	assert.Equal(t, 2, res.Detections().OfRule("Redirect STDOUT/STDIN to Network Connection in Container").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_CurlUninstall(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.LegacyDiginfraRules_v1_0_1),
		diginfra.WithCaptureFile(captures.TracesNegativeCurlUninstall),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_DhcpclientRenew(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.LegacyDiginfraRules_v1_0_1),
		diginfra.WithCaptureFile(captures.TracesNegativeDhcpclientRenew),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_StagingWorker(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.LegacyDiginfraRules_v1_0_1),
		diginfra.WithCaptureFile(captures.TracesNegativeStagingWorker),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_DbProgramSpawnedProcess(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.LegacyDiginfraRules_v1_0_1),
		diginfra.WithCaptureFile(captures.TracesPositiveDbProgramSpawnedProcess),
		diginfra.WithAllEvents(),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("NOTICE").Count())
	assert.Equal(t, 1, res.Detections().OfRule("DB program spawned process").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_UserMgmtBinaries(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.LegacyDiginfraRules_v1_0_1),
		diginfra.WithCaptureFile(captures.TracesPositiveUserMgmtBinaries),
		diginfra.WithAllEvents(),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("NOTICE").Count())
	assert.Equal(t, 1, res.Detections().OfRule("User mgmt binaries").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_Exim4(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.LegacyDiginfraRules_v1_0_1),
		diginfra.WithCaptureFile(captures.TracesNegativeExim4),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_WriteEtc(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.LegacyDiginfraRules_v1_0_1),
		diginfra.WithCaptureFile(captures.TracesPositiveWriteEtc),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("ERROR").Count())
	assert.Equal(t, 1, res.Detections().OfRule("Write below etc").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_StagingCollector(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.LegacyDiginfraRules_v1_0_1),
		diginfra.WithCaptureFile(captures.TracesNegativeStagingCollector),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_ContainerPrivileged(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.LegacyDiginfraRules_v1_0_1),
		diginfra.WithCaptureFile(captures.TracesPositiveContainerPrivileged),
		diginfra.WithAllEvents(),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("INFO").Count())
	assert.Equal(t, 3, res.Detections().OfRule("Launch Privileged Container").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_ContainerSensitiveMount(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.LegacyDiginfraRules_v1_0_1),
		diginfra.WithCaptureFile(captures.TracesPositiveContainerSensitiveMount),
		diginfra.WithAllEvents(),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("INFO").Count())
	assert.Equal(t, 3, res.Detections().OfRule("Launch Sensitive Mount Container").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_WriteBinaryDir(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.LegacyDiginfraRules_v1_0_1),
		diginfra.WithCaptureFile(captures.TracesPositiveWriteBinaryDir),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("ERROR").Count())
	assert.Equal(t, 4, res.Detections().OfRule("Write below binary dir").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_CurlInstall(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.LegacyDiginfraRules_v1_0_1),
		diginfra.WithCaptureFile(captures.TracesNegativeCurlInstall),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_StagingDb(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.LegacyDiginfraRules_v1_0_1),
		diginfra.WithCaptureFile(captures.TracesNegativeStagingDb),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_ModifyBinaryDirs(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.LegacyDiginfraRules_v1_0_1),
		diginfra.WithCaptureFile(captures.TracesPositiveModifyBinaryDirs),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("ERROR").Count())
	assert.Equal(t, 1, res.Detections().OfRule("Modify binary dirs").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_NonSudoSetuid(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.LegacyDiginfraRules_v1_0_1),
		diginfra.WithCaptureFile(captures.TracesPositiveNonSudoSetuid),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_GitPush(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.LegacyDiginfraRules_v1_0_1),
		diginfra.WithCaptureFile(captures.TracesNegativeGitPush),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_KubeDemo(t *testing.T) {
	// todo(jasondellaluce): this is very heavy and slow, let's skip it for now
	t.Skip()
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithStopAfter(90*time.Second),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.LegacyDiginfraRules_v1_0_1),
		diginfra.WithCaptureFile(captures.TracesNegativeKubeDemo),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Zero(t, res.Detections().Count())
	assert.Zero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_DiginfraEventGenerator(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.LegacyDiginfraRules_v1_0_1),
		diginfra.WithCaptureFile(captures.TracesPositiveDiginfraEventGenerator),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("ERROR").Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NotZero(t, res.Detections().OfPriority("NOTICE").Count())
	assert.NotZero(t, res.Detections().OfPriority("DEBUG").Count())
	assert.Equal(t, 1, res.Detections().OfRule("Write below binary dir").Count())
	assert.Equal(t, 3, res.Detections().OfRule("Read sensitive file untrusted").Count())
	assert.Equal(t, 1, res.Detections().OfRule("Run shell untrusted").Count())
	assert.Equal(t, 1, res.Detections().OfRule("Write below rpm database").Count())
	assert.Equal(t, 1, res.Detections().OfRule("Write below etc").Count())
	assert.Equal(t, 1, res.Detections().OfRule("System procs network activity").Count())
	assert.Equal(t, 1, res.Detections().OfRule("Mkdir binary dirs").Count())
	assert.Equal(t, 1, res.Detections().OfRule("System user interactive").Count())
	assert.Equal(t, 1, res.Detections().OfRule("DB program spawned process").Count())
	assert.Equal(t, 0, res.Detections().OfRule("Non sudo setuid").Count())
	assert.Equal(t, 1, res.Detections().OfRule("Create files below dev").Count())
	assert.Equal(t, 2, res.Detections().OfRule("Modify binary dirs").Count())
	assert.Equal(t, 0, res.Detections().OfRule("Change thread namespace").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_SystemUserInteractive(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.LegacyDiginfraRules_v1_0_1),
		diginfra.WithCaptureFile(captures.TracesPositiveSystemUserInteractive),
		diginfra.WithAllEvents(),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("INFO").Count())
	assert.Equal(t, 1, res.Detections().OfRule("System user interactive").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_RuleNamesWithRegexChars(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.LegacyDiginfraRules_v1_0_1),
		diginfra.WithRules(rules.RuleNamesWithRegexChars),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.Equal(t, 8, res.Detections().OfRule(`Open From Cat ($\.*+?()[]{}|^)`).Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_JsonOutputNoOutputProperty(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.RuleAppend),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotRegexp(t, `.*Warning An open of /dev/null was seen.*`, res.Stdout())
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_JsonOutputNoTagsProperty(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.RuleAppend),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotRegexp(t, `.*"tags":[ ]*\[.*\],.*`, res.Stdout())
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_JsonOutputEmptyTagsProperty(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.RuleAppend),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=true"),
	)
	assert.Regexp(t, `.*"tags":[ ]*\[\],.*`, res.Stdout())
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_RulesDirectory(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.RulesDir000SingleRule, rules.RulesDir001DoubleRule),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithAllEvents(),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NotZero(t, res.Detections().OfPriority("INFO").Count())
	assert.NotZero(t, res.Detections().OfPriority("ERROR").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_EnabledRuleUsingFalseEnabledFlagOnly(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.EnabledRuleUsingEnabledFlagOnly),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.Equal(t, 8, res.Detections().OfRule("open_from_cat").Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_NullOutputField(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.NullOutputField),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "json_include_output_property=true"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Regexp(t, `Warning An open was seen .cport=<NA> command=cat /dev/null.`, res.Stdout())
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_InOperatorNetmasks(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.DetectConnectUsingIn),
		diginfra.WithCaptureFile(captures.ConnectLocalhost),
		diginfra.WithArgs("-o", "json_include_output_property=false"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("INFO").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_TimeIso8601(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRules(rules.SingleRule),
		diginfra.WithCaptureFile(captures.CatWrite),
		diginfra.WithArgs("-o", "time_format_iso_8601=true"),
		diginfra.WithArgs("-o", "json_include_output_property=true"),
		diginfra.WithArgs("-o", "json_include_tags_property=false"),
	)
	assert.Regexp(t, `^\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\+0000`, res.Stderr())
	assert.Regexp(t, `2016-08-04T16:17:57.882054739\+0000: Warning An open was seen`, res.Stdout())
	assert.NotZero(t, res.Detections().Count())
	assert.NotZero(t, res.Detections().OfPriority("WARNING").Count())
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_TestWarnings(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRulesValidation(rules.DiginfraRulesWarnings),
	)
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
	assert.True(t, res.RuleValidation().At(0).Successful)
	warnings := res.RuleValidation().AllWarnings().
		OfCode("LOAD_NO_EVTTYPE").
		OfItemType("rule").
		OfMessage("Rule matches too many evt.type values. This has a significant performance penalty.")
	assert.NotNil(t, warnings.OfItemName("no_evttype"))
	assert.NotNil(t, warnings.OfItemName("evttype_not_equals"))
	assert.NotNil(t, warnings.OfItemName("leading_not"))
	assert.NotNil(t, warnings.OfItemName("not_equals_at_end"))
	assert.NotNil(t, warnings.OfItemName("not_at_end"))
	assert.NotNil(t, warnings.OfItemName("not_equals_and_not"))
	assert.NotNil(t, warnings.OfItemName("leading_in_not_equals_at_evttype"))
	assert.NotNil(t, warnings.OfItemName("not_with_evttypes"))
	assert.NotNil(t, warnings.OfItemName("not_with_evttypes_addl"))
}

func grpcOutputResponseToDiginfraAlert(res *grpcOutputs.Response) *diginfra.Alert {
	outputFields := make(map[string]interface{})
	for k, v := range res.OutputFields {
		outputFields[k] = v
	}
	return &diginfra.Alert{
		Time:         res.Time.AsTime(),
		Rule:         res.Rule,
		Output:       res.Output,
		Priority:     res.Priority.String(),
		Source:       res.Source,
		Hostname:     res.Hostname,
		Tags:         res.Tags,
		OutputFields: outputFields,
	}
}

func TestDiginfra_Legacy_GrpcUnixSocketOutputs(t *testing.T) {
	var wg sync.WaitGroup
	defer wg.Wait()
	t.Parallel()

	// launch diginfra asynchronously
	ctx, ctxCancel := context.WithCancel(context.Background())
	defer ctxCancel()
	runner := tests.NewDiginfraExecutableRunner(t)
	socketName := runner.WorkDir() + "/diginfra.sock"
	wg.Add(1)
	go func() {
		defer wg.Done()
		res := diginfra.Test(
			runner,
			diginfra.WithContext(ctx),
			diginfra.WithRules(rules.SingleRuleWithTags),
			diginfra.WithConfig(configs.GrpcUnixSocket),
			diginfra.WithCaptureFile(captures.CatWrite),
			diginfra.WithStopAfter(30*time.Second),
			diginfra.WithArgs("-o", "time_format_iso_8601=true"),
			diginfra.WithArgs("-o", "grpc.bind_address=unix://"+socketName),
		)
		require.NotContains(t, res.Stderr(), "Error starting gRPC server")
		// todo(jasondellaluce): skipping this as it can be flacky (Diginfra sometimes shutsdown
		// with exit code -1), we need to investigate on that
		// require.Nil(t, res.Err())
	}()

	// wait up until Diginfra creates the unix socket
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(socketName); err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		break
	}

	// connect using the Diginfra grpc client and collect detection
	grpcClient, err := client.NewForConfig(ctx, &client.Config{UnixSocketPath: "unix://" + socketName})
	require.Nil(t, err)

	expectedCount := 8
	expectedErr := errors.New("expected error")
	detections := make(diginfra.Detections, 0)
	err = grpcClient.OutputsWatch(context.Background(), func(res *grpcOutputs.Response) error {
		detections = append(detections, grpcOutputResponseToDiginfraAlert(res))
		if len(detections) == expectedCount {
			// note: we stop Diginfra when we reache the number of expected
			// detections
			ctxCancel()
			return expectedErr
		}
		return nil
	}, 100*time.Millisecond)

	// perform checks on the detections
	// todo(jasondellaluce): add deeper checks on the received struct
	require.Equal(t, expectedErr, err)
	assert.Equal(t, expectedCount, detections.Count())
	assert.Equal(t, expectedCount, detections.
		OfPriority("WARNING").
		OfRule("open_from_cat").Count())
}

func TestDiginfra_Legacy_NoPluginsUnknownSource(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRulesValidation(rules.PluginsCloudtrailCreateInstances),
	)
	assert.NotNil(t, res.RuleValidation().AllWarnings().
		OfCode("LOAD_UNKNOWN_SOURCE").
		OfItemType("rule").
		OfItemName("Cloudtrail Create Instance").
		OfMessage("Unknown source aws_cloudtrail, skipping"))
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_AppendUnknownSource(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRulesValidation(rules.AppendUnknownSource),
	)
	assert.NotNil(t, res.RuleValidation().AllWarnings().
		OfCode("LOAD_UNKNOWN_SOURCE").
		OfItemType("rule").
		OfItemName("Rule1").
		OfMessage("Unknown source mysource, skipping"))
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}

func TestDiginfra_Legacy_NoPluginsUnknownSourceRuleException(t *testing.T) {
	t.Parallel()
	checkConfig(t)
	res := diginfra.Test(
		tests.NewDiginfraExecutableRunner(t),
		diginfra.WithOutputJSON(),
		diginfra.WithRulesValidation(rules.PluginsCloudtrailCreateInstancesExceptions),
	)
	assert.NotNil(t, res.RuleValidation().AllWarnings().
		OfCode("LOAD_UNKNOWN_SOURCE").
		OfItemType("rule").
		OfItemName("Cloudtrail Create Instance").
		OfMessage("Unknown source aws_cloudtrail, skipping"))
	assert.NoError(t, res.Err(), "%s", res.Stderr())
	assert.Equal(t, 0, res.ExitCode())
}
