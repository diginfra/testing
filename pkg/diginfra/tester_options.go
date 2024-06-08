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
	"context"
	"fmt"
	"time"

	"github.com/diginfra/testing/pkg/run"
)

func withMultipleArgValues(arg string, values ...string) TestOption {
	return func(o *testOptions) {
		for _, v := range values {
			o.args = append(o.args, arg)
			o.args = append(o.args, v)
		}
	}
}

// WithArgs runs Diginfra with the given arguments.
func WithArgs(args ...string) TestOption {
	return func(ro *testOptions) { ro.args = append(ro.args, args...) }
}

// WithRules runs Diginfra with the given rules files through the `-r` option.
func WithRules(rules ...run.FileAccessor) TestOption {
	return func(o *testOptions) {
		for _, r := range rules {
			o.args = append(o.args, "-r", r.Name())
			o.files = append(o.files, r)
		}
	}
}

// WithConfig runs Diginfra with the given config file through the `-c` option.
func WithConfig(f run.FileAccessor) TestOption {
	return func(o *testOptions) {
		o.args = removeFromArgs(o.args, "-c", 1)
		o.args = append(o.args, "-c", f.Name())
		o.files = append(o.files, f)
	}
}

// WithEnabledTags runs Diginfra with enabled rules tags through the `-t` option.
func WithEnabledTags(tags ...string) TestOption {
	return withMultipleArgValues("-t", tags...)
}

// WithDisabledTags runs Diginfra with disabled rules tags through the `-T` option.
func WithDisabledTags(tags ...string) TestOption {
	return withMultipleArgValues("-T", tags...)
}

// WithDisabledRules runs Diginfra with disabled rules through the `-D` option.
func WithDisabledRules(rules ...string) TestOption {
	return withMultipleArgValues("-D", rules...)
}

// WithEnabledSources runs Diginfra with enabled event sources through the `--enable-source` option.
func WithEnabledSources(sources ...string) TestOption {
	return withMultipleArgValues("--enable-source", sources...)
}

// WithDisabledSources runs Diginfra with disabled event sources through the `--disable-source` option.
func WithDisabledSources(sources ...string) TestOption {
	return withMultipleArgValues("--disable-source", sources...)
}

// WithPrometheusMetrics runs Diginfra enabling prometheus metrics endpoint.
func WithPrometheusMetrics() TestOption {
	return func(o *testOptions) {
		o.args = append(o.args, "-o", "metrics.enabled=true")
		o.args = append(o.args, "-o", "metrics.output_rule=true")
		o.args = append(o.args, "-o", "metrics.interval=2s")
		o.args = append(o.args, "-o", "webserver.enabled=true")
		o.args = append(o.args, "-o", "webserver.prometheus_metrics_enabled=true")
	}
}

// WithMinRulePriority runs Diginfra by forcing a mimimum rules priority.
func WithMinRulePriority(priority string) TestOption {
	return func(o *testOptions) {
		o.args = append(o.args, "-o", "priority="+priority)
	}
}

// WithOutputJSON runs Diginfra by forcing a the output in JSON format.
func WithOutputJSON() TestOption {
	return func(o *testOptions) {
		o.args = append(o.args, "-o", "json_output=true")
	}
}

// WithAllEvents runs Diginfra with all events enabled through the `-A` option.
func WithAllEvents() TestOption {
	return func(o *testOptions) {
		o.args = append(o.args, "-A")
	}
}

// WithCaptureFile runs Diginfra reading events from a capture file through the `-o engine.kind=replay` option.
func WithCaptureFile(f run.FileAccessor) TestOption {
	return func(o *testOptions) {
		o.args = append(o.args, "-o", "engine.kind=replay", "-o", fmt.Sprintf("engine.replay.capture_file=%s", f.Name()))
		o.files = append(o.files, f)
	}
}

// WithContextDeadline runs Diginfra with a maximum context deadline.
func WithContextDeadline(duration time.Duration) TestOption {
	return func(o *testOptions) {
		o.duration = duration
	}
}

// WithRulesValidation runs Diginfra with the given rules files to be validated through the `-V` option.
func WithRulesValidation(rules ...run.FileAccessor) TestOption {
	return func(o *testOptions) {
		for _, r := range rules {
			o.args = append(o.args, "-V", r.Name())
			o.files = append(o.files, r)
		}
	}
}

// WithExtraFiles runs Diginfra with a given set of extra loaded files.
// This can be used to make the underlying runner aware of files referred to by
// Diginfra, its config, or arguments set with WithArgs.
func WithExtraFiles(files ...run.FileAccessor) TestOption {
	return func(o *testOptions) {
		o.files = append(o.files, files...)
	}
}

// WithEnvVars runs Diginfra with a given set of environment varibles.
func WithEnvVars(vars map[string]string) TestOption {
	return func(o *testOptions) {
		o.runOpts = append(o.runOpts, run.WithEnvVars(vars))
	}
}

// WithContext runs Diginfra with a given context.
func WithContext(ctx context.Context) TestOption {
	return func(o *testOptions) { o.ctx = ctx }
}

// WithStopAfter tells Diginfra to stop after 'duration' with the `-M` option.
func WithStopAfter(duration time.Duration) TestOption {
	return func(o *testOptions) {
		o.args = removeFromArgs(o.args, "-M", 1)
		o.args = append(o.args, "-M", fmt.Sprintf("%d", int64(duration.Seconds())))
	}
}
