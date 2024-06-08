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

package diginfractl

import (
	"context"

	"github.com/diginfra/testing/pkg/run"
	"go.uber.org/multierr"
)

// Err returns a non-nil error in case of issues when running diginfractl.
func (t *TestOutput) Err() error {
	return multierr.Append(t.opts.err, t.err)
}

// DurationExceeded returns true if the diginfractl run exceeded the expected
// duration or if the context had expired.
func (t *TestOutput) DurationExceeded() bool {
	for _, err := range multierr.Errors(t.Err()) {
		if err == context.DeadlineExceeded {
			return true
		}
	}
	return false
}

// ExitCode returns the numeric exit code of the diginfractl process.
func (t *TestOutput) ExitCode() int {
	for _, err := range multierr.Errors(t.Err()) {
		if exitCodeErr, ok := err.(*run.ExitCodeError); ok {
			return exitCodeErr.Code
		}
	}
	return 0
}

// Stdout returns a string containing the stdout output of the diginfractl run.
func (t *TestOutput) Stdout() string {
	return t.stdout.String()
}

// Stderr returns a string containing the stderr output of the diginfractl run.
func (t *TestOutput) Stderr() string {
	return t.stderr.String()
}
