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

package plugins

import "github.com/diginfra/testing/pkg/run"

var K8SAuditPlugin = run.NewLocalFileAccessor(
	"libk8saudit.so",
	"/usr/share/diginfra/plugins/libk8saudit.so")

var CloudtrailPlugin = run.NewLocalFileAccessor(
	"libcloudtrail.so",
	"/usr/share/diginfra/plugins/libcloudtrail.so")

var JSONPlugin = run.NewLocalFileAccessor(
	"libjson.so",
	"/usr/share/diginfra/plugins/libjson.so")

var DummyPlugin = run.NewLocalFileAccessor(
	"libdummy.so",
	"/usr/share/diginfra/plugins/libdummy.so")
