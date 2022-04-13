// Copyright 2020 Coinbase, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package klaytn

import (
	"github.com/klaytn/klaytn/node/cn"
)

// convert raw eth data from client to rosetta

var (
	tracerTimeout = "120s"
)

func loadTraceConfig() (*cn.TraceConfig, error) {
	// Use fastCallTracer instead of call_tracer.js
	fct := "fastCallTracer"
	return &cn.TraceConfig{
		Timeout: &tracerTimeout,
		Tracer:  &fct,
	}, nil
}
