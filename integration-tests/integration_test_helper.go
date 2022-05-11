// Copyright 2022 Klaytn Authors
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

package integration_tests

import (
	"github.com/klaytn/rosetta-klaytn/configuration"
	"github.com/klaytn/rosetta-klaytn/klaytn"
	"github.com/klaytn/rosetta-klaytn/services"
	"github.com/klaytn/rosetta-sdk-go-klaytn/asserter"
	"github.com/klaytn/rosetta-sdk-go-klaytn/server"
	"github.com/klaytn/rosetta-sdk-go-klaytn/types"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

var (
	// This will use default Klaytn Node URL which is "http://localhost:8551"
	// nodeURL = "http://localhost:8551"
	networkIdf *types.NetworkIdentifier
	cfg        *configuration.Configuration
	ast        *asserter.Asserter
	client     *klaytn.Client
	err        error

	networkAPIService      *services.NetworkAPIService
	accountAPIService      *services.AccountAPIService
	blockAPIService        *services.BlockAPIService
	constructionAPIService *services.ConstructionAPIService
	mempoolAPIService      server.MempoolAPIServicer
	callAPIService         *services.CallAPIService
)

func initTestValues(t *testing.T) {
	setTestEnv()
	genTestConfig(t)
	genTestAsserter(t)
	genTestClient(t)

	networkAPIService = services.NewNetworkAPIService(cfg, client)
	accountAPIService = services.NewAccountAPIService(cfg, client)
	blockAPIService = services.NewBlockAPIService(cfg, client)
	blockAPIService = services.NewBlockAPIService(cfg, client)
	constructionAPIService = services.NewConstructionAPIService(cfg, client)
	mempoolAPIService = services.NewMempoolAPIService(cfg, client)
	callAPIService = services.NewCallAPIService(cfg, client)
}

func setTestEnv() {
	os.Setenv(configuration.ModeEnv, string(configuration.Online))
	os.Setenv(configuration.NetworkEnv, configuration.Local)
	os.Setenv(configuration.PortEnv, "10100")
}

func genTestConfig(t *testing.T) {
	cfg, err = configuration.LoadConfiguration()
	assert.Nil(t, err)
}

func genTestAsserter(t *testing.T) {
	// The asserter automatically rejects incorrectly formatted
	// requests.
	ast, err = asserter.NewServer(
		klaytn.OperationTypes,
		klaytn.HistoricalBalanceSupported,
		[]*types.NetworkIdentifier{cfg.Network},
		klaytn.CallMethods,
		klaytn.IncludeMempoolCoins,
		"",
	)
	assert.Nil(t, err)
}

func genTestClient(t *testing.T) {
	client, err = klaytn.NewClient(cfg.KlaytnNodeURL, cfg.Params, cfg.SkipAdmin)
	assert.Nil(t, err)
}
