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

package integration

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	klaytnTypes "github.com/klaytn/klaytn/blockchain/types"
	"github.com/klaytn/klaytn/blockchain/types/accountkey"
	"github.com/klaytn/klaytn/client"
	"github.com/klaytn/klaytn/common"
	"github.com/klaytn/klaytn/crypto"
	"github.com/klaytn/klaytn/params"
	"github.com/klaytn/rosetta-klaytn/configuration"
	"github.com/klaytn/rosetta-klaytn/klaytn"
	"github.com/klaytn/rosetta-klaytn/services"
	"github.com/klaytn/rosetta-sdk-go-klaytn/types"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

var (
	networkIdf *types.NetworkIdentifier
	cfg        *configuration.Configuration
	c          *klaytn.Client
	err        error

	networkAPIService *services.NetworkAPIService
	accountAPIService *services.AccountAPIService
	// blockAPIService        *services.BlockAPIService
	// constructionAPIService *services.ConstructionAPIService
	// mempoolAPIService      server.MempoolAPIServicer
	// callAPIService         *services.CallAPIService

	testAccount *TestAccount
	receiver    *TestAccount

	klaytnClient *client.Client
)

type TestAccount struct {
	Addr   common.Address
	Key    []*ecdsa.PrivateKey
	Nonce  uint64
	AccKey accountkey.AccountKey
}

func initTestValues(t *testing.T) {
	setTestEnv()
	genTestConfig(t)
	genTestClient(t)
	getAccountFromCliConfig(t)

	networkAPIService = services.NewNetworkAPIService(cfg, c)
	accountAPIService = services.NewAccountAPIService(cfg, c)
	// blockAPIService = services.NewBlockAPIService(cfg, c)
	// blockAPIService = services.NewBlockAPIService(cfg, c)
	// constructionAPIService = services.NewConstructionAPIService(cfg, c)
	// mempoolAPIService = services.NewMempoolAPIService(cfg, c)
	// callAPIService = services.NewCallAPIService(cfg, c)
}

func setTestEnv() {
	url := os.Getenv(configuration.KENEnv)
	if len(url) == 0 {
		os.Setenv(configuration.KENEnv, configuration.DefaultKENURL)
	}
	mode := os.Getenv(configuration.ModeEnv)
	if mode == "" {
		os.Setenv(configuration.ModeEnv, string(configuration.Online))
	}
	net := os.Getenv(configuration.NetworkEnv)
	if net == "" {
		os.Setenv(configuration.NetworkEnv, configuration.Local)
	}
	port := os.Getenv(configuration.PortEnv)
	if port == "" {
		os.Setenv(configuration.PortEnv, "10100")
	}
}

func genTestConfig(t *testing.T) {
	cfg, err = configuration.LoadConfiguration()
	assert.Nil(t, err)
}

func genTestClient(t *testing.T) {
	c, err = klaytn.NewClient(cfg.KlaytnNodeURL, cfg.Params, cfg.SkipAdmin)
	assert.Nil(t, err)

	klaytnClient, err = client.Dial(cfg.KlaytnNodeURL)
	assert.Nil(t, err)
}

func getAccountFromCliConfig(t *testing.T) {
	path, err := os.Getwd()
	assert.Nil(t, err)

	// mainnet, testnet or local
	networkName := strings.ToLower(os.Getenv(configuration.NetworkEnv))
	if !strings.ContainsAny(networkName, "net") {
		// Convert local to localnet for path
		networkName += "net"
	}
	path = filepath.Join(path, "../rosetta-cli-conf/"+networkName+"/config.json")

	cliConfFile, err := ioutil.ReadFile(path)
	assert.Nil(t, err)
	var cliConf map[string]interface{}
	err = json.Unmarshal(cliConfFile, &cliConf)
	assert.Nil(t, err)
	fmt.Println(cliConf)

	constructionObject, ok := cliConf["construction"].(map[string]interface{})
	assert.True(t, ok)
	accounts, ok := constructionObject["prefunded_accounts"].([]interface{})
	assert.True(t, ok)
	fmt.Println(accounts)

	if len(accounts) == 0 {
		msg := fmt.Sprintf("prefunded_accounts does not exist in %v.", path)
		assert.Fail(t, msg)
	}
	acctObject, ok := accounts[0].(map[string]interface{})
	assert.True(t, ok)
	fmt.Println(testAccount)
	privateKey, ok := acctObject["privkey"].(string)
	assert.True(t, ok)
	acctIdf, ok := acctObject["account_identifier"].(map[string]interface{})
	assert.True(t, ok)
	address, ok := acctIdf["address"].(string)
	assert.True(t, ok)

	testAccount = genTestAccount(t, privateKey, common.HexToAddress(address))
	receiver = getRandomTestAccount(t)
}

func genTestAccount(t *testing.T, privKey string, address common.Address) *TestAccount {
	key, err := crypto.HexToECDSA(privKey)
	assert.Nil(t, err)

	return &TestAccount{
		Addr:   address,
		Key:    []*ecdsa.PrivateKey{key},
		Nonce:  uint64(0),
		AccKey: accountkey.NewAccountKeyLegacy(),
	}
}