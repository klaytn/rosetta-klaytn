// Copyright 2022 Klaytn
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
	"github.com/klaytn/rosetta-sdk-go-klaytn/types"
	"github.com/stretchr/testify/assert"
	"testing"
)

// Test /account/balance
func TestAccountBalance(t *testing.T) {
	initTestValues(t)
	genTestData(t)
	defer c.Close()

	ctx := context.Background()

	acctIdf := types.AccountIdentifier{Address: testAccount.Addr.String()}
	request := &types.AccountBalanceRequest{
		NetworkIdentifier: networkIdf,
		AccountIdentifier: &acctIdf,
		BlockIdentifier:   &types.PartialBlockIdentifier{Index: testBlockNumber},
		Currencies: []*types.Currency{
			&types.Currency{Symbol: "KLAY", Decimals: 18},
		},
	}
	ret, err := accountAPIService.AccountBalance(ctx, request)
	assert.Nil(t, err)
	assert.NotNil(t, ret.Balances)
	assert.NotNil(t, ret.BlockIdentifier)
	assert.Equal(t, ret.BlockIdentifier.Index, *testBlockNumber)
	assert.Equal(t, ret.BlockIdentifier.Hash, testBlockHash)

	nonce, ok := ret.Metadata["nonce"].(int64)
	assert.True(t, ok)
	assert.True(t, nonce > 0)
}

// Test /account/balance with an account which doesn't have state in blockchain
func TestAccountBalanceNotExisted(t *testing.T) {
	initTestValues(t)
	genTestData(t)
	defer c.Close()

	ctx := context.Background()

	randomAcct := getRandomTestAccount(t)
	acctIdf := types.AccountIdentifier{Address: randomAcct.Addr.String()}
	request := &types.AccountBalanceRequest{
		NetworkIdentifier: networkIdf,
		AccountIdentifier: &acctIdf,
		BlockIdentifier:   &types.PartialBlockIdentifier{Index: testBlockNumber},
		Currencies: []*types.Currency{
			&types.Currency{Symbol: "KLAY", Decimals: 18},
		},
	}
	ret, err := accountAPIService.AccountBalance(ctx, request)
	assert.Nil(t, err)
	assert.NotNil(t, ret.Balances)
	assert.Equal(t, len(ret.Balances), 1)
	assert.Equal(t, ret.Balances[0].Value, "0")
	assert.Equal(t, ret.Balances[0].Currency.Symbol, "KLAY")
	assert.Equal(t, ret.Balances[0].Currency.Decimals, int32(18))
	assert.NotNil(t, ret.BlockIdentifier)
	assert.Equal(t, ret.BlockIdentifier.Index, *testBlockNumber)
	assert.Equal(t, ret.BlockIdentifier.Hash, testBlockHash)

	nonce, ok := ret.Metadata["nonce"].(int64)
	assert.True(t, ok)
	assert.Equal(t, nonce, int64(0))
}
