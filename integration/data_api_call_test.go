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
	"github.com/klaytn/klaytn/common"
	"github.com/klaytn/rosetta-sdk-go-klaytn/types"
	"github.com/stretchr/testify/assert"
	"strconv"
	"strings"
	"testing"
)

// Test /call with klay_call
func TestCallKlayCall(t *testing.T) {
	initTestValues(t)
	defer c.Close()

	ctx := context.Background()

	req := &types.CallRequest{
		NetworkIdentifier: networkIdf,
		Method:            "klay_call",
		Parameters: map[string]interface{}{
			"to":   "0x684df7c7c35B6dF2ded9dcBa436DDa7F2096A773",
			"data": "0x06fdde03",
		},
	}
	res, err := callAPIService.Call(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
	assert.NotNil(t, res.Result)
	assert.Equal(t, res.Result["data"], "0x")
}

// Test /call with klay_call with invalid call parameter
func TestCallKlayCallWithInvalidParam(t *testing.T) {
	initTestValues(t)
	defer c.Close()

	ctx := context.Background()

	req := &types.CallRequest{
		NetworkIdentifier: networkIdf,
		Method:            "klay_call",
		Parameters: map[string]interface{}{
			"to": "0x684df7c7c35B6dF2ded9dcBa436DDa7F2096A773",
		},
	}
	res, err := callAPIService.Call(ctx, req)
	assert.Nil(t, res)
	assert.NotNil(t, err)
	expectedMsg := "Call parameters invalid"
	assert.True(t, strings.Contains(err.Message, expectedMsg))
}

// Test /call with klay_getBlockByNumber
func TestCallKlayGetBlokcByNumber(t *testing.T) {
	initTestValues(t)
	defer c.Close()
	genTestData(t)

	ctx := context.Background()

	req := &types.CallRequest{
		NetworkIdentifier: networkIdf,
		Method:            "klay_getBlockByNumber",
		Parameters: map[string]interface{}{
			"index":                    testBlockNumber,
			"show_transaction_details": true,
		},
	}
	res, err := callAPIService.Call(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
	expectedBlockNum := strconv.FormatInt(*testBlockNumber, 16)
	bn := strings.Replace(res.Result["number"].(string), "0x", "", 1)
	assert.Equal(t, bn, expectedBlockNum)
	txs := res.Result["transactions"].([]interface{})
	bnInTx := strings.Replace(txs[0].(map[string]interface{})["blockNumber"].(string), "0x", "", 1)
	assert.Equal(t, bnInTx, expectedBlockNum)

	req.Parameters["show_transaction_details"] = false
	res, err = callAPIService.Call(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
	txs = res.Result["transactions"].([]interface{})
	found := false
	for _, tx := range txs {
		txHash := tx.(string)
		if txHash == testTxHash {
			found = true
			break
		}
	}
	assert.True(t, found)
}

// Test /call with klay_getBlockByNumber with future block number
func TestCallKlayGetBlokcByNumberWithFutureBlock(t *testing.T) {
	initTestValues(t)
	defer c.Close()
	genTestData(t)

	ctx := context.Background()

	// Search future block
	req := &types.CallRequest{
		NetworkIdentifier: networkIdf,
		Method:            "klay_getBlockByNumber",
		Parameters: map[string]interface{}{
			"index": *testBlockNumber + 10000000,
		},
	}
	res, err := callAPIService.Call(ctx, req)
	assert.NotNil(t, err)
	assert.Nil(t, res)
	expectedMsg := "klaytn client error"
	assert.True(t, strings.Contains(err.Message, expectedMsg))
	expectedMsg = "the block does not exist"
	assert.True(t, strings.Contains(err.Details["context"].(string), expectedMsg))
}

// Test /call with klay_getTransactionReceipt
func TestCallKlayGetTransactionReceipt(t *testing.T) {
	initTestValues(t)
	defer c.Close()
	genTestData(t)

	ctx := context.Background()

	req := &types.CallRequest{
		NetworkIdentifier: networkIdf,
		Method:            "klay_getTransactionReceipt",
		Parameters: map[string]interface{}{
			"tx_hash": testTxHash,
		},
	}
	res, err := callAPIService.Call(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
	expectedBlockNum := strconv.FormatInt(*testBlockNumber, 16)
	bn := strings.Replace(res.Result["blockNumber"].(string), "0x", "", 1)
	assert.Equal(t, bn, expectedBlockNum)
	assert.Equal(t, res.Result["transactionHash"].(string), testTxHash)
	from := res.Result["from"].(string)
	assert.Equal(t, strings.ToLower(from), strings.ToLower(testAccount.Addr.Hex()))
}

// Test /call with klay_getTransactionReceipt with invalid data
func TestCallKlayGetTransactionReceiptWithInvalidData(t *testing.T) {
	initTestValues(t)
	defer c.Close()
	genTestData(t)

	ctx := context.Background()

	// Search future block
	req := &types.CallRequest{
		NetworkIdentifier: networkIdf,
		Method:            "klay_getTransactionReceipt",
		Parameters: map[string]interface{}{
			"tx_hash": "This is not Tx Hash",
		},
	}
	res, err := callAPIService.Call(ctx, req)
	assert.NotNil(t, err)
	assert.Nil(t, res)
	expectedMsg := "klaytn client error"
	assert.True(t, strings.Contains(err.Message, expectedMsg))
	expectedMsg = "cannot unmarshal hex string without 0x prefix"
	assert.True(t, strings.Contains(err.Details["context"].(string), expectedMsg))

	req.Parameters["tx_hash"] = common.HexToHash("0x6aff81a284d362d198060c6cd3e4b2162595f94de41c287d85b59f42851125fe").Hex()
	res, err = callAPIService.Call(ctx, req)
	assert.NotNil(t, err)
	assert.Nil(t, res)
	expectedMsg = "klaytn client error"
	assert.True(t, strings.Contains(err.Message, expectedMsg))
	expectedMsg = "not found"
	assert.True(t, strings.Contains(err.Details["context"].(string), expectedMsg))
}

// Test /call with klay_estimateGas
func TestCallKlayEstimateGas(t *testing.T) {
	initTestValues(t)
	defer c.Close()

	ctx := context.Background()

	req := &types.CallRequest{
		NetworkIdentifier: networkIdf,
		Method:            "klay_estimateGas",
		Parameters: map[string]interface{}{
			"from": testAccount.Addr.Hex(),
			"to":   "0x684df7c7c35B6dF2ded9dcBa436DDa7F2096A773",
			"data": "0x06fdde03",
		},
	}
	res, err := callAPIService.Call(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, res)
	assert.NotNil(t, res.Result)
	assert.NotNil(t, res.Result["data"])
}

// Test /call with klay_estimateGas with invalid call parameter
func TestCallKlayEstimateGasWithInvalidParam(t *testing.T) {
	initTestValues(t)
	defer c.Close()

	ctx := context.Background()

	req := &types.CallRequest{
		NetworkIdentifier: networkIdf,
		Method:            "klay_estimateGas",
		Parameters: map[string]interface{}{
			"to": "0x684df7c7c35B6dF2ded9dcBa436DDa7F2096A773",
		},
	}
	res, err := callAPIService.Call(ctx, req)
	assert.Nil(t, res)
	assert.NotNil(t, err)
	expectedMsg := "Call parameters invalid"
	assert.True(t, strings.Contains(err.Message, expectedMsg))
}
