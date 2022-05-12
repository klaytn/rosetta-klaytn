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
	"github.com/klaytn/rosetta-klaytn/klaytn"
	"github.com/klaytn/rosetta-sdk-go-klaytn/types"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

// Test /block
func TestBlock(t *testing.T) {
	initTestValues(t)
	genTestData(t)
	defer c.Close()

	ctx := context.Background()

	request := &types.BlockRequest{
		NetworkIdentifier: networkIdf,
		BlockIdentifier:   &types.PartialBlockIdentifier{Index: testBlockNumber},
	}
	ret, err := blockAPIService.Block(ctx, request)
	assert.Nil(t, err)
	assert.NotNil(t, ret.Block)
	assert.Equal(t, ret.Block.BlockIdentifier.Hash, testBlockHash)
	assert.Equal(t, ret.Block.BlockIdentifier.Index, *testBlockNumber)
	assert.Equal(t, len(ret.Block.Transactions), 2)
	assert.Equal(t, ret.Block.Transactions[0].TransactionIdentifier.Hash, testBlockHash)
	assert.Equal(t, ret.Block.Transactions[0].Operations[0].Type, klaytn.BlockRewardOpType)
	assert.Equal(t, ret.Block.Transactions[1].TransactionIdentifier.Hash, testTxHash)
	assert.Equal(t, len(ret.Block.Transactions[1].Operations), 4)
	assert.Equal(t, ret.Block.Transactions[1].Operations[0].Type, klaytn.FeeOpType)
	assert.Equal(t, ret.Block.Transactions[1].Operations[1].Type, klaytn.FeeOpType)
	assert.Equal(t, ret.Block.Transactions[1].Operations[0].OperationIdentifier.Index, int64(0))
	assert.Equal(t, ret.Block.Transactions[1].Operations[1].OperationIdentifier.Index, int64(1))
	assert.Equal(t, len(ret.Block.Transactions[1].Operations[1].RelatedOperations), 1)
	assert.Equal(t, ret.Block.Transactions[1].Operations[1].RelatedOperations[0].Index, int64(0))
	assert.Equal(t, ret.Block.Transactions[1].Operations[2].Type, klaytn.CallOpType)
	assert.Equal(t, ret.Block.Transactions[1].Operations[3].Type, klaytn.CallOpType)
	assert.Equal(t, ret.Block.Transactions[1].Operations[2].OperationIdentifier.Index, int64(2))
	assert.Equal(t, ret.Block.Transactions[1].Operations[3].OperationIdentifier.Index, int64(3))
	assert.Equal(t, len(ret.Block.Transactions[1].Operations[3].RelatedOperations), 1)
	assert.Equal(t, ret.Block.Transactions[1].Operations[3].RelatedOperations[0].Index, int64(2))

	// Default latest block
	request.BlockIdentifier = nil
	ret, err = blockAPIService.Block(ctx, request)
	assert.Nil(t, err)
	assert.NotNil(t, ret.Block)
}

// Test /block with invalid data
func TestBlockNotExisted(t *testing.T) {
	initTestValues(t)
	genTestData(t)
	defer c.Close()

	ctx := context.Background()

	invalidHash := "0xe9a11d9ef95fb437f75d07ce768d43e74f158dd54b106e7d3746ce29d545b550"
	request := &types.BlockRequest{
		NetworkIdentifier: networkIdf,
		BlockIdentifier:   &types.PartialBlockIdentifier{Hash: &invalidHash},
	}
	ret, err := blockAPIService.Block(ctx, request)
	assert.NotNil(t, err)
	assert.Nil(t, ret)
	expectedMsg := "could not get block"
	assert.True(t, strings.Contains(err.Details["context"].(string), expectedMsg))
}

// Test /block/transaction
func TestBlockTransaction(t *testing.T) {
	initTestValues(t)
	genTestData(t)
	defer c.Close()

	ctx := context.Background()

	request := &types.BlockTransactionRequest{
		NetworkIdentifier:     networkIdf,
		BlockIdentifier:       &types.BlockIdentifier{Hash: testBlockHash, Index: *testBlockNumber},
		TransactionIdentifier: &types.TransactionIdentifier{Hash: testTxHash},
	}
	ret, err := blockAPIService.BlockTransaction(ctx, request)
	assert.Nil(t, err)
	assert.Equal(t, ret.Transaction.TransactionIdentifier.Hash, testTxHash)
	assert.Equal(t, len(ret.Transaction.Operations), 4)
	assert.Equal(t, ret.Transaction.Operations[0].Type, klaytn.FeeOpType)
	assert.Equal(t, ret.Transaction.Operations[1].Type, klaytn.FeeOpType)
	assert.Equal(t, ret.Transaction.Operations[0].OperationIdentifier.Index, int64(0))
	assert.Equal(t, ret.Transaction.Operations[1].OperationIdentifier.Index, int64(1))
	assert.Equal(t, len(ret.Transaction.Operations[1].RelatedOperations), 1)
	assert.Equal(t, ret.Transaction.Operations[1].RelatedOperations[0].Index, int64(0))
	assert.Equal(t, ret.Transaction.Operations[2].Type, klaytn.CallOpType)
	assert.Equal(t, ret.Transaction.Operations[3].Type, klaytn.CallOpType)
	assert.Equal(t, ret.Transaction.Operations[2].OperationIdentifier.Index, int64(2))
	assert.Equal(t, ret.Transaction.Operations[3].OperationIdentifier.Index, int64(3))
	assert.Equal(t, len(ret.Transaction.Operations[3].RelatedOperations), 1)
	assert.Equal(t, ret.Transaction.Operations[3].RelatedOperations[0].Index, int64(2))
}

// Test /block/transaction with invalid data
func TestBlockTransactionNotExisted(t *testing.T) {
	initTestValues(t)
	genTestData(t)
	defer c.Close()

	ctx := context.Background()

	invalidHash := "0xe9a11d9ef95fb437f75d07ce768d43e74f158dd54b106e7d3746ce29d545b550"
	request := &types.BlockTransactionRequest{
		NetworkIdentifier:     networkIdf,
		BlockIdentifier:       &types.BlockIdentifier{Hash: testBlockHash, Index: *testBlockNumber},
		TransactionIdentifier: &types.TransactionIdentifier{Hash: invalidHash},
	}
	ret, err := blockAPIService.BlockTransaction(ctx, request)
	assert.NotNil(t, err)
	assert.Nil(t, ret)
	expectedMsg := "not found"
	assert.True(t, strings.Contains(err.Details["context"].(string), expectedMsg))

	request = &types.BlockTransactionRequest{}
	request.BlockIdentifier = &types.BlockIdentifier{}
	request.BlockIdentifier.Hash = invalidHash
	request.TransactionIdentifier = &types.TransactionIdentifier{Hash: testTxHash}
	ret, err = blockAPIService.BlockTransaction(ctx, request)
	assert.NotNil(t, err)
	assert.Nil(t, ret)
	expectedMsg = "could not get block header for"
	assert.True(t, strings.Contains(err.Details["context"].(string), expectedMsg))

	request = &types.BlockTransactionRequest{}
	request.TransactionIdentifier = &types.TransactionIdentifier{Hash: ""}
	ret, err = blockAPIService.BlockTransaction(ctx, request)
	assert.NotNil(t, err)
	assert.Nil(t, ret)
	expectedMsg = "transaction hash is required"
	assert.True(t, strings.Contains(err.Details["context"].(string), expectedMsg))

	request.TransactionIdentifier = &types.TransactionIdentifier{Hash: testTxHash}
	request.BlockIdentifier = &types.BlockIdentifier{}
	request.BlockIdentifier.Index = int64(0)
	ret, err = blockAPIService.BlockTransaction(ctx, request)
	assert.NotNil(t, err)
	assert.Nil(t, ret)
	expectedMsg = "tx does not belong to the block passed as a parameter"
	assert.True(t, strings.Contains(err.Details["context"].(string), expectedMsg))
}
