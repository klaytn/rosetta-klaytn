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
	"strings"
	"testing"

	"github.com/klaytn/rosetta-klaytn/klaytn"
	"github.com/klaytn/rosetta-sdk-go-klaytn/types"
	"github.com/stretchr/testify/assert"
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
	assert.True(t, len(ret.Block.Transactions) >= 2)
	assert.Equal(t, ret.Block.Transactions[0].TransactionIdentifier.Hash, testBlockHash)
	assert.Equal(t, ret.Block.Transactions[0].Operations[0].Type, klaytn.BlockRewardOpType)
	found := false
	for i := 1; i < len(ret.Block.Transactions); i++ {
		if ret.Block.Transactions[i].TransactionIdentifier.Hash != testTxHash {
			continue
		}
		assert.Equal(t, ret.Block.Transactions[i].TransactionIdentifier.Hash, testTxHash)
		assert.Equal(t, 5, len(ret.Block.Transactions[i].Operations))
		assert.Equal(t, klaytn.FeeOpType, ret.Block.Transactions[i].Operations[0].Type)
		assert.Equal(t, klaytn.FeeOpType, ret.Block.Transactions[i].Operations[1].Type)
		assert.Equal(t, klaytn.FeeOpType, ret.Block.Transactions[i].Operations[2].Type)
		assert.Equal(t, int64(0), ret.Block.Transactions[i].Operations[0].OperationIdentifier.Index)
		assert.Equal(t, int64(1), ret.Block.Transactions[i].Operations[1].OperationIdentifier.Index)
		assert.Equal(t, int64(2), ret.Block.Transactions[i].Operations[2].OperationIdentifier.Index)
		assert.Equal(t, 2, len(ret.Block.Transactions[i].Operations[2].RelatedOperations))
		assert.Equal(t, int64(0), ret.Block.Transactions[i].Operations[2].RelatedOperations[0].Index)
		assert.Equal(t, int64(1), ret.Block.Transactions[i].Operations[2].RelatedOperations[1].Index)
		assert.Equal(t, klaytn.CallOpType, ret.Block.Transactions[i].Operations[3].Type)
		assert.Equal(t, klaytn.CallOpType, ret.Block.Transactions[i].Operations[4].Type)
		assert.Equal(t, int64(3), ret.Block.Transactions[i].Operations[3].OperationIdentifier.Index)
		assert.Equal(t, int64(4), ret.Block.Transactions[i].Operations[4].OperationIdentifier.Index)
		assert.Equal(t, 1, len(ret.Block.Transactions[i].Operations[4].RelatedOperations))
		assert.Equal(t, int64(3), ret.Block.Transactions[i].Operations[4].RelatedOperations[0].Index)
		found = true
	}
	assert.True(t, found)

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
	assert.Equal(t, testTxHash, ret.Transaction.TransactionIdentifier.Hash)
	assert.Equal(t, 5, len(ret.Transaction.Operations))
	assert.Equal(t, klaytn.FeeOpType, ret.Transaction.Operations[0].Type)
	assert.Equal(t, klaytn.FeeOpType, ret.Transaction.Operations[1].Type)
	assert.Equal(t, klaytn.FeeOpType, ret.Transaction.Operations[2].Type)
	assert.Equal(t, int64(0), ret.Transaction.Operations[0].OperationIdentifier.Index)
	assert.Equal(t, int64(1), ret.Transaction.Operations[1].OperationIdentifier.Index)
	assert.Equal(t, int64(2), ret.Transaction.Operations[2].OperationIdentifier.Index)
	assert.Equal(t, 2, len(ret.Transaction.Operations[2].RelatedOperations))
	assert.Equal(t, int64(0), ret.Transaction.Operations[2].RelatedOperations[0].Index)
	assert.Equal(t, int64(1), ret.Transaction.Operations[2].RelatedOperations[1].Index)
	assert.Equal(t, klaytn.CallOpType, ret.Transaction.Operations[3].Type)
	assert.Equal(t, klaytn.CallOpType, ret.Transaction.Operations[4].Type)
	assert.Equal(t, int64(3), ret.Transaction.Operations[3].OperationIdentifier.Index)
	assert.Equal(t, int64(4), ret.Transaction.Operations[4].OperationIdentifier.Index)
	assert.Equal(t, 1, len(ret.Transaction.Operations[4].RelatedOperations))
	assert.Equal(t, int64(3), ret.Transaction.Operations[4].RelatedOperations[0].Index)
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
