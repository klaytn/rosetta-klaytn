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
//
// Modifications Copyright © 2022 Klaytn
// Modified and improved for the Klaytn development

package services

import (
	"context"
	"testing"

	"github.com/klaytn/rosetta-klaytn/configuration"
	mocks "github.com/klaytn/rosetta-klaytn/mocks/services"
	"github.com/klaytn/rosetta-sdk-go-klaytn/types"

	"github.com/stretchr/testify/assert"
)

func TestMempoolService_Offline(t *testing.T) {
	cfg := &configuration.Configuration{
		Mode: configuration.Offline,
	}
	mockClient := &mocks.Client{}
	servicer := NewMempoolAPIService(cfg, mockClient)
	ctx := context.Background()

	mem, err := servicer.Mempool(ctx, nil)
	assert.Nil(t, mem)
	assert.Equal(t, ErrUnavailableOffline.Code, err.Code)
	assert.Equal(t, ErrUnavailableOffline.Message, err.Message)

	memTransaction, err := servicer.MempoolTransaction(ctx, nil)
	assert.Nil(t, memTransaction)
	assert.Equal(t, ErrUnimplemented.Code, err.Code)
	assert.Equal(t, ErrUnimplemented.Message, err.Message)

	mockClient.AssertExpectations(t)
}

func TestMempoolService_Online(t *testing.T) {
	cfg := &configuration.Configuration{
		Mode: configuration.Online,
	}
	mockClient := &mocks.Client{}
	servicer := NewMempoolAPIService(cfg, mockClient)
	ctx := context.Background()

	mempool := &types.MempoolResponse{
		TransactionIdentifiers: []*types.TransactionIdentifier{
			{
				Hash: "0xb89dbf00e5c1a6ec89a4d42879969e8ea843a6814a783fb5c2bbf712ea1ef071",
			},
		},
	}

	t.Run("mempool", func(t *testing.T) {
		mockClient.
			On("GetMempool", ctx).
			Return(mempool, nil).
			Once()

		actualMempool, err := servicer.Mempool(ctx, &types.NetworkRequest{})

		assert.Nil(t, err)
		assert.Equal(t, mempool, actualMempool)
	})

	mockClient.AssertExpectations(t)
}
