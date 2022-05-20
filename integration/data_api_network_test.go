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
	"testing"

	"github.com/klaytn/rosetta-klaytn/configuration"
	"github.com/klaytn/rosetta-klaytn/klaytn"
	"github.com/klaytn/rosetta-sdk-go-klaytn/types"
	"github.com/stretchr/testify/assert"
)

// Test /network/list
func TestNetworkList(t *testing.T) {
	initTestValues(t)
	defer c.Close()

	ctx := context.Background()

	request := &types.MetadataRequest{}
	res, err := networkAPIService.NetworkList(ctx, request)
	assert.Nil(t, err)

	assert.Equal(t, len(res.NetworkIdentifiers), 1)
	assert.Equal(t, res.NetworkIdentifiers[0].Blockchain, klaytn.Blockchain)
	assert.Equal(t, res.NetworkIdentifiers[0].Network, klaytn.LocalNetwork)
}

// Test /network/options
func TestNetworkOptions(t *testing.T) {
	initTestValues(t)
	defer c.Close()

	ctx := context.Background()

	request := &types.NetworkRequest{}
	request.NetworkIdentifier = networkIdf
	res, err := networkAPIService.NetworkOptions(ctx, request)
	assert.Nil(t, err)

	assert.Equal(t, res.Version.RosettaVersion, types.RosettaAPIVersion)
	assert.Equal(t, res.Version.NodeVersion, klaytn.NodeVersion)
	assert.Equal(t, res.Version.MiddlewareVersion, types.String(configuration.MiddlewareVersion))
	assert.NotNil(t, res.Allow.Errors)
	assert.NotNil(t, res.Allow.OperationTypes)
	assert.NotNil(t, res.Allow.OperationStatuses)
	assert.NotNil(t, res.Allow.HistoricalBalanceLookup)
	assert.NotNil(t, res.Allow.CallMethods)
}

// Test /network/status
func TestNetworkStatus(t *testing.T) {
	initTestValues(t)
	defer c.Close()

	ctx := context.Background()

	request := &types.NetworkRequest{}
	request.NetworkIdentifier = networkIdf
	res, err := networkAPIService.NetworkStatus(ctx, request)
	assert.Nil(t, err)

	assert.True(t, res.CurrentBlockIdentifier.Index > klaytn.GenesisBlockIndex)
	assert.NotNil(t, res.CurrentBlockIdentifier.Hash)
	assert.NotNil(t, res.CurrentBlockTimestamp)
	assert.Equal(t, res.GenesisBlockIdentifier.Index, klaytn.GenesisBlockIndex)
	assert.Equal(t, res.GenesisBlockIdentifier.Hash, klaytn.LocalGenesisBlockIdentifier.Hash)
	assert.NotNil(t, res.Peers)
}
