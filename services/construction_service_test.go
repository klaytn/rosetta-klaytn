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

package services

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/klaytn/klaytn/common"
	"github.com/klaytn/klaytn/params"
	"github.com/klaytn/rosetta-klaytn/klaytn"

	"github.com/klaytn/rosetta-klaytn/configuration"
	mocks "github.com/klaytn/rosetta-klaytn/mocks/services"

	"github.com/klaytn/rosetta-sdk-go-klaytn/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func forceHexDecode(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("could not decode hex %s", s)
	}

	return b
}

func forceMarshalMap(t *testing.T, i interface{}) map[string]interface{} {
	m, err := marshalJSONMap(i)
	if err != nil {
		t.Fatalf("could not marshal map %s", types.PrintStruct(i))
	}

	return m
}

func TestConstructionService(t *testing.T) {
	networkIdentifier = &types.NetworkIdentifier{
		Network:    klaytn.TestnetNetwork,
		Blockchain: klaytn.Blockchain,
	}

	cfg := &configuration.Configuration{
		Mode:    configuration.Online,
		Network: networkIdentifier,
		Params:  params.BaobabChainConfig,
	}
	cfg.Params.ChainID = big.NewInt(3)

	mockClient := &mocks.Client{}
	servicer := NewConstructionAPIService(cfg, mockClient)
	ctx := context.Background()

	// Test Derive
	mockClient.On(
		"GetAccount",
		ctx,
		"0xe3a5B4d7f79d64088C8d4ef153A7DDe2B2d47309",
		"latest",
	).Return(map[string]interface{}{
		"accType": float64(1),
		"account": map[string]interface{}{
			"balance":       "0x1",
			"humanReadable": false,
			"key":           map[string]interface{}{"keyType": float64(1), "key": map[string]interface{}{}},
			"nonce":         float64(1),
		},
	}, nil).Once()

	publicKey := &types.PublicKey{
		Bytes: forceHexDecode(
			t,
			"03d3d3358e7f69cbe45bde38d7d6f24660c7eeeaee5c5590cfab985c8839b21fd5",
		),
		CurveType: types.Secp256k1,
	}
	accountIdf, err := servicer.ConstructionDerive(ctx, &types.ConstructionDeriveRequest{
		NetworkIdentifier: networkIdentifier,
		PublicKey:         publicKey,
	})
	assert.Nil(t, err)
	assert.NotNil(t, accountIdf)
	assert.Equal(t, accountIdf.AccountIdentifier.Address, "0xe3a5B4d7f79d64088C8d4ef153A7DDe2B2d47309")
	assert.NotNil(t, accountIdf.AccountIdentifier.Metadata)

	// Test Preprocess
	intent := `[{"operation_identifier":{"index":0},"type":"CALL","account":{"address":"0xe3a5B4d7f79d64088C8d4ef153A7DDe2B2d47309"},"amount":{"value":"-42894881044106498","currency":{"symbol":"KLAY","decimals":18}}},{"operation_identifier":{"index":1},"type":"CALL","account":{"address":"0x57B414a0332B5CaB885a451c2a28a07d1e9b8a8d"},"amount":{"value":"42894881044106498","currency":{"symbol":"KLAY","decimals":18}}}]` // nolint
	var ops []*types.Operation
	assert.NoError(t, json.Unmarshal([]byte(intent), &ops))
	preprocessResponse, err := servicer.ConstructionPreprocess(
		ctx,
		&types.ConstructionPreprocessRequest{
			NetworkIdentifier: networkIdentifier,
			Operations:        ops,
		},
	)
	assert.Nil(t, err)
	optionsRaw := `{"from":"0xe3a5B4d7f79d64088C8d4ef153A7DDe2B2d47309"}`
	var options options
	assert.NoError(t, json.Unmarshal([]byte(optionsRaw), &options))
	assert.Equal(t, &types.ConstructionPreprocessResponse{
		Options: forceMarshalMap(t, options),
	}, preprocessResponse)

	// Test Metadata
	metadata := &metadata{
		GasPrice: big.NewInt(1000000000),
		Nonce:    0,
	}

	mockClient.On(
		"SuggestGasPrice",
		ctx,
	).Return(
		big.NewInt(1000000000),
		nil,
	).Once()
	mockClient.On(
		"PendingNonceAt",
		ctx,
		common.HexToAddress("0xe3a5B4d7f79d64088C8d4ef153A7DDe2B2d47309"),
	).Return(
		uint64(0),
		nil,
	).Once()
	metadataResponse, err := servicer.ConstructionMetadata(ctx, &types.ConstructionMetadataRequest{
		NetworkIdentifier: networkIdentifier,
		Options:           forceMarshalMap(t, options),
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.ConstructionMetadataResponse{
		Metadata: forceMarshalMap(t, metadata),
		SuggestedFee: []*types.Amount{
			{
				Value:    "21000000000000",
				Currency: klaytn.Currency,
			},
		},
	}, metadataResponse)

	// Test Payloads
	unsignedRaw := `{"from":"0xe3a5B4d7f79d64088C8d4ef153A7DDe2B2d47309","to":"0x57B414a0332B5CaB885a451c2a28a07d1e9b8a8d","value":"0x9864aac3510d02","data":"0x","nonce":"0x0","gas_price":"0x3b9aca00","gas":"0x5208","chain_id":"0x3"}` // nolint
	payloadsResponse, err := servicer.ConstructionPayloads(ctx, &types.ConstructionPayloadsRequest{
		NetworkIdentifier: networkIdentifier,
		Operations:        ops,
		Metadata:          forceMarshalMap(t, metadata),
	})
	assert.Nil(t, err)
	payloadsRaw := `[{"address":"0xe3a5B4d7f79d64088C8d4ef153A7DDe2B2d47309","hex_bytes":"b682f3e39c512ff57471f482eab264551487320cbd3b34485f4779a89e5612d1","account_identifier":{"address":"0xe3a5B4d7f79d64088C8d4ef153A7DDe2B2d47309"},"signature_type":"ecdsa_recovery"}]` // nolint
	var payloads []*types.SigningPayload
	assert.NoError(t, json.Unmarshal([]byte(payloadsRaw), &payloads))
	assert.Equal(t, &types.ConstructionPayloadsResponse{
		UnsignedTransaction: unsignedRaw,
		Payloads:            payloads,
	}, payloadsResponse)

	// Test Parse Unsigned
	parseOpsRaw := `[{"operation_identifier":{"index":0},"type":"CALL","account":{"address":"0xe3a5B4d7f79d64088C8d4ef153A7DDe2B2d47309"},"amount":{"value":"-42894881044106498","currency":{"symbol":"KLAY","decimals":18}}},{"operation_identifier":{"index":1},"related_operations":[{"index":0}],"type":"CALL","account":{"address":"0x57B414a0332B5CaB885a451c2a28a07d1e9b8a8d"},"amount":{"value":"42894881044106498","currency":{"symbol":"KLAY","decimals":18}}}]` // nolint
	var parseOps []*types.Operation
	assert.NoError(t, json.Unmarshal([]byte(parseOpsRaw), &parseOps))
	parseUnsignedResponse, err := servicer.ConstructionParse(ctx, &types.ConstructionParseRequest{
		NetworkIdentifier: networkIdentifier,
		Signed:            false,
		Transaction:       unsignedRaw,
	})
	assert.Nil(t, err)
	parseMetadata := &parseMetadata{
		Nonce:    metadata.Nonce,
		GasPrice: metadata.GasPrice,
		ChainID:  big.NewInt(3),
	}
	assert.Equal(t, &types.ConstructionParseResponse{
		Operations:               parseOps,
		AccountIdentifierSigners: []*types.AccountIdentifier{},
		Metadata:                 forceMarshalMap(t, parseMetadata),
	}, parseUnsignedResponse)

	// Test Combine
	signaturesRaw := `[{"hex_bytes":"8c712c64bc65c4a88707fa93ecd090144dffb1bf133805a10a51d354c2f9f2b25a63cea6989f4c58372c41f31164036a6b25dce1d5c05e1d31c16c0590c176e801","signing_payload":{"address":"0xe3a5B4d7f79d64088C8d4ef153A7DDe2B2d47309","hex_bytes":"b682f3e39c512ff57471f482eab264551487320cbd3b34485f4779a89e5612d1","account_identifier":{"address":"0xe3a5B4d7f79d64088C8d4ef153A7DDe2B2d47309"},"signature_type":"ecdsa_recovery"},"public_key":{"hex_bytes":"03d3d3358e7f69cbe45bde38d7d6f24660c7eeeaee5c5590cfab985c8839b21fd5","curve_type":"secp256k1"},"signature_type":"ecdsa_recovery"}]` // nolint
	var signatures []*types.Signature
	assert.NoError(t, json.Unmarshal([]byte(signaturesRaw), &signatures))
	// TODO-Klaytn: The type, maxFeePerGas and maxPriorityFeePerGas are removed in the signedRaw
	// variable.
	// If Klaytn added type, maxFeePerGas and maxPriorityFeePerGas to types.Transaction struct,
	// we need to add those fields to the signedRaw also.
	signedRaw := `{"nonce":"0x0","gasPrice":"0x3b9aca00","gas":"0x5208","to":"0x57b414a0332b5cab885a451c2a28a07d1e9b8a8d","value":"0x9864aac3510d02","input":"0x","signatures":[{"V":"0x2a","R":"0x8c712c64bc65c4a88707fa93ecd090144dffb1bf133805a10a51d354c2f9f2b2","S":"0x5a63cea6989f4c58372c41f31164036a6b25dce1d5c05e1d31c16c0590c176e8"}],"hash":"0x424969b1a98757bcd748c60bad2a7de9745cfb26bfefb4550e780a098feada42"}` // nolint
	combineResponse, err := servicer.ConstructionCombine(ctx, &types.ConstructionCombineRequest{
		NetworkIdentifier:   networkIdentifier,
		UnsignedTransaction: unsignedRaw,
		Signatures:          signatures,
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.ConstructionCombineResponse{
		SignedTransaction: signedRaw,
	}, combineResponse)

	// Test Parse Signed
	parseSignedResponse, err := servicer.ConstructionParse(ctx, &types.ConstructionParseRequest{
		NetworkIdentifier: networkIdentifier,
		Signed:            true,
		Transaction:       signedRaw,
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.ConstructionParseResponse{
		Operations: parseOps,
		AccountIdentifierSigners: []*types.AccountIdentifier{
			{Address: "0xe3a5B4d7f79d64088C8d4ef153A7DDe2B2d47309"},
		},
		Metadata: forceMarshalMap(t, parseMetadata),
	}, parseSignedResponse)

	// Test Hash
	transactionIdentifier := &types.TransactionIdentifier{
		Hash: "0x424969b1a98757bcd748c60bad2a7de9745cfb26bfefb4550e780a098feada42",
	}
	hashResponse, err := servicer.ConstructionHash(ctx, &types.ConstructionHashRequest{
		NetworkIdentifier: networkIdentifier,
		SignedTransaction: signedRaw,
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.TransactionIdentifierResponse{
		TransactionIdentifier: transactionIdentifier,
	}, hashResponse)

	// Test Submit
	mockClient.On(
		"SendTransaction",
		ctx,
		mock.Anything, // can't test ethTx here because it contains "time"
	).Return(
		nil,
	)
	submitResponse, err := servicer.ConstructionSubmit(ctx, &types.ConstructionSubmitRequest{
		NetworkIdentifier: networkIdentifier,
		SignedTransaction: signedRaw,
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.TransactionIdentifierResponse{
		TransactionIdentifier: transactionIdentifier,
	}, submitResponse)

	mockClient.AssertExpectations(t)
}

//func TestDeriveAccountKeyLegacy(t *testing.T) {
//	networkIdentifier = &types.NetworkIdentifier{
//		Network:    klaytn.TestnetNetwork,
//		Blockchain: klaytn.Blockchain,
//	}
//
//	cfg := &configuration.Configuration{
//		Mode:    configuration.Online,
//		Network: networkIdentifier,
//		Params:  params.BaobabChainConfig,
//	}
//	cfg.Params.ChainID = big.NewInt(3)
//
//	mockClient := &mocks.Client{}
//	servicer := NewConstructionAPIService(cfg, mockClient)
//	ctx := context.Background()
//
//	// Test Derive with uncompressed public key string.
//	// Test when there is no state in Klaytn network.
//	expectedResult := map[string]interface{}{
//		"accType": float64(1),
//		"account": map[string]interface{}{
//			"balance":       "0x0",
//			"humanReadable": false,
//			"key":           map[string]interface{}{"keyType": float64(1), "key": map[string]interface{}{}},
//			"nonce":         float64(0),
//		},
//	}
//	mockClient.On(
//		"GetAccount",
//		ctx,
//		"0xfE8ad07E2f5A972aD1146c22DbCFBEC4Ad36bdD9",
//		"latest",
//	).Return(
//		nil,
//		nil,
//	).Once()
//
//	publicKey := &types.PublicKey{
//		Bytes: forceHexDecode(
//			t,
//			"cc6ae711f6d972f3f434e573ee91a3a10586b60766ba88de1bd6ecc1be02630b2caa95f1c64dc15b83e793b3c5e3499dd8c0f7871fb39e5e8d91f3ff9201416f", // nolint: lll
//		),
//		CurveType: types.Secp256k1,
//	}
//	accountIdf, err := servicer.ConstructionDerive(ctx, &types.ConstructionDeriveRequest{
//		NetworkIdentifier: networkIdentifier,
//		PublicKey:         publicKey,
//	})
//	assert.Nil(t, err)
//	assert.NotNil(t, accountIdf)
//	assert.Equal(t, accountIdf.AccountIdentifier.Address, "0xfE8ad07E2f5A972aD1146c22DbCFBEC4Ad36bdD9")
//	assert.NotNil(t, accountIdf.AccountIdentifier.Metadata)
//	assert.Equal(t, expectedResult, accountIdf.AccountIdentifier.Metadata)
//
//	// Test Derive with uncompressed public key string.
//	// Test when there is a state in Klaytn network.
//	expectedResult = map[string]interface{}{
//		"accType": float64(1),
//		"account": map[string]interface{}{
//			"balance":       "0x1",
//			"humanReadable": false,
//			"key":           map[string]interface{}{"keyType": float64(1), "key": map[string]interface{}{}},
//			"nonce":         float64(1),
//		},
//	}
//	mockClient.On(
//		"GetAccount",
//		ctx,
//		"0x2aD64a85d0e07179268bc3AEA645255a34a55350",
//		"latest",
//	).Return(expectedResult, nil).Once()
//
//	publicKey = &types.PublicKey{
//		Bytes: forceHexDecode(
//			t,
//			"74b3c5c50573363f53e94111cb5d19e0a48dcb914d380ac524d962f29f1757cae72fbaecad93cf58b202dfb012b7b43370ba0799c0f268675f08af5f9e475924", // nolint: lll
//		),
//		CurveType: types.Secp256k1,
//	}
//	accountIdf, err = servicer.ConstructionDerive(ctx, &types.ConstructionDeriveRequest{
//		NetworkIdentifier: networkIdentifier,
//		PublicKey:         publicKey,
//	})
//	assert.Nil(t, err)
//	assert.NotNil(t, accountIdf)
//	assert.Equal(t, accountIdf.AccountIdentifier.Address, "0x2aD64a85d0e07179268bc3AEA645255a34a55350")
//	assert.NotNil(t, accountIdf.AccountIdentifier.Metadata)
//	assert.Equal(t, expectedResult, accountIdf.AccountIdentifier.Metadata)
//
//	// Test Derive with compressed public key string.
//	// Test when there is no state in Klaytn network.
//	expectedResult = map[string]interface{}{
//		"accType": float64(1),
//		"account": map[string]interface{}{
//			"balance":       "0x0",
//			"humanReadable": false,
//			"key":           map[string]interface{}{"keyType": float64(1), "key": map[string]interface{}{}},
//			"nonce":         float64(0),
//		},
//	}
//	mockClient.On(
//		"GetAccount",
//		ctx,
//		"0x63154341A48e210348a4Cb2bd90F24675e1c1BA8",
//		"latest",
//	).Return(
//		nil,
//		nil,
//	).Once()
//
//	// Umcompressed format is below
//	// nolint: lll
//	// c4f781ee514a65c46df4fd24521daa369a8a73bd964c7e4f295cc7dec185328fec9e1830876540caa670dfb084b5ee28f944dfda6a7d1ad00eae24483edc3592
//	publicKey = &types.PublicKey{
//		Bytes: forceHexDecode(
//			t,
//			"02c4f781ee514a65c46df4fd24521daa369a8a73bd964c7e4f295cc7dec185328f",
//		),
//		CurveType: types.Secp256k1,
//	}
//	accountIdf, err = servicer.ConstructionDerive(ctx, &types.ConstructionDeriveRequest{
//		NetworkIdentifier: networkIdentifier,
//		PublicKey:         publicKey,
//	})
//	assert.Nil(t, err)
//	assert.NotNil(t, accountIdf)
//	assert.Equal(t, accountIdf.AccountIdentifier.Address, "0x63154341A48e210348a4Cb2bd90F24675e1c1BA8")
//	assert.NotNil(t, accountIdf.AccountIdentifier.Metadata)
//	assert.Equal(t, expectedResult, accountIdf.AccountIdentifier.Metadata)
//
//	// Test Derive with uncompressed public key string.
//	// Test when there is a state in Klaytn network.
//	expectedResult = map[string]interface{}{
//		"accType": float64(1),
//		"account": map[string]interface{}{
//			"balance":       "0x1",
//			"humanReadable": false,
//			"key":           map[string]interface{}{"keyType": float64(1), "key": map[string]interface{}{}},
//			"nonce":         float64(1),
//		},
//	}
//	mockClient.On(
//		"GetAccount",
//		ctx,
//		"0xE9928998caba828E17D1dc3403D4c6Df26eE4637",
//		"latest",
//	).Return(expectedResult, nil).Once()
//
//	// Umcompressed format is below
//	// nolint: lll
//	// f72d9099365d8f9f97d1528a91357b56ae6aad332dc11d034fbfb43b33de254b233e55b1966cea1e53a7fe61e58b6dc22c24cb292ed5d63ab794490507d7d3b6
//	publicKey = &types.PublicKey{
//		Bytes: forceHexDecode(
//			t,
//			"02f72d9099365d8f9f97d1528a91357b56ae6aad332dc11d034fbfb43b33de254b",
//		),
//		CurveType: types.Secp256k1,
//	}
//	accountIdf, err = servicer.ConstructionDerive(ctx, &types.ConstructionDeriveRequest{
//		NetworkIdentifier: networkIdentifier,
//		PublicKey:         publicKey,
//	})
//	assert.Nil(t, err)
//	assert.NotNil(t, accountIdf)
//	assert.Equal(t, accountIdf.AccountIdentifier.Address, "0xE9928998caba828E17D1dc3403D4c6Df26eE4637")
//	assert.NotNil(t, accountIdf.AccountIdentifier.Metadata)
//	assert.Equal(t, expectedResult, accountIdf.AccountIdentifier.Metadata)
//
//	// Test Derive with compressed public key string.
//	// Test when there is no state in Klaytn network.
//	expectedResult = map[string]interface{}{
//		"accType": float64(1),
//		"account": map[string]interface{}{
//			"balance":       "0x0",
//			"humanReadable": false,
//			"key":           map[string]interface{}{"keyType": float64(1), "key": map[string]interface{}{}},
//			"nonce":         float64(0),
//		},
//	}
//	mockClient.On(
//		"GetAccount",
//		ctx,
//		"0x63154341A48e210348a4Cb2bd90F24675e1c1BA8",
//		"latest",
//	).Return(
//		nil,
//		nil,
//	).Once()
//
//	// Umcompressed format is below
//	// nolint: lll
//	// c4f781ee514a65c46df4fd24521daa369a8a73bd964c7e4f295cc7dec185328fec9e1830876540caa670dfb084b5ee28f944dfda6a7d1ad00eae24483edc3592
//	publicKey = &types.PublicKey{
//		Bytes: forceHexDecode(
//			t,
//			"02c4f781ee514a65c46df4fd24521daa369a8a73bd964c7e4f295cc7dec185328f",
//		),
//		CurveType: types.Secp256k1,
//	}
//	accountIdf, err = servicer.ConstructionDerive(ctx, &types.ConstructionDeriveRequest{
//		NetworkIdentifier: networkIdentifier,
//		PublicKey:         publicKey,
//	})
//	assert.Nil(t, err)
//	assert.NotNil(t, accountIdf)
//	assert.Equal(t, accountIdf.AccountIdentifier.Address, "0x63154341A48e210348a4Cb2bd90F24675e1c1BA8")
//	assert.NotNil(t, accountIdf.AccountIdentifier.Metadata)
//	assert.Equal(t, expectedResult, accountIdf.AccountIdentifier.Metadata)
//
//	// Test Derive with uncompressed public key string.
//	// Test when there is a state in Klaytn network.
//	expectedResult = map[string]interface{}{
//		"accType": float64(1),
//		"account": map[string]interface{}{
//			"balance":       "0x1",
//			"humanReadable": false,
//			"key":           map[string]interface{}{"keyType": float64(1), "key": map[string]interface{}{}},
//			"nonce":         float64(1),
//		},
//	}
//	mockClient.On(
//		"GetAccount",
//		ctx,
//		"0xE9928998caba828E17D1dc3403D4c6Df26eE4637",
//		"latest",
//	).Return(expectedResult, nil).Once()
//
//	// Umcompressed format is below
//	// nolint: lll
//	// f72d9099365d8f9f97d1528a91357b56ae6aad332dc11d034fbfb43b33de254b233e55b1966cea1e53a7fe61e58b6dc22c24cb292ed5d63ab794490507d7d3b6
//	publicKey = &types.PublicKey{
//		Bytes: forceHexDecode(
//			t,
//			"02f72d9099365d8f9f97d1528a91357b56ae6aad332dc11d034fbfb43b33de254b",
//		),
//		CurveType: types.Secp256k1,
//	}
//	accountIdf, err = servicer.ConstructionDerive(ctx, &types.ConstructionDeriveRequest{
//		NetworkIdentifier: networkIdentifier,
//		PublicKey:         publicKey,
//	})
//	assert.Nil(t, err)
//	assert.NotNil(t, accountIdf)
//	assert.Equal(t, accountIdf.AccountIdentifier.Address, "0xE9928998caba828E17D1dc3403D4c6Df26eE4637")
//	assert.NotNil(t, accountIdf.AccountIdentifier.Metadata)
//	assert.Equal(t, expectedResult, accountIdf.AccountIdentifier.Metadata)
//
//	// Test Derive with compressed public key string with an address in metadata.
//	// Test when address derived from public key is matched with user's address parameter.
//	expectedResult = map[string]interface{}{
//		"accType": float64(1),
//		"account": map[string]interface{}{
//			"balance":       "0x0",
//			"humanReadable": false,
//			"key":           map[string]interface{}{"keyType": float64(1), "key": map[string]interface{}{}},
//			"nonce":         float64(0),
//		},
//	}
//	mockClient.On(
//		"GetAccount",
//		ctx,
//		"0xa347E12F38aa4557509235780C2fcB67f1B80374",
//		"latest",
//	).Return(
//		nil,
//		nil,
//	).Once()
//
//	// Umcompressed format is below
//	// nolint: lll
//	// 609c0c18480450dc6dd87a067d6906af26ed99b9a529b4b6a28c49e43d4ecb473ba6f96d33675d086ad732a7322963a1efb6dc32602043e076f2cf9531de7928
//	publicKey = &types.PublicKey{
//		Bytes: forceHexDecode(
//			t,
//			"02609c0c18480450dc6dd87a067d6906af26ed99b9a529b4b6a28c49e43d4ecb47",
//		),
//		CurveType: types.Secp256k1,
//	}
//	accountIdf, err = servicer.ConstructionDerive(ctx, &types.ConstructionDeriveRequest{
//		NetworkIdentifier: networkIdentifier,
//		PublicKey:         publicKey,
//		Metadata: map[string]interface{}{
//			"address": "0xa347E12F38aa4557509235780C2fcB67f1B80374",
//		},
//	})
//	assert.Nil(t, err)
//	assert.NotNil(t, accountIdf)
//	assert.Equal(t, accountIdf.AccountIdentifier.Address, "0xa347E12F38aa4557509235780C2fcB67f1B80374")
//	assert.NotNil(t, accountIdf.AccountIdentifier.Metadata)
//	assert.Equal(t, expectedResult, accountIdf.AccountIdentifier.Metadata)
//
//	// Error Case Testing
//	// Test Derive with uncompressed public key string with an address in metadata.
//	// Test when address derived from public key is not matched with user's address parameter.
//	expectedResult = map[string]interface{}{
//		"accType": float64(1),
//		"account": map[string]interface{}{
//			"balance":       "0x1",
//			"humanReadable": false,
//			"key":           map[string]interface{}{"keyType": float64(1), "key": map[string]interface{}{}},
//			"nonce":         float64(1),
//		},
//	}
//	mockClient.On(
//		"GetAccount",
//		ctx,
//		"0xa5c4A7C5323122789a9f9d9A06a2F2900b49f452",
//		"latest",
//	).Return(expectedResult, nil).Once()
//
//	// Umcompressed format is below
//	// nolint: lll
//	// f72d9099365d8f9f97d1528a91357b56ae6aad332dc11d034fbfb43b33de254b233e55b1966cea1e53a7fe61e58b6dc22c24cb292ed5d63ab794490507d7d3b6
//	publicKey = &types.PublicKey{
//		Bytes: forceHexDecode(
//			t,
//			"02a7f8429d4fef81df5ec74bc4d5c205373b772283fa7eeeae9843df93d33acd2f",
//		),
//		CurveType: types.Secp256k1,
//	}
//	accountIdf, err = servicer.ConstructionDerive(ctx, &types.ConstructionDeriveRequest{
//		NetworkIdentifier: networkIdentifier,
//		PublicKey:         publicKey,
//		Metadata: map[string]interface{}{
//			"address": "0xa5c4A7C5323122789a9f9d9A06a2F2900b49f452",
//		},
//	})
//	assert.NotNil(t, err)
//	assert.Nil(t, accountIdf)
//	assert.NotNil(t, err.Details)
//	assert.NotNil(t, err.Details["metadata"])
//	assert.Equal(t, expectedResult, err.Details["metadata"])
//
//	mockClient.AssertExpectations(t)
//}
//
//func TestDeriveAccountKeyPublic(t *testing.T) {
//	networkIdentifier = &types.NetworkIdentifier{
//		Network:    klaytn.TestnetNetwork,
//		Blockchain: klaytn.Blockchain,
//	}
//
//	cfg := &configuration.Configuration{
//		Mode:    configuration.Online,
//		Network: networkIdentifier,
//		Params:  params.BaobabChainConfig,
//	}
//	cfg.Params.ChainID = big.NewInt(3)
//
//	mockClient := &mocks.Client{}
//	servicer := NewConstructionAPIService(cfg, mockClient)
//	ctx := context.Background()
//
//	// Test Derive with uncompressed public key string with an address in metadata.
//	// Test when public key is matched.
//	expectedResult := map[string]interface{}{
//		"accType": float64(1),
//		"account": map[string]interface{}{
//			"balance":       "0x1",
//			"humanReadable": false,
//			"key": map[string]interface{}{"keyType": float64(2), "key": map[string]interface{}{
//				"x": "0x69d939901cd4c7f863a68925221244632f07d574335bdc6b5aacd4812ffb38d9",
//				"y": "0xee5c2aca8480083fe028e54491f809d5ddeb6d6a0684f227664ede5884bdae59",
//			}},
//			"nonce": float64(1),
//		},
//	}
//	mockClient.On(
//		"GetAccount",
//		ctx,
//		"0x4A54b7fAd4Fdcb2aaBBD5e254B2412a14944e8AE",
//		"latest",
//	).Return(expectedResult, nil).Once()
//
//	publicKey := &types.PublicKey{
//		Bytes: forceHexDecode(
//			t,
//			"69d939901cd4c7f863a68925221244632f07d574335bdc6b5aacd4812ffb38d9ee5c2aca8480083fe028e54491f809d5ddeb6d6a0684f227664ede5884bdae59", // nolint: lll
//		),
//		CurveType: types.Secp256k1,
//	}
//	accountIdf, err := servicer.ConstructionDerive(ctx, &types.ConstructionDeriveRequest{
//		NetworkIdentifier: networkIdentifier,
//		PublicKey:         publicKey,
//		Metadata: map[string]interface{}{
//			"address": "0x4A54b7fAd4Fdcb2aaBBD5e254B2412a14944e8AE",
//		},
//	})
//	assert.Nil(t, err)
//	assert.NotNil(t, accountIdf)
//	assert.Equal(t, accountIdf.AccountIdentifier.Address, "0x4A54b7fAd4Fdcb2aaBBD5e254B2412a14944e8AE")
//	assert.NotNil(t, accountIdf.AccountIdentifier.Metadata)
//	assert.Equal(t, expectedResult, accountIdf.AccountIdentifier.Metadata)
//
//	// Test Derive with compressed public key string with an address in metadata.
//	// Test when public key is matched.
//	expectedResult = map[string]interface{}{
//		"accType": float64(1),
//		"account": map[string]interface{}{
//			"balance":       "0x1",
//			"humanReadable": false,
//			"key": map[string]interface{}{"keyType": float64(2), "key": map[string]interface{}{
//				"x": "0x8b37e07e722d2294e2531410fd617d8ca25dc8f2e44f804796d89dde9a21d1d3",
//				"y": "0xc837d6b30cc755ab64f16c810c2d87463dc23561a3c4f2ffd534dab7701d5166",
//			}},
//			"nonce": float64(1),
//		},
//	}
//	mockClient.On(
//		"GetAccount",
//		ctx,
//		"0x233070a387998b2e0fe60ED048dbb6df06c5FE38",
//		"latest",
//	).Return(expectedResult, nil).Once()
//
//	// Umcompressed format is below
//	// nolint: lll
//	// 8b37e07e722d2294e2531410fd617d8ca25dc8f2e44f804796d89dde9a21d1d3c837d6b30cc755ab64f16c810c2d87463dc23561a3c4f2ffd534dab7701d5166
//	publicKey = &types.PublicKey{
//		Bytes: forceHexDecode(
//			t,
//			"028b37e07e722d2294e2531410fd617d8ca25dc8f2e44f804796d89dde9a21d1d3",
//		),
//		CurveType: types.Secp256k1,
//	}
//	accountIdf, err = servicer.ConstructionDerive(ctx, &types.ConstructionDeriveRequest{
//		NetworkIdentifier: networkIdentifier,
//		PublicKey:         publicKey,
//		Metadata: map[string]interface{}{
//			"address": "0x233070a387998b2e0fe60ED048dbb6df06c5FE38",
//		},
//	})
//	assert.Nil(t, err)
//	assert.NotNil(t, accountIdf)
//	assert.Equal(t, accountIdf.AccountIdentifier.Address, "0x233070a387998b2e0fe60ED048dbb6df06c5FE38")
//	assert.NotNil(t, accountIdf.AccountIdentifier.Metadata)
//	assert.Equal(t, expectedResult, accountIdf.AccountIdentifier.Metadata)
//
//	// Test Derive with uncompressed public key string with an address in metadata. (leading zeros case)
//	// Test when public key is matched.
//	expectedResult = map[string]interface{}{
//		"accType": float64(1),
//		"account": map[string]interface{}{
//			"balance":       "0x1",
//			"humanReadable": false,
//			"key": map[string]interface{}{"keyType": float64(2), "key": map[string]interface{}{
//				"x": "0x2337135c0bc83b94907cea0ebbbe5b1c2ee570071dd45d5bc7448b4dc7202b6",
//				"y": "0xa78d9efe5a976a70a26773971b642f3ed4f493be0e0c1c27bbc33b319c84b951",
//			}},
//			"nonce": float64(1),
//		},
//	}
//	mockClient.On(
//		"GetAccount",
//		ctx,
//		"0x7BF5E2692Fea83c71dA09B5b868cF545845b786D",
//		"latest",
//	).Return(expectedResult, nil).Once()
//
//	publicKey = &types.PublicKey{
//		Bytes: forceHexDecode(
//			t,
//			"02337135c0bc83b94907cea0ebbbe5b1c2ee570071dd45d5bc7448b4dc7202b6a78d9efe5a976a70a26773971b642f3ed4f493be0e0c1c27bbc33b319c84b951", // nolint: lll
//		),
//		CurveType: types.Secp256k1,
//	}
//	accountIdf, err = servicer.ConstructionDerive(ctx, &types.ConstructionDeriveRequest{
//		NetworkIdentifier: networkIdentifier,
//		PublicKey:         publicKey,
//		Metadata: map[string]interface{}{
//			"address": "0x7BF5E2692Fea83c71dA09B5b868cF545845b786D",
//		},
//	})
//	assert.Nil(t, err)
//	assert.NotNil(t, accountIdf)
//	assert.Equal(t, accountIdf.AccountIdentifier.Address, "0x7BF5E2692Fea83c71dA09B5b868cF545845b786D")
//	assert.NotNil(t, accountIdf.AccountIdentifier.Metadata)
//	assert.Equal(t, expectedResult, accountIdf.AccountIdentifier.Metadata)
//
//	// Error Case Testing
//	// Test Derive with compressed public key string with an address in metadata.
//	// Test when public key is not matched with user's public key input.
//	expectedResult = map[string]interface{}{
//		"accType": float64(1),
//		"account": map[string]interface{}{
//			"balance":       "0x1",
//			"humanReadable": false,
//			"key": map[string]interface{}{"keyType": float64(2), "key": map[string]interface{}{
//				"x": "0x925544ea745aba352b3a8ce718e50f4ebc80a4e704fc625b2233548205d507f4",
//				"y": "0x82002911ca9da8009eb2516303c624b77a6388b159d67722f3b7f00d53cd5702",
//			}},
//			"nonce": float64(1),
//		},
//	}
//	mockClient.On(
//		"GetAccount",
//		ctx,
//		"0x554aa5CC0D733c5c9F2BA45dD8E8D53b94069B0a",
//		"latest",
//	).Return(expectedResult, nil).Once()
//
//	// Umcompressed format is below
//	// nolint: lll
//	// 225145a6b2bd744b940521c61c607413046bf69846170c771bff9dc43d243aa20963dc5404ed670076757b7857207acf6b3c35e458800e36d775a090262c81d8
//	publicKey = &types.PublicKey{
//		Bytes: forceHexDecode(
//			t,
//			"02225145a6b2bd744b940521c61c607413046bf69846170c771bff9dc43d243aa2",
//		),
//		CurveType: types.Secp256k1,
//	}
//	accountIdf, err = servicer.ConstructionDerive(ctx, &types.ConstructionDeriveRequest{
//		NetworkIdentifier: networkIdentifier,
//		PublicKey:         publicKey,
//		Metadata: map[string]interface{}{
//			"address": "0x554aa5CC0D733c5c9F2BA45dD8E8D53b94069B0a",
//		},
//	})
//	assert.NotNil(t, err)
//	assert.Nil(t, accountIdf)
//	assert.NotNil(t, err.Details)
//	assert.NotNil(t, err.Details["metadata"])
//	assert.Equal(t, expectedResult, err.Details["metadata"])
//
//	mockClient.AssertExpectations(t)
//}
//
//func TestDeriveAccountKeyFail(t *testing.T) {
//	networkIdentifier = &types.NetworkIdentifier{
//		Network:    klaytn.TestnetNetwork,
//		Blockchain: klaytn.Blockchain,
//	}
//
//	cfg := &configuration.Configuration{
//		Mode:    configuration.Online,
//		Network: networkIdentifier,
//		Params:  params.BaobabChainConfig,
//	}
//	cfg.Params.ChainID = big.NewInt(3)
//
//	mockClient := &mocks.Client{}
//	servicer := NewConstructionAPIService(cfg, mockClient)
//	ctx := context.Background()
//
//	// Test Error Case
//	// Test Derive with uncompressed public key string without an address.
//	// Test when account key is AccountKeyFail.
//	expectedResult := map[string]interface{}{
//		"accType": float64(1),
//		"account": map[string]interface{}{
//			"balance":       "0x1",
//			"humanReadable": false,
//			"key":           map[string]interface{}{"keyType": float64(3), "key": map[string]interface{}{}},
//			"nonce":         float64(1),
//		},
//	}
//	mockClient.On(
//		"GetAccount",
//		ctx,
//		"0x2eFDb29eFcc38e7a5171B7c43c1D2c3986964159",
//		"latest",
//	).Return(expectedResult, nil).Once()
//
//	publicKey := &types.PublicKey{
//		Bytes: forceHexDecode(
//			t,
//			"3cbe27632c7c23b04e0dc58532f272a37104f2c2c3ade7fe2c4facdb78f8a6b6e17dcd3b280091433946b5c9da356ac001c74f1551afe475a292ab81246cb40d", // nolint: lll
//		),
//		CurveType: types.Secp256k1,
//	}
//	accountIdf, err := servicer.ConstructionDerive(ctx, &types.ConstructionDeriveRequest{
//		NetworkIdentifier: networkIdentifier,
//		PublicKey:         publicKey,
//	})
//	assert.NotNil(t, err)
//	assert.Nil(t, accountIdf)
//	assert.NotNil(t, err.Details)
//	assert.NotNil(t, err.Details["metadata"])
//	assert.Equal(t, expectedResult, err.Details["metadata"])
//
//	// Test Error Case
//	// Test Derive with compressed public key string with an address.
//	// Test when account key is AccountKeyFail.
//	mockClient.On(
//		"GetAccount",
//		ctx,
//		"0xFB4a7C354D77b1466e5E6b6e84E9ADe45a30eb31",
//		"latest",
//	).Return(expectedResult, nil).Once()
//
//	publicKey = &types.PublicKey{
//		Bytes: forceHexDecode(
//			t,
//			"02681174b403604fc8d283f5fb63f1ac67df6227a3fab8cf3890afecce042ff384",
//		),
//		CurveType: types.Secp256k1,
//	}
//	accountIdf, err = servicer.ConstructionDerive(ctx, &types.ConstructionDeriveRequest{
//		NetworkIdentifier: networkIdentifier,
//		PublicKey:         publicKey,
//		Metadata: map[string]interface{}{
//			"address": "0xFB4a7C354D77b1466e5E6b6e84E9ADe45a30eb31",
//		},
//	})
//	assert.NotNil(t, err)
//	assert.Nil(t, accountIdf)
//	assert.NotNil(t, err.Details)
//	assert.NotNil(t, err.Details["metadata"])
//	assert.Equal(t, expectedResult, err.Details["metadata"])
//
//	// Test Error Case
//	// Test Derive with compressed public key string with an address.
//	// Test when account is SCA(Smart Contract Account).
//	mockClient.On(
//		"GetAccount",
//		ctx,
//		"0x487D7E1c3e4457307C7FeeA407dD0ed36524AcDB",
//		"latest",
//	).Return(expectedResult, nil).Once()
//
//	publicKey = &types.PublicKey{
//		Bytes: forceHexDecode(
//			t,
//			"02681174b403604fc8d283f5fb63f1ac67df6227a3fab8cf3890afecce042ff384",
//		),
//		CurveType: types.Secp256k1,
//	}
//	accountIdf, err = servicer.ConstructionDerive(ctx, &types.ConstructionDeriveRequest{
//		NetworkIdentifier: networkIdentifier,
//		PublicKey:         publicKey,
//		Metadata: map[string]interface{}{
//			"address": "0x487D7E1c3e4457307C7FeeA407dD0ed36524AcDB",
//		},
//	})
//	assert.NotNil(t, err)
//	assert.Nil(t, accountIdf)
//	assert.NotNil(t, err.Details)
//	assert.NotNil(t, err.Details["metadata"])
//	assert.Equal(t, expectedResult, err.Details["metadata"])
//
//	mockClient.AssertExpectations(t)
//}
//
//func TestDeriveAccountKeyWeightedMultiSig(t *testing.T) {
//	networkIdentifier = &types.NetworkIdentifier{
//		Network:    klaytn.TestnetNetwork,
//		Blockchain: klaytn.Blockchain,
//	}
//
//	cfg := &configuration.Configuration{
//		Mode:    configuration.Online,
//		Network: networkIdentifier,
//		Params:  params.BaobabChainConfig,
//	}
//	cfg.Params.ChainID = big.NewInt(3)
//
//	mockClient := &mocks.Client{}
//	servicer := NewConstructionAPIService(cfg, mockClient)
//	ctx := context.Background()
//
//	// Test Derive with uncompressed public key string with an address in metadata.
//	// Test when public key is included.
//	expectedResult := map[string]interface{}{
//		"accType": float64(1),
//		"account": map[string]interface{}{
//			"balance":       "0x1",
//			"humanReadable": false,
//			"key": map[string]interface{}{"keyType": float64(4), "key": map[string]interface{}{
//				"threshold": 2,
//				"keys": []interface{}{
//					map[string]interface{}{
//						"weight": 1,
//						"key": map[string]interface{}{
//							"x": "0x69d939901cd4c7f863a68925221244632f07d574335bdc6b5aacd4812ffb38d9",
//							"y": "0xee5c2aca8480083fe028e54491f809d5ddeb6d6a0684f227664ede5884bdae59",
//						},
//					},
//					map[string]interface{}{
//						"weight": 1,
//						"key": map[string]interface{}{
//							"x": "0xf86eddd4bd5fc8739524eaa197bf5d8ad6236665f522ef296527ff5b1f280a73",
//							"y": "0x7cfba9e3e77e8a99352bb5a92e6f9c4c04c2decc9ec04914ae8605d798770c46",
//						},
//					},
//				},
//			}},
//			"nonce": float64(1),
//		},
//	}
//	mockClient.On(
//		"GetAccount",
//		ctx,
//		"0x3c23006f4167cda086f8D55ABfb6CA7f8E767Fc7",
//		"latest",
//	).Return(expectedResult, nil).Once()
//
//	publicKey := &types.PublicKey{
//		Bytes: forceHexDecode(
//			t,
//			"f86eddd4bd5fc8739524eaa197bf5d8ad6236665f522ef296527ff5b1f280a737cfba9e3e77e8a99352bb5a92e6f9c4c04c2decc9ec04914ae8605d798770c46", // nolint: lll
//		),
//		CurveType: types.Secp256k1,
//	}
//	accountIdf, err := servicer.ConstructionDerive(ctx, &types.ConstructionDeriveRequest{
//		NetworkIdentifier: networkIdentifier,
//		PublicKey:         publicKey,
//		Metadata: map[string]interface{}{
//			"address": "0x3c23006f4167cda086f8D55ABfb6CA7f8E767Fc7",
//		},
//	})
//	assert.Nil(t, err)
//	assert.NotNil(t, accountIdf)
//	assert.Equal(t, accountIdf.AccountIdentifier.Address, "0x3c23006f4167cda086f8D55ABfb6CA7f8E767Fc7")
//	assert.NotNil(t, accountIdf.AccountIdentifier.Metadata)
//	assert.Equal(t, expectedResult, accountIdf.AccountIdentifier.Metadata)
//
//	// Test Derive with compressed public key string with an address in metadata.
//	// Test when public key is included.
//	expectedResult = map[string]interface{}{
//		"accType": float64(1),
//		"account": map[string]interface{}{
//			"balance":       "0x1",
//			"humanReadable": false,
//			"key": map[string]interface{}{"keyType": float64(4), "key": map[string]interface{}{
//				"threshold": 2,
//				"keys": []interface{}{
//					map[string]interface{}{
//						"weight": 1,
//						"key": map[string]interface{}{
//							"x": "0x69d939901cd4c7f863a68925221244632f07d574335bdc6b5aacd4812ffb38d9",
//							"y": "0xee5c2aca8480083fe028e54491f809d5ddeb6d6a0684f227664ede5884bdae59",
//						},
//					},
//					map[string]interface{}{
//						"weight": 1,
//						"key": map[string]interface{}{
//							"x": "0x3d66a515e7a30c835f0b16065d2e16db833a78b436a14f20b2e834c3a78c5244",
//							"y": "0x4823ca3b62b42a00bd3c50f97099a9d9cfc128231aba613539105a6d16673392",
//						},
//					},
//				},
//			}},
//			"nonce": float64(1),
//		},
//	}
//	mockClient.On(
//		"GetAccount",
//		ctx,
//		"0xeffedf2d84cB1F1a65c9B5f56eA9ceB6D7F6022f",
//		"latest",
//	).Return(expectedResult, nil).Once()
//
//	// Umcompressed format is below
//	// nolint: lll
//	// 3d66a515e7a30c835f0b16065d2e16db833a78b436a14f20b2e834c3a78c52444823ca3b62b42a00bd3c50f97099a9d9cfc128231aba613539105a6d16673392
//	publicKey = &types.PublicKey{
//		Bytes: forceHexDecode(
//			t,
//			"023d66a515e7a30c835f0b16065d2e16db833a78b436a14f20b2e834c3a78c5244",
//		),
//		CurveType: types.Secp256k1,
//	}
//	accountIdf, err = servicer.ConstructionDerive(ctx, &types.ConstructionDeriveRequest{
//		NetworkIdentifier: networkIdentifier,
//		PublicKey:         publicKey,
//		Metadata: map[string]interface{}{
//			"address": "0xeffedf2d84cB1F1a65c9B5f56eA9ceB6D7F6022f",
//		},
//	})
//	assert.Nil(t, err)
//	assert.NotNil(t, accountIdf)
//	assert.Equal(t, accountIdf.AccountIdentifier.Address, "0xeffedf2d84cB1F1a65c9B5f56eA9ceB6D7F6022f")
//	assert.NotNil(t, accountIdf.AccountIdentifier.Metadata)
//	assert.Equal(t, expectedResult, accountIdf.AccountIdentifier.Metadata)
//
//	// Error Case Testing
//	// Test Derive with compressed public key string with an address in metadata.
//	// Test when public key is not included in the multisig account key.
//	expectedResult = map[string]interface{}{
//		"accType": float64(1),
//		"account": map[string]interface{}{
//			"balance":       "0x1",
//			"humanReadable": false,
//			"key": map[string]interface{}{"keyType": float64(4), "key": map[string]interface{}{
//				"threshold": 2,
//				"keys": []interface{}{
//					map[string]interface{}{
//						"weight": 1,
//						"key": map[string]interface{}{
//							"x": "0x69d939901cd4c7f863a68925221244632f07d574335bdc6b5aacd4812ffb38d9",
//							"y": "0xee5c2aca8480083fe028e54491f809d5ddeb6d6a0684f227664ede5884bdae59",
//						},
//					},
//					map[string]interface{}{
//						"weight": 1,
//						"key": map[string]interface{}{
//							"x": "0x3d66a515e7a30c835f0b16065d2e16db833a78b436a14f20b2e834c3a78c5244",
//							"y": "0x4823ca3b62b42a00bd3c50f97099a9d9cfc128231aba613539105a6d16673392",
//						},
//					},
//				},
//			}},
//			"nonce": float64(1),
//		},
//	}
//	mockClient.On(
//		"GetAccount",
//		ctx,
//		"0x4C01983c5c7EEf73e94DB969b6b1d6b9a420A916",
//		"latest",
//	).Return(expectedResult, nil).Once()
//
//	// Umcompressed format is below
//	// nolint: lll
//	// b8951daf5458517314f6f03c9cf43093f1fcc221b258fbb07fa0a20d9768c38978877fe435035f9cf02a583ccdec2c1510b55ab094eb410ed281692e64add8fa
//	publicKey = &types.PublicKey{
//		Bytes: forceHexDecode(
//			t,
//			"02b8951daf5458517314f6f03c9cf43093f1fcc221b258fbb07fa0a20d9768c389",
//		),
//		CurveType: types.Secp256k1,
//	}
//	accountIdf, err = servicer.ConstructionDerive(ctx, &types.ConstructionDeriveRequest{
//		NetworkIdentifier: networkIdentifier,
//		PublicKey:         publicKey,
//		Metadata: map[string]interface{}{
//			"address": "0x4C01983c5c7EEf73e94DB969b6b1d6b9a420A916",
//		},
//	})
//	assert.NotNil(t, err)
//	assert.Nil(t, accountIdf)
//	assert.NotNil(t, err.Details)
//	assert.NotNil(t, err.Details["metadata"])
//	assert.Equal(t, expectedResult, err.Details["metadata"])
//
//	mockClient.AssertExpectations(t)
//}
//
//func TestDeriveAccountKeyRoleBased(t *testing.T) {
//	networkIdentifier = &types.NetworkIdentifier{
//		Network:    klaytn.TestnetNetwork,
//		Blockchain: klaytn.Blockchain,
//	}
//
//	cfg := &configuration.Configuration{
//		Mode:    configuration.Online,
//		Network: networkIdentifier,
//		Params:  params.BaobabChainConfig,
//	}
//	cfg.Params.ChainID = big.NewInt(3)
//
//	mockClient := &mocks.Client{}
//	servicer := NewConstructionAPIService(cfg, mockClient)
//	ctx := context.Background()
//
//	// Test Derive with uncompressed public key string with an address in metadata.
//	// Test when public key is included when roleTransactionKey is AccountKeyWeightedMultiSig.
//	expectedResult := map[string]interface{}{
//		"accType": float64(1),
//		"account": map[string]interface{}{
//			"balance":       "0x1",
//			"humanReadable": false,
//			"key": map[string]interface{}{"keyType": float64(5), "key": []interface{}{
//				map[string]interface{}{"keyType": float64(4), "key": map[string]interface{}{
//					"threshold": 2,
//					"keys": []interface{}{
//						map[string]interface{}{
//							"weight": 1,
//							"key": map[string]interface{}{
//								"x": "0xd80f4e6ec2239d4fd460cdf09f124fdf538edec72cc4887acdad88f4df970d12",
//								"y": "0x4547c81e0fdf045c985367d8f308ebf7dd6311c14016899ad1941d7128959530",
//							},
//						},
//						map[string]interface{}{
//							"weight": 1,
//							"key": map[string]interface{}{
//								"x": "0xad8c07dfc9382047fdfa4393b90b3e00954c426aca26f8b0ab4408a0a89fd56b",
//								"y": "0x260e155f4e234d182fb71526b36388252844f00442c55708a29c2c85f2608fec",
//							},
//						},
//					},
//				}},
//				map[string]interface{}{"keyType": float64(4), "key": map[string]interface{}{
//					"threshold": 2,
//					"keys": []interface{}{
//						map[string]interface{}{
//							"weight": 1,
//							"key": map[string]interface{}{
//								"x": "0x9ca49f018f36c893ad4f3a228fb20bc7b0e53b83fe87abd6beb334d42af0cc4b",
//								"y": "0x64dc2f9e7119aea0aed72833a1e48966908e7b3f039f8dcb8116ae7a7ffc1bf1",
//							},
//						},
//						map[string]interface{}{
//							"weight": 1,
//							"key": map[string]interface{}{
//								"x": "0x82b3649a02f74e52bfd64e2785a6e93ebe690667f7bbd5934533b06b44ddfb48",
//								"y": "0x421857bf756b2d9ae2445811397ea81bd1e89e3bd64cabd1f5fe722cff23dbed",
//							},
//						},
//					},
//				}},
//				map[string]interface{}{"keyType": float64(4), "key": map[string]interface{}{
//					"threshold": 2,
//					"keys": []interface{}{
//						map[string]interface{}{
//							"weight": 1,
//							"key": map[string]interface{}{
//								"x": "0x2d5390f276b73a544c94c12fab061e3326a3a254fd5b8dae90de7e20e26d8fcf",
//								"y": "0x15299b85973d4913aead02f13c4aca4948fbe132d251df40fd1bb273e525dd7c",
//							},
//						},
//						map[string]interface{}{
//							"weight": 1,
//							"key": map[string]interface{}{
//								"x": "0xf6599e14850c33069241b9ed68dfea156f58c6d1757c72e43883587ec8ee0cb3",
//								"y": "0xc6c2547aaebc384ff359cfc3c4ad7399d7095ca4316578a2a0d6e615dd93d78",
//							},
//						},
//					},
//				}},
//			}},
//			"nonce": float64(1),
//		},
//	}
//	mockClient.On(
//		"GetAccount",
//		ctx,
//		"0x74a9000C4375B87Ab275b7F51299c8C892fa42B0",
//		"latest",
//	).Return(expectedResult, nil).Once()
//
//	publicKey := &types.PublicKey{
//		Bytes: forceHexDecode(
//			t,
//			"d80f4e6ec2239d4fd460cdf09f124fdf538edec72cc4887acdad88f4df970d124547c81e0fdf045c985367d8f308ebf7dd6311c14016899ad1941d7128959530", // nolint: lll
//		),
//		CurveType: types.Secp256k1,
//	}
//	accountIdf, err := servicer.ConstructionDerive(ctx, &types.ConstructionDeriveRequest{
//		NetworkIdentifier: networkIdentifier,
//		PublicKey:         publicKey,
//		Metadata: map[string]interface{}{
//			"address": "0x74a9000C4375B87Ab275b7F51299c8C892fa42B0",
//		},
//	})
//	assert.Nil(t, err)
//	assert.NotNil(t, accountIdf)
//	assert.Equal(t, accountIdf.AccountIdentifier.Address, "0x74a9000C4375B87Ab275b7F51299c8C892fa42B0")
//	assert.NotNil(t, accountIdf.AccountIdentifier.Metadata)
//	assert.Equal(t, expectedResult, accountIdf.AccountIdentifier.Metadata)
//
//	// Test Derive with compressed public key string with an address in metadata.
//	// Test when public key is included when roleTransactionKey is AccountKeyWeightedMultiSig.
//	mockClient.On(
//		"GetAccount",
//		ctx,
//		"0x6B0e79cb4D63552247D97Df8bfac0dcEc67EB531",
//		"latest",
//	).Return(expectedResult, nil).Once()
//
//	// Umcompressed format is below
//	// nolint: lll
//	// d80f4e6ec2239d4fd460cdf09f124fdf538edec72cc4887acdad88f4df970d124547c81e0fdf045c985367d8f308ebf7dd6311c14016899ad1941d7128959530
//	publicKey = &types.PublicKey{
//		Bytes: forceHexDecode(
//			t,
//			"02d80f4e6ec2239d4fd460cdf09f124fdf538edec72cc4887acdad88f4df970d12",
//		),
//		CurveType: types.Secp256k1,
//	}
//	accountIdf, err = servicer.ConstructionDerive(ctx, &types.ConstructionDeriveRequest{
//		NetworkIdentifier: networkIdentifier,
//		PublicKey:         publicKey,
//		Metadata: map[string]interface{}{
//			"address": "0x6B0e79cb4D63552247D97Df8bfac0dcEc67EB531",
//		},
//	})
//	assert.Nil(t, err)
//	assert.NotNil(t, accountIdf)
//	assert.Equal(t, accountIdf.AccountIdentifier.Address, "0x6B0e79cb4D63552247D97Df8bfac0dcEc67EB531")
//	assert.NotNil(t, accountIdf.AccountIdentifier.Metadata)
//	assert.Equal(t, expectedResult, accountIdf.AccountIdentifier.Metadata)
//
//	// Error Case Testing
//	// Test Derive with compressed public key string with an address in metadata.
//	// Test when public key is not included in the roleTransactionKey.
//	mockClient.On(
//		"GetAccount",
//		ctx,
//		"0x0FCefeC5151e5dd1b2CD610f6932f005faE46cd3",
//		"latest",
//	).Return(expectedResult, nil).Once()
//
//	// Umcompressed format is below
//	// nolint: lll
//	// 2d5390f276b73a544c94c12fab061e3326a3a254fd5b8dae90de7e20e26d8fcf15299b85973d4913aead02f13c4aca4948fbe132d251df40fd1bb273e525dd7c
//	publicKey = &types.PublicKey{
//		Bytes: forceHexDecode(
//			t,
//			"022d5390f276b73a544c94c12fab061e3326a3a254fd5b8dae90de7e20e26d8fcf",
//		),
//		CurveType: types.Secp256k1,
//	}
//	accountIdf, err = servicer.ConstructionDerive(ctx, &types.ConstructionDeriveRequest{
//		NetworkIdentifier: networkIdentifier,
//		PublicKey:         publicKey,
//		Metadata: map[string]interface{}{
//			"address": "0x0FCefeC5151e5dd1b2CD610f6932f005faE46cd3",
//		},
//	})
//	assert.NotNil(t, err)
//	assert.Nil(t, accountIdf)
//	assert.NotNil(t, err.Details)
//	assert.NotNil(t, err.Details["metadata"])
//	assert.Equal(t, expectedResult, err.Details["metadata"])
//
//	// Test Derive with uncompressed public key string with an address in metadata.
//	// Test when address derived from public key is matched with address input.
//	expectedResult = map[string]interface{}{
//		"accType": float64(1),
//		"account": map[string]interface{}{
//			"balance":       "0x1",
//			"humanReadable": false,
//			"key": map[string]interface{}{"keyType": float64(5), "key": []interface{}{
//				map[string]interface{}{"keyType": float64(1), "key": map[string]interface{}{}},
//				map[string]interface{}{"keyType": float64(4), "key": map[string]interface{}{
//					"threshold": 2,
//					"keys": []interface{}{
//						map[string]interface{}{
//							"weight": 1,
//							"key": map[string]interface{}{
//								"x": "0x9ca49f018f36c893ad4f3a228fb20bc7b0e53b83fe87abd6beb334d42af0cc4b",
//								"y": "0x64dc2f9e7119aea0aed72833a1e48966908e7b3f039f8dcb8116ae7a7ffc1bf1",
//							},
//						},
//						map[string]interface{}{
//							"weight": 1,
//							"key": map[string]interface{}{
//								"x": "0x82b3649a02f74e52bfd64e2785a6e93ebe690667f7bbd5934533b06b44ddfb48",
//								"y": "0x421857bf756b2d9ae2445811397ea81bd1e89e3bd64cabd1f5fe722cff23dbed",
//							},
//						},
//					},
//				}},
//				map[string]interface{}{"keyType": float64(4), "key": map[string]interface{}{
//					"threshold": 2,
//					"keys": []interface{}{
//						map[string]interface{}{
//							"weight": 1,
//							"key": map[string]interface{}{
//								"x": "0x2d5390f276b73a544c94c12fab061e3326a3a254fd5b8dae90de7e20e26d8fcf",
//								"y": "0x15299b85973d4913aead02f13c4aca4948fbe132d251df40fd1bb273e525dd7c",
//							},
//						},
//						map[string]interface{}{
//							"weight": 1,
//							"key": map[string]interface{}{
//								"x": "0xf6599e14850c33069241b9ed68dfea156f58c6d1757c72e43883587ec8ee0cb3",
//								"y": "0xc6c2547aaebc384ff359cfc3c4ad7399d7095ca4316578a2a0d6e615dd93d78",
//							},
//						},
//					},
//				}},
//			}},
//			"nonce": float64(1),
//		},
//	}
//	mockClient.On(
//		"GetAccount",
//		ctx,
//		"0x981D452f2C8F7C70Ee6521Ab9137832Fa776b003",
//		"latest",
//	).Return(expectedResult, nil).Once()
//
//	publicKey = &types.PublicKey{
//		Bytes: forceHexDecode(
//			t,
//			"e059a26740ef7bb1ccaf3e6772003ef46b5c15cecd52f5c3ab0af89a2f5156dc02a0d0e12a94345307cd1572625ce626388aaa0292233aac9e8aa87e1fd61120", // nolint: lll
//		),
//		CurveType: types.Secp256k1,
//	}
//	accountIdf, err = servicer.ConstructionDerive(ctx, &types.ConstructionDeriveRequest{
//		NetworkIdentifier: networkIdentifier,
//		PublicKey:         publicKey,
//		Metadata: map[string]interface{}{
//			"address": "0x981D452f2C8F7C70Ee6521Ab9137832Fa776b003",
//		},
//	})
//	assert.Nil(t, err)
//	assert.NotNil(t, accountIdf)
//	assert.Equal(t, accountIdf.AccountIdentifier.Address, "0x981D452f2C8F7C70Ee6521Ab9137832Fa776b003")
//	assert.NotNil(t, accountIdf.AccountIdentifier.Metadata)
//	assert.Equal(t, expectedResult, accountIdf.AccountIdentifier.Metadata)
//
//	// Test Derive with compressed public key string with an address in metadata.
//	// Test when public key is matched with public key in roleTrnasactionKey.
//	expectedResult = map[string]interface{}{
//		"accType": float64(1),
//		"account": map[string]interface{}{
//			"balance":       "0x1",
//			"humanReadable": false,
//			"key": map[string]interface{}{"keyType": float64(5), "key": []interface{}{
//				map[string]interface{}{"keyType": float64(2), "key": map[string]interface{}{
//					"x": "0x7a4036db14032238697c8ceb3f1727fdf1204cf3906914bb97ae5f8535463ea7",
//					"y": "0xc27ef21ac1230ec3cd9c0fb8f39b56c31ee0abd854e8f9492eb004774968f241",
//				}},
//				map[string]interface{}{"keyType": float64(4), "key": map[string]interface{}{
//					"threshold": 2,
//					"keys": []interface{}{
//						map[string]interface{}{
//							"weight": 1,
//							"key": map[string]interface{}{
//								"x": "0x9ca49f018f36c893ad4f3a228fb20bc7b0e53b83fe87abd6beb334d42af0cc4b",
//								"y": "0x64dc2f9e7119aea0aed72833a1e48966908e7b3f039f8dcb8116ae7a7ffc1bf1",
//							},
//						},
//						map[string]interface{}{
//							"weight": 1,
//							"key": map[string]interface{}{
//								"x": "0x82b3649a02f74e52bfd64e2785a6e93ebe690667f7bbd5934533b06b44ddfb48",
//								"y": "0x421857bf756b2d9ae2445811397ea81bd1e89e3bd64cabd1f5fe722cff23dbed",
//							},
//						},
//					},
//				}},
//				map[string]interface{}{"keyType": float64(4), "key": map[string]interface{}{
//					"threshold": 2,
//					"keys": []interface{}{
//						map[string]interface{}{
//							"weight": 1,
//							"key": map[string]interface{}{
//								"x": "0x2d5390f276b73a544c94c12fab061e3326a3a254fd5b8dae90de7e20e26d8fcf",
//								"y": "0x15299b85973d4913aead02f13c4aca4948fbe132d251df40fd1bb273e525dd7c",
//							},
//						},
//						map[string]interface{}{
//							"weight": 1,
//							"key": map[string]interface{}{
//								"x": "0xf6599e14850c33069241b9ed68dfea156f58c6d1757c72e43883587ec8ee0cb3",
//								"y": "0xc6c2547aaebc384ff359cfc3c4ad7399d7095ca4316578a2a0d6e615dd93d78",
//							},
//						},
//					},
//				}},
//			}},
//			"nonce": float64(1),
//		},
//	}
//	mockClient.On(
//		"GetAccount",
//		ctx,
//		"0x49183D2633F935806dA598072b7EF83612ce6B62",
//		"latest",
//	).Return(expectedResult, nil).Once()
//
//	// Uncompressed format is below
//	// nolint: lll
//	// 7a4036db14032238697c8ceb3f1727fdf1204cf3906914bb97ae5f8535463ea7c27ef21ac1230ec3cd9c0fb8f39b56c31ee0abd854e8f9492eb004774968f241
//	publicKey = &types.PublicKey{
//		Bytes: forceHexDecode(
//			t,
//			"037a4036db14032238697c8ceb3f1727fdf1204cf3906914bb97ae5f8535463ea7",
//		),
//		CurveType: types.Secp256k1,
//	}
//	accountIdf, err = servicer.ConstructionDerive(ctx, &types.ConstructionDeriveRequest{
//		NetworkIdentifier: networkIdentifier,
//		PublicKey:         publicKey,
//		Metadata: map[string]interface{}{
//			"address": "0x49183D2633F935806dA598072b7EF83612ce6B62",
//		},
//	})
//	assert.Nil(t, err)
//	assert.NotNil(t, accountIdf)
//	assert.Equal(t, accountIdf.AccountIdentifier.Address, "0x49183D2633F935806dA598072b7EF83612ce6B62")
//	assert.NotNil(t, accountIdf.AccountIdentifier.Metadata)
//	assert.Equal(t, expectedResult, accountIdf.AccountIdentifier.Metadata)
//
//	// Error Case Testing
//	// Test Derive with compressed public key string with an address in metadata.
//	// Test when roleTrnasactionKey is AccountKeyFail.
//	expectedResult = map[string]interface{}{
//		"accType": float64(1),
//		"account": map[string]interface{}{
//			"balance":       "0x1",
//			"humanReadable": false,
//			"key": map[string]interface{}{"keyType": float64(5), "key": []interface{}{
//				map[string]interface{}{"keyType": float64(3), "key": map[string]interface{}{}},
//				map[string]interface{}{"keyType": float64(4), "key": map[string]interface{}{
//					"threshold": 2,
//					"keys": []interface{}{
//						map[string]interface{}{
//							"weight": 1,
//							"key": map[string]interface{}{
//								"x": "0x9ca49f018f36c893ad4f3a228fb20bc7b0e53b83fe87abd6beb334d42af0cc4b",
//								"y": "0x64dc2f9e7119aea0aed72833a1e48966908e7b3f039f8dcb8116ae7a7ffc1bf1",
//							},
//						},
//						map[string]interface{}{
//							"weight": 1,
//							"key": map[string]interface{}{
//								"x": "0x82b3649a02f74e52bfd64e2785a6e93ebe690667f7bbd5934533b06b44ddfb48",
//								"y": "0x421857bf756b2d9ae2445811397ea81bd1e89e3bd64cabd1f5fe722cff23dbed",
//							},
//						},
//					},
//				}},
//				map[string]interface{}{"keyType": float64(4), "key": map[string]interface{}{
//					"threshold": 2,
//					"keys": []interface{}{
//						map[string]interface{}{
//							"weight": 1,
//							"key": map[string]interface{}{
//								"x": "0x2d5390f276b73a544c94c12fab061e3326a3a254fd5b8dae90de7e20e26d8fcf",
//								"y": "0x15299b85973d4913aead02f13c4aca4948fbe132d251df40fd1bb273e525dd7c",
//							},
//						},
//						map[string]interface{}{
//							"weight": 1,
//							"key": map[string]interface{}{
//								"x": "0xf6599e14850c33069241b9ed68dfea156f58c6d1757c72e43883587ec8ee0cb3",
//								"y": "0xc6c2547aaebc384ff359cfc3c4ad7399d7095ca4316578a2a0d6e615dd93d78",
//							},
//						},
//					},
//				}},
//			}},
//			"nonce": float64(1),
//		},
//	}
//	mockClient.On(
//		"GetAccount",
//		ctx,
//		"0xb1fCb32A0Fc9B565c237832Be1E8954bf82d57B1",
//		"latest",
//	).Return(expectedResult, nil).Once()
//
//	// Uncompressed format is below
//	// nolint: lll
//	// 7a4036db14032238697c8ceb3f1727fdf1204cf3906914bb97ae5f8535463ea7c27ef21ac1230ec3cd9c0fb8f39b56c31ee0abd854e8f9492eb004774968f241
//	publicKey = &types.PublicKey{
//		Bytes: forceHexDecode(
//			t,
//			"037a4036db14032238697c8ceb3f1727fdf1204cf3906914bb97ae5f8535463ea7",
//		),
//		CurveType: types.Secp256k1,
//	}
//	accountIdf, err = servicer.ConstructionDerive(ctx, &types.ConstructionDeriveRequest{
//		NetworkIdentifier: networkIdentifier,
//		PublicKey:         publicKey,
//		Metadata: map[string]interface{}{
//			"address": "0xb1fCb32A0Fc9B565c237832Be1E8954bf82d57B1",
//		},
//	})
//	assert.NotNil(t, err)
//	assert.Nil(t, accountIdf)
//	assert.NotNil(t, err.Details)
//	assert.NotNil(t, err.Details["metadata"])
//	assert.Equal(t, expectedResult, err.Details["metadata"])
//
//	mockClient.AssertExpectations(t)
//}
