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
	"encoding/hex"
	klayTypes "github.com/klaytn/klaytn/blockchain/types"
	"github.com/klaytn/klaytn/common/hexutil"
	"github.com/klaytn/klaytn/crypto"
	"github.com/klaytn/rosetta-klaytn/configuration"
	"github.com/klaytn/rosetta-klaytn/klaytn"
	"github.com/klaytn/rosetta-sdk-go-klaytn/types"
	"github.com/stretchr/testify/assert"
	"math/big"
	"strconv"
	"strings"
	"testing"
)

var (
	operations          []*types.Operation
	metadata            map[string]interface{}
	suggestedFee        *types.Amount
	unsignedTransaction string
	signedTransaction   string
	payloads            *types.SigningPayload
)

// Test /construction/derive
func TestConstructionDerive(t *testing.T) {
	initTestValues(t)
	defer c.Close()

	// Test construction service under offline mode
	cfg.Mode = configuration.Offline

	expectedAddress := "0x1D41e2b162ED86b4c7efDBdA12cd36391d17BE36"
	pubKey, err := hex.DecodeString("03f557fe349fec4c29b4f18b8544cc670c6c1b33bdae2f91f98166d0cd16270ce2")
	assert.Nil(t, err)
	ctx := context.Background()
	req := &types.ConstructionDeriveRequest{
		NetworkIdentifier: networkIdf,
		PublicKey: &types.PublicKey{
			Bytes: pubKey,
		},
	}
	res, tErr := constructionAPIService.ConstructionDerive(ctx, req)
	assert.Nil(t, tErr)
	assert.NotNil(t, res)
	assert.Equal(t, res.AccountIdentifier.Address, expectedAddress)

	pubKey, err = hex.DecodeString("f557fe349fec4c29b4f18b8544cc670c6c1b33bdae2f91f98166d0cd16270ce204b62ba0ae9f726519d546083cc849e5b8c762b0e21306788b71acda4e3b2ae9")
	assert.Nil(t, err)
	req.PublicKey.Bytes = pubKey
	res, tErr = constructionAPIService.ConstructionDerive(ctx, req)
	assert.Nil(t, tErr)
	assert.NotNil(t, res)
	assert.Equal(t, res.AccountIdentifier.Address, expectedAddress)
}

// Test /construction/derive with invalid public key
func TestConstructionDeriveInvalidPublicKey(t *testing.T) {
	initTestValues(t)
	defer c.Close()

	// Test construction service under offline mode
	cfg.Mode = configuration.Offline

	// Invalid length
	pubKey, err := hex.DecodeString("03f557fe349fec4c29b4f18b8544cc670c6c1b33bdaf91f98166d0cd16270ce2")
	assert.Nil(t, err)
	ctx := context.Background()
	req := &types.ConstructionDeriveRequest{
		NetworkIdentifier: networkIdf,
		PublicKey: &types.PublicKey{
			Bytes: pubKey,
		},
	}
	res, tErr := constructionAPIService.ConstructionDerive(ctx, req)
	assert.NotNil(t, tErr)
	assert.Nil(t, res)
	expectedMsg := "public key is invalid"
	assert.True(t, strings.Contains(tErr.Message, expectedMsg))

	// Invalid public key
	pubKey, err = hex.DecodeString("08f557fe349fec4c29b4f18b8544cc670c6c1b33bdaf91f98166d0cd16270ce212")
	assert.Nil(t, err)
	req.PublicKey.Bytes = pubKey
	res, tErr = constructionAPIService.ConstructionDerive(ctx, req)
	assert.NotNil(t, tErr)
	assert.Nil(t, res)
	expectedMsg = "unable to decompress public key"
	assert.True(t, strings.Contains(tErr.Message, expectedMsg))
}

// Test /construction/preprocess
func TestConstructionPreprocess(t *testing.T) {
	initTestValues(t)
	defer c.Close()

	// Test construction service under offline mode
	cfg.Mode = configuration.Offline

	setDefaultOperations(t)
	req := &types.ConstructionPreprocessRequest{
		NetworkIdentifier: networkIdf,
		Operations:        operations,
	}
	ctx := context.Background()
	res, tErr := constructionAPIService.ConstructionPreprocess(ctx, req)
	assert.Nil(t, tErr)
	assert.NotNil(t, res)
	assert.Equal(t, res.Options["from"].(string), testAccount.Addr.Hex())
}

// Test /construction/preprocess with invalid operation
func TestConstructionPreprocessInvalidOps(t *testing.T) {
	initTestValues(t)
	defer c.Close()

	// Test construction service under offline mode
	cfg.Mode = configuration.Offline

	ops := []*types.Operation{}
	req := &types.ConstructionPreprocessRequest{
		NetworkIdentifier: networkIdf,
		Operations:        ops,
	}
	ctx := context.Background()
	res, tErr := constructionAPIService.ConstructionPreprocess(ctx, req)
	assert.NotNil(t, tErr)
	assert.Nil(t, res)
	expectedMsg := "unable to match anything to 0 operations"
	assert.True(t, strings.Contains(tErr.Details["context"].(string), expectedMsg))

	// There is no negative value operation
	setDefaultOperations(t)
	ops = operations
	ops[0].Amount.Value = "1"
	ops[1].Amount.Value = "1"

	req = &types.ConstructionPreprocessRequest{
		NetworkIdentifier: networkIdf,
		Operations:        ops,
	}
	res, tErr = constructionAPIService.ConstructionPreprocess(ctx, req)
	assert.NotNil(t, tErr)
	assert.Nil(t, res)
	expectedMsg = "unable to find match for operation"
	assert.True(t, strings.Contains(tErr.Details["context"].(string), expectedMsg))

	// There is no positive value operation
	ops[0].Amount.Value = "-1"
	ops[1].Amount.Value = "-1"

	req = &types.ConstructionPreprocessRequest{
		NetworkIdentifier: networkIdf,
		Operations:        ops,
	}
	res, tErr = constructionAPIService.ConstructionPreprocess(ctx, req)
	assert.NotNil(t, tErr)
	assert.Nil(t, res)
	expectedMsg = "unable to find match for operation"
	assert.True(t, strings.Contains(tErr.Details["context"].(string), expectedMsg))
}

// Test /construction/metadata
func TestConstructionMetadata(t *testing.T) {
	initTestValues(t)
	defer c.Close()

	// metadata can be served only in online mode
	cfg.Mode = configuration.Online

	// The value filled in the `Options` field is the result of Preprocess.
	req := &types.ConstructionMetadataRequest{
		NetworkIdentifier: networkIdf,
		Options: map[string]interface{}{
			"from": testAccount.Addr.Hex(),
		},
	}
	ctx := context.Background()
	res, tErr := constructionAPIService.ConstructionMetadata(ctx, req)
	n, err := strconv.ParseUint(strings.Replace(res.Metadata["nonce"].(string), "0x", "", 1), 16, 64)
	assert.Nil(t, err)
	gp, ok := new(big.Int).SetString(strings.Replace(res.Metadata["gas_price"].(string), "0x", "", 1), 16)
	assert.True(t, ok)
	assert.Nil(t, tErr)
	assert.NotNil(t, res)

	expectedUnitPrice := new(big.Int).SetUint64(cfg.Params.UnitPrice)
	transferGasLimit := new(big.Int).SetInt64(klaytn.TransferGasLimit)
	assert.True(t, n > 0)
	assert.Equal(t, gp, expectedUnitPrice)
	assert.Equal(t, res.SuggestedFee[0].Value, new(big.Int).Mul(expectedUnitPrice, transferGasLimit).String())
	assert.Equal(t, res.SuggestedFee[0].Currency.Symbol, "KLAY")
	assert.Equal(t, res.SuggestedFee[0].Currency.Decimals, int32(18))

	metadata = res.Metadata
	suggestedFee = res.SuggestedFee[0]
}

// Test /construction/metadata with offline mode or invalid data
func TestConstructionMetadataInvalidModeOrData(t *testing.T) {
	initTestValues(t)
	defer c.Close()

	// Test construction service under offline mode
	cfg.Mode = configuration.Offline

	// The `Options` field is what
	req := &types.ConstructionMetadataRequest{
		NetworkIdentifier: networkIdf,
		Options: map[string]interface{}{
			"from": testAccount.Addr.Hex(),
		},
	}
	ctx := context.Background()
	res, tErr := constructionAPIService.ConstructionMetadata(ctx, req)
	assert.NotNil(t, tErr)
	assert.Nil(t, res)
	expectedMsg := "Endpoint unavailable offline"
	assert.True(t, strings.Contains(tErr.Message, expectedMsg))

	cfg.Mode = configuration.Online

	// The `Options` field is what
	req = &types.ConstructionMetadataRequest{
		NetworkIdentifier: networkIdf,
		Options:           map[string]interface{}{},
	}
	res, tErr = constructionAPIService.ConstructionMetadata(ctx, req)
	assert.NotNil(t, tErr)
	assert.Nil(t, res)
	expectedMsg = "from address is invalid"
	assert.True(t, strings.Contains(tErr.Message, expectedMsg))
}

// Test /construction/payloads
func TestConstructionPayloads(t *testing.T) {
	initTestValues(t)
	defer c.Close()

	setDefaultOperations(t)
	setMetadataAndSuggestedFee(t)

	// Test construction service under offline mode
	cfg.Mode = configuration.Offline

	req := &types.ConstructionPayloadsRequest{
		NetworkIdentifier: networkIdf,
		Operations:        operations,
		Metadata:          metadata,
	}
	ctx := context.Background()
	res, tErr := constructionAPIService.ConstructionPayloads(ctx, req)
	assert.Nil(t, tErr)
	assert.NotNil(t, res)
	assert.True(t, strings.Contains(res.UnsignedTransaction, testAccount.Addr.Hex()))
	assert.True(t, strings.Contains(res.UnsignedTransaction, receiver.Addr.Hex()))
	assert.Equal(t, res.Payloads[0].AccountIdentifier.Address, testAccount.Addr.Hex())
	assert.NotNil(t, res.Payloads[0].Bytes)
	assert.Equal(t, res.Payloads[0].SignatureType, types.EcdsaRecovery)

	unsignedTransaction = res.UnsignedTransaction
	payloads = res.Payloads[0]
}

// Test /construction/payloads with invalid data
func TestConstructionPayloadsWithInvalidData(t *testing.T) {
	initTestValues(t)
	defer c.Close()

	setDefaultOperations(t)
	setMetadataAndSuggestedFee(t)

	// Test construction service under offline mode
	cfg.Mode = configuration.Offline

	req := &types.ConstructionPayloadsRequest{
		NetworkIdentifier: networkIdf,
		Operations:        operations,
		Metadata: map[string]interface{}{
			"nonce":     "invalidNonce",
			"gas_price": "invalid gas",
		},
	}
	ctx := context.Background()
	res, tErr := constructionAPIService.ConstructionPayloads(ctx, req)
	assert.NotNil(t, tErr)
	assert.Nil(t, res)
	expectedMsg := "Unable to parse intermediate result"
	assert.True(t, strings.Contains(tErr.Message, expectedMsg))
}

// Test /construction/combine
func TestConstructionCombine(t *testing.T) {
	initTestValues(t)
	defer c.Close()

	getUnsignedTx(t)

	// Test construction service under offline mode
	cfg.Mode = configuration.Offline

	// Have to sign a txhash
	sig, err := crypto.Sign(payloads.Bytes[:], testAccount.Key[0])
	assert.Nil(t, err)

	req := &types.ConstructionCombineRequest{
		NetworkIdentifier:   networkIdf,
		UnsignedTransaction: unsignedTransaction,
		Signatures: []*types.Signature{
			&types.Signature{
				SigningPayload: payloads,
				PublicKey: &types.PublicKey{
					Bytes: crypto.CompressPubkey(&testAccount.Key[0].PublicKey),
				},
				SignatureType: types.EcdsaRecovery,
				Bytes:         sig,
			},
		},
	}
	ctx := context.Background()
	res, tErr := constructionAPIService.ConstructionCombine(ctx, req)
	assert.Nil(t, tErr)
	assert.NotNil(t, res)
	assert.NotEqual(t, res.SignedTransaction, "")
}

// Test /construction/combine with invalid unsigned tx
func TestConstructionCombineWithInvalidUnsignedTx(t *testing.T) {
	initTestValues(t)
	defer c.Close()

	getUnsignedTx(t)

	// Test construction service under offline mode
	cfg.Mode = configuration.Offline

	req := &types.ConstructionCombineRequest{
		NetworkIdentifier:   networkIdf,
		UnsignedTransaction: "",
		Signatures: []*types.Signature{
			&types.Signature{
				SigningPayload: payloads,
				PublicKey: &types.PublicKey{
					Bytes: crypto.CompressPubkey(&testAccount.Key[0].PublicKey),
				},
				SignatureType: types.EcdsaRecovery,
				Bytes:         make([]byte, 65),
			},
		},
	}
	ctx := context.Background()
	res, tErr := constructionAPIService.ConstructionCombine(ctx, req)
	assert.NotNil(t, tErr)
	assert.Nil(t, res)
	expectedMsg := "Unable to parse intermediate result"
	assert.True(t, strings.Contains(tErr.Message, expectedMsg))
}

// Test /construction/parse
func TestConstructionParse(t *testing.T) {
	initTestValues(t)
	defer c.Close()

	getSignedTx(t)

	// Test construction service under offline mode
	cfg.Mode = configuration.Offline

	// Parse signed tx
	req := &types.ConstructionParseRequest{
		NetworkIdentifier: networkIdf,
		Signed:            true,
		Transaction:       signedTransaction,
	}
	ctx := context.Background()
	res, tErr := constructionAPIService.ConstructionParse(ctx, req)
	assert.Nil(t, tErr)
	assert.NotNil(t, res)
	assert.True(t, len(res.AccountIdentifierSigners) > 0)
	assert.Equal(t, len(res.Operations), len(operations))
	assert.Equal(t, res.Metadata["nonce"], metadata["nonce"])
	assert.Equal(t, res.Metadata["gas_price"], metadata["gas_price"])
	assert.Equal(t, res.Metadata["chain_id"].(string), hexutil.EncodeBig(cfg.Params.ChainID))

	// Parse unsigned tx
	req = &types.ConstructionParseRequest{
		NetworkIdentifier: networkIdf,
		Signed:            false,
		Transaction:       unsignedTransaction,
	}
	res, tErr = constructionAPIService.ConstructionParse(ctx, req)
	assert.Nil(t, tErr)
	assert.NotNil(t, res)
	assert.True(t, len(res.AccountIdentifierSigners) == 0)
	assert.Equal(t, len(res.Operations), len(operations))
	assert.Equal(t, res.Metadata["nonce"], metadata["nonce"])
	assert.Equal(t, res.Metadata["gas_price"], metadata["gas_price"])
	assert.Equal(t, res.Metadata["chain_id"].(string), hexutil.EncodeBig(cfg.Params.ChainID))
}

// Test /construction/submit
func TestConstructionSubmit(t *testing.T) {
	initTestValues(t)
	defer c.Close()

	getSignedTx(t)

	// Test construction submit can be served only in online mode
	cfg.Mode = configuration.Online

	// Submit signed tx
	req := &types.ConstructionSubmitRequest{
		NetworkIdentifier: networkIdf,
		SignedTransaction: signedTransaction,
	}
	ctx := context.Background()
	res, tErr := constructionAPIService.ConstructionSubmit(ctx, req)
	assert.Nil(t, tErr)
	assert.NotNil(t, res)

	tx := new(klayTypes.Transaction)
	err = tx.UnmarshalJSON([]byte(signedTransaction))
	assert.Nil(t, err)
	assert.Equal(t, res.TransactionIdentifier.Hash, tx.Hash().Hex())
}

func getUnsignedTx(t *testing.T) {
	setDefaultOperations(t)
	setMetadataAndSuggestedFee(t)

	cfg.Mode = configuration.Offline

	req := &types.ConstructionPayloadsRequest{
		NetworkIdentifier: networkIdf,
		Operations:        operations,
		Metadata:          metadata,
	}
	ctx := context.Background()
	res, tErr := constructionAPIService.ConstructionPayloads(ctx, req)
	assert.Nil(t, tErr)

	unsignedTransaction = res.UnsignedTransaction
	payloads = res.Payloads[0]
}

func getSignedTx(t *testing.T) {
	// Set unsignedTransaction and payloads
	getUnsignedTx(t)

	cfg.Mode = configuration.Offline

	// Sign to the tx
	sig, err := crypto.Sign(payloads.Bytes[:], testAccount.Key[0])
	assert.Nil(t, err)

	req := &types.ConstructionCombineRequest{
		NetworkIdentifier:   networkIdf,
		UnsignedTransaction: unsignedTransaction,
		Signatures: []*types.Signature{
			&types.Signature{
				SigningPayload: payloads,
				PublicKey: &types.PublicKey{
					Bytes: crypto.CompressPubkey(&testAccount.Key[0].PublicKey),
				},
				SignatureType: types.EcdsaRecovery,
				Bytes:         sig,
			},
		},
	}
	ctx := context.Background()
	res, tErr := constructionAPIService.ConstructionCombine(ctx, req)
	assert.Nil(t, tErr)

	signedTransaction = res.SignedTransaction
}

func setDefaultOperations(t *testing.T) {
	operations = []*types.Operation{
		&types.Operation{
			OperationIdentifier: &types.OperationIdentifier{Index: 0},
			Type:                klaytn.CallOpType,
			Status:              types.String(klaytn.SuccessStatus),
			Account:             &types.AccountIdentifier{Address: testAccount.Addr.Hex()},
			Amount:              &types.Amount{Value: "-1", Currency: &types.Currency{Symbol: "KLAY", Decimals: 18}},
		},
		&types.Operation{
			OperationIdentifier: &types.OperationIdentifier{Index: 1},
			Type:                klaytn.CallOpType,
			Status:              types.String(klaytn.SuccessStatus),
			Account:             &types.AccountIdentifier{Address: receiver.Addr.Hex()},
			Amount:              &types.Amount{Value: "1", Currency: &types.Currency{Symbol: "KLAY", Decimals: 18}},
		},
	}
}

func setMetadataAndSuggestedFee(t *testing.T) {
	cfg.Mode = configuration.Online

	req := &types.ConstructionMetadataRequest{
		NetworkIdentifier: networkIdf,
		Options: map[string]interface{}{
			"from": testAccount.Addr.Hex(),
		},
	}
	ctx := context.Background()
	res, tErr := constructionAPIService.ConstructionMetadata(ctx, req)
	assert.Nil(t, tErr)
	metadata = res.Metadata
	suggestedFee = res.SuggestedFee[0]

	cfg.Mode = configuration.Offline
}
