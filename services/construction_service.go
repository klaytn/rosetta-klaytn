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
	"encoding/json"
	"fmt"
	"github.com/klaytn/klaytn/common"
	"github.com/klaytn/rosetta-klaytn/klaytn"
	"math/big"
	"strconv"

	klayTypes "github.com/klaytn/klaytn/blockchain/types"
	"github.com/klaytn/rosetta-klaytn/configuration"

	"github.com/klaytn/rosetta-sdk-go-klaytn/parser"
	"github.com/klaytn/rosetta-sdk-go-klaytn/types"
)

// ConstructionAPIService implements the server.ConstructionAPIServicer interface.
type ConstructionAPIService struct {
	config *configuration.Configuration
	client Client
}

// NewConstructionAPIService creates a new instance of a ConstructionAPIService.
func NewConstructionAPIService(
	cfg *configuration.Configuration,
	client Client,
) *ConstructionAPIService {
	return &ConstructionAPIService{
		config: cfg,
		client: client,
	}
}

// ConstructionDerive implements the /construction/derive endpoint.
func (s *ConstructionAPIService) ConstructionDerive(
	ctx context.Context,
	request *types.ConstructionDeriveRequest,
) (*types.ConstructionDeriveResponse, *types.Error) {
	return nil, ErrNotSupportedAPI
	//pubkey, err := crypto.DecompressPubkey(request.PublicKey.Bytes)
	//if err != nil {
	//	return nil, wrapErr(ErrUnableToDecompressPubkey, err)
	//}
	//
	//addr := crypto.PubkeyToAddress(*pubkey)
	//return &types.ConstructionDeriveResponse{
	//	AccountIdentifier: &types.AccountIdentifier{
	//		Address: addr.Hex(),
	//	},
	//}, nil
}

// ConstructionPreprocess implements the /construction/preprocess
// endpoint.
func (s *ConstructionAPIService) ConstructionPreprocess(
	ctx context.Context,
	request *types.ConstructionPreprocessRequest,
) (*types.ConstructionPreprocessResponse, *types.Error) {
	descriptions := &parser.Descriptions{
		OperationDescriptions: []*parser.OperationDescription{
			{
				Type: klaytn.CallOpType,
				Account: &parser.AccountDescription{
					Exists: true,
				},
				Amount: &parser.AmountDescription{
					Exists:   true,
					Sign:     parser.NegativeAmountSign,
					Currency: klaytn.Currency,
				},
			},
			{
				Type: klaytn.CallOpType,
				Account: &parser.AccountDescription{
					Exists: true,
				},
				Amount: &parser.AmountDescription{
					Exists:   true,
					Sign:     parser.PositiveAmountSign,
					Currency: klaytn.Currency,
				},
			},
		},
		ErrUnmatched: true,
	}

	matches, err := parser.MatchOperations(descriptions, request.Operations)
	if err != nil {
		return nil, wrapErr(ErrUnclearIntent, err)
	}

	fromOp, _ := matches[0].First()
	fromAdd := fromOp.Account.Address
	toOp, _ := matches[1].First()
	toAdd := toOp.Account.Address

	// Ensure valid from address
	checkFrom, ok := klaytn.ChecksumAddress(fromAdd)
	if !ok {
		return nil, wrapErr(ErrInvalidAddress, fmt.Errorf("%s is not a valid address", fromAdd))
	}

	// Ensure valid to address
	_, ok = klaytn.ChecksumAddress(toAdd)
	if !ok {
		return nil, wrapErr(ErrInvalidAddress, fmt.Errorf("%s is not a valid address", toAdd))
	}

	preprocessOutput := &options{
		From: checkFrom,
	}

	marshaled, err := marshalJSONMap(preprocessOutput)
	if err != nil {
		return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
	}

	return &types.ConstructionPreprocessResponse{
		Options: marshaled,
	}, nil
}

// ConstructionMetadata implements the /construction/metadata endpoint.
func (s *ConstructionAPIService) ConstructionMetadata(
	ctx context.Context,
	request *types.ConstructionMetadataRequest,
) (*types.ConstructionMetadataResponse, *types.Error) {
	if s.config.Mode != configuration.Online {
		return nil, ErrUnavailableOffline
	}

	var input options
	if err := unmarshalJSONMap(request.Options, &input); err != nil {
		return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
	}

	nonce, err := s.client.PendingNonceAt(ctx, common.HexToAddress(input.From))
	if err != nil {
		return nil, wrapErr(ErrKlaytnClient, err)
	}
	gasPrice, err := s.client.SuggestGasPrice(ctx)
	if err != nil {
		return nil, wrapErr(ErrKlaytnClient, err)
	}

	metadata := &metadata{
		Nonce:    nonce,
		GasPrice: gasPrice,
	}

	metadataMap, err := marshalJSONMap(metadata)
	if err != nil {
		return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
	}

	// Find suggested gas usage
	suggestedFee := metadata.GasPrice.Int64() * klaytn.TransferGasLimit

	return &types.ConstructionMetadataResponse{
		Metadata: metadataMap,
		SuggestedFee: []*types.Amount{
			{
				Value:    strconv.FormatInt(suggestedFee, 10),
				Currency: klaytn.Currency,
			},
		},
	}, nil
}

// ConstructionPayloads implements the /construction/payloads endpoint.
func (s *ConstructionAPIService) ConstructionPayloads(
	ctx context.Context,
	request *types.ConstructionPayloadsRequest,
) (*types.ConstructionPayloadsResponse, *types.Error) {
	descriptions := &parser.Descriptions{
		OperationDescriptions: []*parser.OperationDescription{
			{
				Type: klaytn.CallOpType,
				Account: &parser.AccountDescription{
					Exists: true,
				},
				Amount: &parser.AmountDescription{
					Exists:   true,
					Sign:     parser.NegativeAmountSign,
					Currency: klaytn.Currency,
				},
			},
			{
				Type: klaytn.CallOpType,
				Account: &parser.AccountDescription{
					Exists: true,
				},
				Amount: &parser.AmountDescription{
					Exists:   true,
					Sign:     parser.PositiveAmountSign,
					Currency: klaytn.Currency,
				},
			},
		},
		ErrUnmatched: true,
	}
	matches, err := parser.MatchOperations(descriptions, request.Operations)
	if err != nil {
		return nil, wrapErr(ErrUnclearIntent, err)
	}

	// Convert map to Metadata struct
	var metadata metadata
	if err := unmarshalJSONMap(request.Metadata, &metadata); err != nil {
		return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
	}

	// Required Fields for constructing a real Ethereum transaction
	toOp, amount := matches[1].First()
	toAdd := toOp.Account.Address
	nonce := metadata.Nonce
	gasPrice := metadata.GasPrice
	chainID := s.config.Params.ChainID
	transferGasLimit := uint64(klaytn.TransferGasLimit)
	transferData := []byte{}

	// Additional Fields for constructing custom Ethereum tx struct
	fromOp, _ := matches[0].First()
	fromAdd := fromOp.Account.Address

	// Ensure valid from address
	checkFrom, ok := klaytn.ChecksumAddress(fromAdd)
	if !ok {
		return nil, wrapErr(ErrInvalidAddress, fmt.Errorf("%s is not a valid address", fromAdd))
	}

	// Ensure valid to address
	checkTo, ok := klaytn.ChecksumAddress(toAdd)
	if !ok {
		return nil, wrapErr(ErrInvalidAddress, fmt.Errorf("%s is not a valid address", toAdd))
	}

	tx := klayTypes.NewTransaction(
		nonce,
		common.HexToAddress(checkTo),
		amount,
		transferGasLimit,
		gasPrice,
		transferData,
	)

	unsignedTx := &transaction{
		From:     checkFrom,
		To:       checkTo,
		Value:    amount,
		Data:     tx.Data(),
		Nonce:    tx.Nonce(),
		GasPrice: gasPrice,
		GasLimit: tx.Gas(),
		ChainID:  chainID,
	}

	// Construct SigningPayload
	signer := klayTypes.NewEIP155Signer(chainID)
	payload := &types.SigningPayload{
		AccountIdentifier: &types.AccountIdentifier{Address: checkFrom},
		Bytes:             signer.Hash(tx).Bytes(),
		SignatureType:     types.EcdsaRecovery,
	}

	unsignedTxJSON, err := json.Marshal(unsignedTx)
	if err != nil {
		return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
	}

	return &types.ConstructionPayloadsResponse{
		UnsignedTransaction: string(unsignedTxJSON),
		Payloads:            []*types.SigningPayload{payload},
	}, nil
}

// ConstructionCombine implements the /construction/combine
// endpoint.
func (s *ConstructionAPIService) ConstructionCombine(
	ctx context.Context,
	request *types.ConstructionCombineRequest,
) (*types.ConstructionCombineResponse, *types.Error) {
	var unsignedTx transaction
	if err := json.Unmarshal([]byte(request.UnsignedTransaction), &unsignedTx); err != nil {
		return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
	}

	klayTransaction := klayTypes.NewTransaction(
		unsignedTx.Nonce,
		common.HexToAddress(unsignedTx.To),
		unsignedTx.Value,
		unsignedTx.GasLimit,
		unsignedTx.GasPrice,
		unsignedTx.Data,
	)

	signer := klayTypes.NewEIP155Signer(unsignedTx.ChainID)
	signedTx, err := klayTransaction.WithSignature(signer, request.Signatures[0].Bytes)
	if err != nil {
		return nil, wrapErr(ErrSignatureInvalid, err)
	}

	signedTxJSON, err := signedTx.MarshalJSON()
	if err != nil {
		return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
	}

	return &types.ConstructionCombineResponse{
		SignedTransaction: string(signedTxJSON),
	}, nil
}

// ConstructionHash implements the /construction/hash endpoint.
func (s *ConstructionAPIService) ConstructionHash(
	ctx context.Context,
	request *types.ConstructionHashRequest,
) (*types.TransactionIdentifierResponse, *types.Error) {
	signedTx := klayTypes.Transaction{}
	if err := signedTx.UnmarshalJSON([]byte(request.SignedTransaction)); err != nil {
		return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
	}

	hash := signedTx.Hash().Hex()

	return &types.TransactionIdentifierResponse{
		TransactionIdentifier: &types.TransactionIdentifier{
			Hash: hash,
		},
	}, nil
}

// ConstructionParse implements the /construction/parse endpoint.
func (s *ConstructionAPIService) ConstructionParse(
	ctx context.Context,
	request *types.ConstructionParseRequest,
) (*types.ConstructionParseResponse, *types.Error) {
	var tx transaction
	if !request.Signed {
		err := json.Unmarshal([]byte(request.Transaction), &tx)
		if err != nil {
			return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
		}
	} else {
		t := new(klayTypes.Transaction)
		err := t.UnmarshalJSON([]byte(request.Transaction))
		if err != nil {
			return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
		}

		tx.To = t.To().String()
		tx.Value = t.Value()
		tx.Data = t.Data()
		tx.Nonce = t.Nonce()
		tx.GasPrice = t.GasPrice()
		tx.GasLimit = t.Gas()
		tx.ChainID = t.ChainId()

		var fromAddress common.Address
		if t.IsEthereumTransaction() {
			signer := klayTypes.LatestSignerForChainID(t.ChainId())
			fromAddress, err = klayTypes.Sender(signer, t)
		} else {
			fromAddress, err = t.From()
		}
		if err != nil {
			return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
		}

		tx.From = fromAddress.String()
	}

	// Ensure valid from address
	checkFrom, ok := klaytn.ChecksumAddress(tx.From)
	if !ok {
		return nil, wrapErr(ErrInvalidAddress, fmt.Errorf("%s is not a valid address", tx.From))
	}

	// Ensure valid to address
	checkTo, ok := klaytn.ChecksumAddress(tx.To)
	if !ok {
		return nil, wrapErr(ErrInvalidAddress, fmt.Errorf("%s is not a valid address", tx.To))
	}

	ops := []*types.Operation{
		{
			Type: klaytn.CallOpType,
			OperationIdentifier: &types.OperationIdentifier{
				Index: 0,
			},
			Account: &types.AccountIdentifier{
				Address: checkFrom,
			},
			Amount: &types.Amount{
				Value:    new(big.Int).Neg(tx.Value).String(),
				Currency: klaytn.Currency,
			},
		},
		{
			Type: klaytn.CallOpType,
			OperationIdentifier: &types.OperationIdentifier{
				Index: 1,
			},
			RelatedOperations: []*types.OperationIdentifier{
				{
					Index: 0,
				},
			},
			Account: &types.AccountIdentifier{
				Address: checkTo,
			},
			Amount: &types.Amount{
				Value:    tx.Value.String(),
				Currency: klaytn.Currency,
			},
		},
	}

	metadata := &parseMetadata{
		Nonce:    tx.Nonce,
		GasPrice: tx.GasPrice,
		ChainID:  tx.ChainID,
	}
	metaMap, err := marshalJSONMap(metadata)
	if err != nil {
		return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
	}

	var resp *types.ConstructionParseResponse
	if request.Signed {
		resp = &types.ConstructionParseResponse{
			Operations: ops,
			AccountIdentifierSigners: []*types.AccountIdentifier{
				{
					Address: checkFrom,
				},
			},
			Metadata: metaMap,
		}
	} else {
		resp = &types.ConstructionParseResponse{
			Operations:               ops,
			AccountIdentifierSigners: []*types.AccountIdentifier{},
			Metadata:                 metaMap,
		}
	}
	return resp, nil
}

// ConstructionSubmit implements the /construction/submit endpoint.
func (s *ConstructionAPIService) ConstructionSubmit(
	ctx context.Context,
	request *types.ConstructionSubmitRequest,
) (*types.TransactionIdentifierResponse, *types.Error) {
	if s.config.Mode != configuration.Online {
		return nil, ErrUnavailableOffline
	}

	var signedTx klayTypes.Transaction
	if err := signedTx.UnmarshalJSON([]byte(request.SignedTransaction)); err != nil {
		return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
	}

	if err := s.client.SendTransaction(ctx, &signedTx); err != nil {
		return nil, wrapErr(ErrBroadcastFailed, err)
	}

	txIdentifier := &types.TransactionIdentifier{
		Hash: signedTx.Hash().Hex(),
	}
	return &types.TransactionIdentifierResponse{
		TransactionIdentifier: txIdentifier,
	}, nil
}
