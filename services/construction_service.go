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
// Modified and improved for the Klaytn development.

package services

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"

	"github.com/klaytn/klaytn/common"
	"github.com/klaytn/klaytn/crypto"
	"github.com/klaytn/rosetta-klaytn/klaytn"

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
	// When pubKey is compressed public key format that starts with 0x02 or 0x03,
	// get ecdsa public key from byte array like below.
	var pubKey *ecdsa.PublicKey
	var err error
	switch len(request.PublicKey.Bytes) {
	case 33: // nolint: gomnd
		pubKey, err = crypto.DecompressPubkey(request.PublicKey.Bytes)
		if err != nil {
			return nil, wrapErr(ErrUnableToDecompressPubkey, err)
		}
	case 64: // nolint: gomnd
		// When pubKey is uncompressed public key format,
		// get ecdsa public key from byte array like below.
		pubKey = &ecdsa.PublicKey{
			X: new(big.Int).SetBytes(request.PublicKey.Bytes[:32]),
			Y: new(big.Int).SetBytes(request.PublicKey.Bytes[32:]),
		}
	default:
		return nil, ErrInvalidPubKey
	}

	addr := crypto.PubkeyToAddress(*pubKey)
	return &types.ConstructionDeriveResponse{
		AccountIdentifier: &types.AccountIdentifier{
			Address: addr.Hex(),
		},
	}, nil
	// // We cannot serve /construction/derive
	// // because we need to get account info from Klaytn Node.
	// if s.config.Mode != configuration.Online {
	// 	return nil, ErrUnavailableOffline
	// }
	//
	// var addr string
	// var tErr error
	// var ok bool
	// derived := false
	// // User can send an address string in metadata.
	// // If user do not send address via metadata, then derive an address from the public key.
	// // If an address is existed in metadata, then get account info from Klaytn
	// // to compare the public key parameter and the public key in the Klaytn account.
	// if request.Metadata == nil {
	// 	addr, tErr = derivedAddress(request.PublicKey.Bytes)
	// 	if tErr != nil {
	// 		return nil, wrapErr(ErrDeriveAddress, tErr)
	// 	}
	// 	derived = true
	// } else {
	// 	addr, ok = request.Metadata["address"].(string)
	// 	if !ok {
	// 		return nil, ErrExtractAddress
	// 	}
	// }
	//
	// // Get a Klaytn account to get account key.
	// acct, err := s.client.GetAccount(ctx, addr, "latest")
	// if err != nil {
	// 	return nil, wrapErrWithMetadata(ErrGetAccountAPI, acct, err)
	// }
	// if acct == nil {
	// 	// "acct == nil" means that Klaytn does not have any state with that account.
	// 	// So we need to proceed derive process with default account that has AccountKeyLegacy.
	// 	acct = map[string]interface{}{
	// 		"accType": float64(1),
	// 		"account": map[string]interface{}{
	// 			"balance":       "0x0",
	// 			"humanReadable": false,
	// 			"key":           map[string]interface{}{"keyType": float64(1), "key": map[string]interface{}{}},
	// 			"nonce":         float64(0),
	// 		},
	// 	}
	// }
	//
	// // The Klaytn account returned from client format is below.
	// // {
	// // 	 accType: 1,
	// // 	 account: {
	// // 		 balance: 49853...,
	// // 		 humanReadable: false,
	// // 		 key: {
	// // 			 keyType: 2,
	// // 			 key: { x: "0x23003...",  y: "0x18a7f..." },
	// // 		 },
	// // 		 nonce: 11
	// // 	 }
	// // }
	// var accType float64
	// if accType, ok = acct["accType"].(float64); !ok {
	// 	return nil, wrapErrWithMetadata(ErrGetAccountAPI, acct, nil)
	// }
	// // If account is not Legacy Account or External Owned Account type,
	// // then throw an error.
	// // See https://docs.klaytn.com/klaytn/design/accounts#klaytn-account-types
	// if accType > float64(1) {
	// 	return nil, wrapErrWithMetadata(ErrAccountType, acct, nil)
	// }
	//
	// var accountMap map[string]interface{}
	// if accountMap, ok = acct["account"].(map[string]interface{}); !ok {
	// 	return nil, wrapErrWithMetadata(ErrGetAccountAPI, acct, nil)
	// }
	// var keyMap map[string]interface{}
	// if keyMap, ok = accountMap["key"].(map[string]interface{}); !ok {
	// 	return nil, wrapErrWithMetadata(ErrGetAccountAPI, acct, nil)
	// }
	// var keyType float64
	// if keyType, ok = keyMap["keyType"].(float64); !ok {
	// 	return nil, wrapErrWithMetadata(ErrGetAccountAPI, acct, nil)
	// }
	//
	// // Make an account identifier with the account returned by client in Metadata field.
	// identifier := types.AccountIdentifier{
	// 	Address:  addr,
	// 	Metadata: acct,
	// }
	//
	// typedError := validatePubKeyForKeyTypes(addr, keyMap, keyType, derived, request.PublicKey.Bytes, acct)
	// if typedError != nil {
	// 	return nil, typedError
	// }
	//
	// return &types.ConstructionDeriveResponse{
	// 	AccountIdentifier: &identifier,
	// }, nil
}

// // validatePubKeyForKeyTypes validates public key byte array received by user as a parameter
// // depends on key type of the Klaytn account.
// func validatePubKeyForKeyTypes(
// 	addr string,
// 	keyMap map[string]interface{},
// 	keyType float64,
// 	derived bool,
// 	pubKey []byte,
// 	acct map[string]interface{},
// ) *types.Error {
// 	var ok bool
// 	// AccountKeyLegacy				0x01
// 	// AccountKeyPublic				0x02
// 	// AccountKeyFail				0x03
// 	// AccountKeyWeightedMultiSig	0x04
// 	// AccountKeyRoleBased			0x05
// 	switch keyType {
// 	case float64(accountkey.AccountKeyTypeLegacy):
// 		// AccountKeyLegacy: compare the address with a derived address
// 		if !derived {
// 			derivedAddr, err := derivedAddress(pubKey)
// 			if err != nil {
// 				return wrapErrWithMetadata(ErrDeriveAddress, acct, err)
// 			}
// 			if derivedAddr != addr {
// 				return wrapErrWithMetadata(ErrDerivedAddrNotMatched, acct, nil)
// 			}
// 		}
// 	case float64(accountkey.AccountKeyTypePublic):
// 		// AccountKeyPublic: compare public key
// 		isSame, err := comparePublicKey(keyMap, pubKey)
// 		if err != nil {
// 			return wrapErrWithMetadata(err, acct, nil)
// 		}
// 		if !isSame {
// 			return wrapErrWithMetadata(ErrDiffPubKey, acct, nil)
// 		}
// 	case float64(accountkey.AccountKeyTypeFail):
// 		// AccountKeyFail: return an error
// 		return wrapErrWithMetadata(ErrAccountKeyFail, acct, nil)
// 	case float64(accountkey.AccountKeyTypeWeightedMultiSig):
// 		// AccountKeyWeightedMultiSig: check whether include the public key or not.
// 		isInclude, err := checkIncludePublicKey(keyMap, pubKey)
// 		if err != nil {
// 			return wrapErrWithMetadata(err, acct, nil)
// 		}
// 		if !isInclude {
// 			return wrapErrWithMetadata(ErrMultiSigNotIncludePubKey, acct, nil)
// 		}
// 	case float64(accountkey.AccountKeyTypeRoleBased):
// 		// AccountKeyRoleBased: check whether RoleTransactionKey includes the public key or not.
// 		var roleKeyArr []interface{}
// 		if roleKeyArr, ok = keyMap["key"].([]interface{}); !ok {
// 			return wrapErrWithMetadata(ErrGetAccountAPI, acct, nil)
// 		}
// 		roleTransactionKeyMap := roleKeyArr[0].(map[string]interface{})
//
// 		var roleTransactionKeyType float64
// 		if roleTransactionKeyType, ok = roleTransactionKeyMap["keyType"].(float64); !ok {
// 			return wrapErrWithMetadata(ErrGetAccountAPI, acct, nil)
// 		}
// 		err := validatePubKeyForKeyTypes(addr, roleTransactionKeyMap, roleTransactionKeyType, derived, pubKey, acct)
// 		if err != nil {
// 			return wrapErrWithMetadata(err, acct, nil)
// 		}
// 	}
// 	return nil
// }
//
// // checkIncludePublicKey checks whether key object includes specific public key(byte array input)
// func checkIncludePublicKey(keyObj map[string]interface{}, pubKey []byte) (bool, *types.Error) {
// 	var keyMap map[string]interface{}
// 	var ok bool
// 	if keyMap, ok = keyObj["key"].(map[string]interface{}); !ok {
// 		return false, ErrGetAccountAPI
// 	}
// 	var keyArr []interface{}
// 	if keyArr, ok = keyMap["keys"].([]interface{}); !ok {
// 		return false, ErrGetAccountAPI
// 	}
// 	for _, k := range keyArr {
// 		isSame, err := comparePublicKey(k.(map[string]interface{}), pubKey)
// 		if isSame || err != nil {
// 			return isSame, err
// 		}
// 	}
// 	return false, nil
// }
//
// // comparePublicKey compares xy point in the key object and public key byte array
// func comparePublicKey(keyObj map[string]interface{}, pubKey []byte) (bool, *types.Error) {
// 	var x, y string
// 	// When pubKey is compressed public key format that starts with 0x02 or 0x03,
// 	// get ecdsa public key from byte array like below.
// 	if len(pubKey) == 33 { // nolint: gomnd
// 		ecdsaPub, err := crypto.DecompressPubkey(pubKey)
// 		if err != nil {
// 			return false, wrapErr(ErrUnableToDecompressPubkey, err)
// 		}
// 		publicKey := accountkey.NewAccountKeyPublicWithValue(ecdsaPub)
// 		x = (*hexutil.Big)(publicKey.X).String()
// 		y = (*hexutil.Big)(publicKey.Y).String()
// 	} else {
// 		// When pubKey is uncompressed public key format,
// 		// get ecdsa public key from byte array like below.
// 		x = hexutil.Encode(pubKey[:32])
// 		y = hexutil.Encode(pubKey[32:])
// 	}
//
// 	// Get ecdsa public key from xy point.
// 	var xyPoint map[string]interface{}
// 	var ok bool
// 	if xyPoint, ok = keyObj["key"].(map[string]interface{}); !ok {
// 		return false, ErrGetAccountAPI
// 	}
// 	var xString, yString string
// 	if xString, ok = xyPoint["x"].(string); !ok {
// 		return false, ErrGetAccountAPI
// 	}
// 	if yString, ok = xyPoint["y"].(string); !ok {
// 		return false, ErrGetAccountAPI
// 	}
// 	// Format with leading zeros
// 	xString = "0x" + fmt.Sprintf("%064s", strings.Replace(xString, "0x", "", 1))
// 	yString = "0x" + fmt.Sprintf("%064s", strings.Replace(yString, "0x", "", 1))
// 	if x != xString || y != yString {
// 		return false, nil
// 	}
// 	return true, nil
// }
//
// // derivedAddress returns derived address string
// func derivedAddress(publicKey []byte) (string, error) {
// 	var pubkey *ecdsa.PublicKey
// 	var err error
// 	// Compressed public key byte array
// 	if len(publicKey) == 33 { // nolint: gomnd
// 		pubkey, err = crypto.DecompressPubkey(publicKey)
// 		if err != nil {
// 			return "", err
// 		}
// 	} else {
// 		pubkey = &ecdsa.PublicKey{
// 			X:     new(big.Int).SetBytes(publicKey[:32]),
// 			Y:     new(big.Int).SetBytes(publicKey[32:]),
// 			Curve: crypto.S256(),
// 		}
// 	}
//
// 	addr := crypto.PubkeyToAddress(*pubkey)
// 	return addr.Hex(), nil
// }

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

	if input.From == "" {
		return nil, ErrInvalidFrom
	}

	// If address is not in 0x hex prefixed string, return an error.
	if !common.IsHexAddress(input.From) {
		return nil, ErrInvalidFrom
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
				Value:    strconv.FormatInt(suggestedFee, 10), // nolint:gomnd
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

	// Required Fields for constructing a real Klaytn transaction
	toOp, amount := matches[1].First()
	toAdd := toOp.Account.Address
	nonce := metadata.Nonce
	gasPrice := metadata.GasPrice
	chainID := s.config.Params.ChainID
	transferGasLimit := uint64(klaytn.TransferGasLimit)
	transferData := []byte{}

	// Additional Fields for constructing custom Klaytn tx struct
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
