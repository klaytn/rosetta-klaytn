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
	"github.com/klaytn/rosetta-sdk-go-klaytn/types"
)

var (
	// Errors contains all errors that could be returned
	// by this Rosetta implementation.
	Errors = []*types.Error{
		ErrUnimplemented,
		ErrUnavailableOffline,
		ErrKlaytnClient,
		ErrUnableToDecompressPubkey,
		ErrUnclearIntent,
		ErrUnableToParseIntermediateResult,
		ErrSignatureInvalid,
		ErrBroadcastFailed,
		ErrCallParametersInvalid,
		ErrCallOutputMarshal,
		ErrCallMethodInvalid,
		ErrInvalidAddress,
		ErrKlaytnClientNotReady,
		ErrInvalidInput,
	}

	// ErrUnimplemented is returned when an endpoint
	// is called that is not implemented.
	ErrUnimplemented = &types.Error{
		Code:    0, //nolint
		Message: "Endpoint not implemented",
	}

	// ErrUnavailableOffline is returned when an endpoint
	// is called that is not available offline.
	ErrUnavailableOffline = &types.Error{
		Code:    1, //nolint
		Message: "Endpoint unavailable offline",
	}

	// ErrKlaytnClient is returned when Klaytn Node
	// errors on a request.
	ErrKlaytnClient = &types.Error{
		Code:    2, //nolint
		Message: "klaytn client error",
	}

	// ErrUnableToDecompressPubkey is returned when
	// the *types.PublicKey provided in /construction/derive
	// cannot be decompressed.
	ErrUnableToDecompressPubkey = &types.Error{
		Code:    3, //nolint
		Message: "unable to decompress public key",
	}

	// ErrUnclearIntent is returned when operations
	// provided in /construction/preprocess or /construction/payloads
	// are not valid.
	ErrUnclearIntent = &types.Error{
		Code:    4, //nolint
		Message: "Unable to parse intent",
	}

	// ErrUnableToParseIntermediateResult is returned
	// when a data structure passed between Construction
	// API calls is not valid.
	ErrUnableToParseIntermediateResult = &types.Error{
		Code:    5, //nolint
		Message: "Unable to parse intermediate result",
	}

	// ErrSignatureInvalid is returned when a signature
	// cannot be parsed.
	ErrSignatureInvalid = &types.Error{
		Code:    6, //nolint
		Message: "Signature invalid",
	}

	// ErrBroadcastFailed is returned when transaction
	// broadcast fails.
	ErrBroadcastFailed = &types.Error{
		Code:    7, //nolint
		Message: "Unable to broadcast transaction",
	}

	// ErrCallParametersInvalid is returned when
	// the parameters for a particular call method
	// are considered invalid.
	ErrCallParametersInvalid = &types.Error{
		Code:    8, //nolint
		Message: "Call parameters invalid",
	}

	// ErrCallOutputMarshal is returned when the output
	// for /call cannot be marshaled.
	ErrCallOutputMarshal = &types.Error{
		Code:    9, //nolint
		Message: "Call output marshal failed",
	}

	// ErrCallMethodInvalid is returned when a /call
	// method is invalid.
	ErrCallMethodInvalid = &types.Error{
		Code:    10, //nolint
		Message: "Call method invalid",
	}

	// ErrInvalidAddress is returned when an address
	// is not valid.
	ErrInvalidAddress = &types.Error{
		Code:    12, //nolint
		Message: "Invalid address",
	}

	// ErrKlaytnClientNotReady is returned when Klaytn client
	// cannot yet serve any queries.
	ErrKlaytnClientNotReady = &types.Error{
		Code:      13, //nolint
		Message:   "Klaytn client not ready",
		Retriable: true,
	}

	// ErrInvalidInput is returned when client
	// has provided invalid input
	ErrInvalidInput = &types.Error{
		Code:    14, //nolint
		Message: "invalid input",
	}

	// ErrNotSupportedAPI is returned when
	// the API endpoint is not supported by rosetta-klaytn.
	ErrNotSupportedAPI = &types.Error{
		Code:    15, //nolint
		Message: "not supported API",
	}

	// ErrGetAccountAPI is returned when
	// the rosetta-klaytn cannot get an account
	// via klay_getAccount API.
	ErrGetAccountAPI = &types.Error{
		Code:    16, //nolint
		Message: "Unable to get an account info",
	}

	// ErrAccountType is returned when
	// the account type is neither LegacyAccount nor EOA.
	ErrAccountType = &types.Error{
		Code:    17, //nolint
		Message: "not supported account type",
	}

	// ErrDeriveAddress is returned if an error is returned during
	// deriving an address from the public key.
	ErrDeriveAddress = &types.Error{
		Code:    18, //nolint
		Message: "cannot derive an address from the public key",
	}

	// ErrDerivedAddrNotMatched is returned if the account associated
	// with the address sent by the user in the metadata field
	// has AccountKeyLegacy as accountKey,
	// and the address derived from the public key
	// does not match the one sent by the user in the metadata field.
	ErrDerivedAddrNotMatched = &types.Error{
		Code:    19, //nolint
		Message: "derived address from the public key does not match with the address in the metadata",
	}

	// ErrXYPoint is returned when failed to extract x and y point.
	ErrXYPoint = &types.Error{
		Code:    20, //nolint
		Message: "Unable to get x, y point from public key",
	}

	// ErrDiffPubKey is returned when public key parameter is different
	// with a public key in Klaytn account.
	ErrDiffPubKey = &types.Error{
		Code:    21, //nolint
		Message: "pubilc key does not match",
	}

	// ErrExtractAddress is returned when fail to get an address from metadata.
	ErrExtractAddress = &types.Error{
		Code:    22, //nolint
		Message: "address string could not be extracted from the metadata",
	}

	// ErrAccountKeyFail is returned when an account key of the Klaytn account is AccountKeyFail.
	ErrAccountKeyFail = &types.Error{
		Code:    23, //nolint
		Message: "Klaytn account with AccountKeyFail cannot be used",
	}

	// ErrMultiSigNotIncludePubKey is returned when the AccountKeyWeightedMultiSig does not include
	// the public key that user pass as a parameter.
	ErrMultiSigNotIncludePubKey = &types.Error{
		Code:    24, //nolint
		Message: "AccountKeyWeightedMultiSig does not include public key passed as a parameter",
	}

	// ErrRoleBasedNotIncludePubKey is returned when the AccountKeyRoleBased does not include
	// the public key that user pass as a parameter in the RoleTransactionKey.
	ErrRoleBasedNotIncludePubKey = &types.Error{
		Code:    25, //nolint
		Message: "AccountKeyRoleBased does not include public key passed as a parameter in the RoleTransactionKey",
	}
)

// wrapErr adds details to the types.Error provided. We use a function
// to do this so that we don't accidentially overrwrite the standard
// errors.
func wrapErr(rErr *types.Error, err error) *types.Error {
	newErr := &types.Error{
		Code:      rErr.Code,
		Message:   rErr.Message,
		Retriable: rErr.Retriable,
	}
	if err != nil {
		newErr.Details = map[string]interface{}{
			"context": err.Error(),
		}
	}

	return newErr
}

// wrapErrWithMetadata adds metatdata to the types.Error provided. We use a function
// to do this so that we don't accidentially overrwrite the standard
// errors.
func wrapErrWithMetadata(rErr *types.Error, metadata map[string]interface{}, err error) *types.Error {
	newErr := &types.Error{
		Code:      rErr.Code,
		Message:   rErr.Message,
		Retriable: rErr.Retriable,
		Details:   map[string]interface{}{"metadata": metadata},
	}

	if err != nil {
		newErr.Details["context"] = err.Error()
	}

	return newErr
}
