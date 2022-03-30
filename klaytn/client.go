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

package klaytn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/klaytn/klaytn"
	"github.com/klaytn/klaytn/blockchain/types"
	"github.com/klaytn/klaytn/blockchain/types/account"
	"github.com/klaytn/klaytn/common"
	"github.com/klaytn/klaytn/networks/p2p"
	"github.com/klaytn/klaytn/networks/rpc"
	"github.com/klaytn/klaytn/node/cn"
	"github.com/klaytn/klaytn/params"
	"github.com/klaytn/klaytn/reward"
	"github.com/klaytn/klaytn/rlp"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/klaytn/klaytn/common/hexutil"
	RosettaTypes "github.com/klaytn/rosetta-sdk-go-klaytn/types"
	"golang.org/x/sync/semaphore"
)

const (
	clientHTTPTimeout = 120 * time.Second

	maxTraceConcurrency  = int64(16) // nolint:gomnd
	semaphoreTraceWeight = int64(1)  // nolint:gomnd

	// eip1559TxType is the EthTypes.Transaction.Type() value that indicates this transaction
	// follows EIP-1559.
	eip1559TxType = 2
)

// Client allows for querying a set of specific Ethereum endpoints in an
// idempotent manner. Client relies on the klay_*, debug_*, admin_*, governance_*, and txpool_* methods.
//
// Client borrows HEAVILY from https://github.com/klaytn/klaytn/blob/dev/client/klay_client.go
type Client struct {
	p  *params.ChainConfig
	tc *cn.TraceConfig

	c JSONRPC

	traceSemaphore *semaphore.Weighted

	skipAdminCalls bool
}

// NewClient creates a Client that from the provided url and params.
func NewClient(url string, params *params.ChainConfig, skipAdminCalls bool) (*Client, error) {
	c, err := rpc.DialHTTPWithClient(url, &http.Client{
		Timeout: clientHTTPTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: unable to dial node", err)
	}

	tc, err := loadTraceConfig()
	if err != nil {
		return nil, fmt.Errorf("%w: unable to load trace config", err)
	}

	return &Client{params, tc, c, semaphore.NewWeighted(maxTraceConcurrency), skipAdminCalls}, nil
}

// Close shuts down the RPC client connection.
func (kc *Client) Close() {
	kc.c.Close()
}

// Status returns klaytn client status information
// for determining node healthiness.
func (kc *Client) Status(ctx context.Context) (
	*RosettaTypes.BlockIdentifier,
	int64,
	*RosettaTypes.SyncStatus,
	[]*RosettaTypes.Peer,
	error,
) {
	header, err := kc.blockHeaderByNumber(ctx, nil)
	if err != nil {
		return nil, -1, nil, nil, err
	}

	progress, err := kc.syncProgress(ctx)
	if err != nil {
		return nil, -1, nil, nil, err
	}

	var syncStatus *RosettaTypes.SyncStatus
	if progress != nil {
		currentIndex := int64(progress.CurrentBlock)
		targetIndex := int64(progress.HighestBlock)

		syncStatus = &RosettaTypes.SyncStatus{
			CurrentIndex: &currentIndex,
			TargetIndex:  &targetIndex,
		}
	}

	peers, err := kc.peers(ctx)
	if err != nil {
		return nil, -1, nil, nil, err
	}

	return &RosettaTypes.BlockIdentifier{
			Hash:  header.Hash().Hex(),
			Index: header.Number.Int64(),
		},
		convertTime(header.Time.Uint64()),
		syncStatus,
		peers,
		nil
}

// PendingNonceAt returns the account nonce of the given account in the pending state.
// This is the nonce that should be used for the next transaction.
func (kc *Client) PendingNonceAt(ctx context.Context, account common.Address) (uint64, error) {
	var result hexutil.Uint64
	err := kc.c.CallContext(ctx, &result, "klay_getTransactionCount", account, "pending")
	return uint64(result), err
}

// SuggestGasPrice retrieves the currently suggested gas price to allow a timely
// execution of a transaction.
func (kc *Client) SuggestGasPrice(ctx context.Context) (*big.Int, error) {
	var hex hexutil.Big
	if err := kc.c.CallContext(ctx, &hex, "klay_gasPrice"); err != nil {
		return nil, err
	}
	return (*big.Int)(&hex), nil
}

// GasPriceAt retrieves the suggested gas price to allow a timely
// execution of a transaction at the given block height.
func (kc *Client) GasPriceAt(ctx context.Context, blockNumber int64) (*big.Int, error) {
	var hex hexutil.Big
	if err := kc.c.CallContext(ctx, &hex, "klay_gasPriceAt", toBlockNumArg(big.NewInt(blockNumber))); err != nil {
		return nil, err
	}
	return (*big.Int)(&hex), nil
}

// Peers retrieves all peers of the node.
func (kc *Client) peers(ctx context.Context) ([]*RosettaTypes.Peer, error) {
	var info []*p2p.PeerInfo

	if kc.skipAdminCalls {
		return []*RosettaTypes.Peer{}, nil
	}

	if err := kc.c.CallContext(ctx, &info, "admin_peers"); err != nil {
		return nil, err
	}

	peers := make([]*RosettaTypes.Peer, len(info))
	for i, peerInfo := range info {
		peers[i] = &RosettaTypes.Peer{
			PeerID: peerInfo.ID,
			Metadata: map[string]interface{}{
				"name":      peerInfo.Name,
				"caps":      peerInfo.Caps,
				"protocols": peerInfo.Protocols,
			},
		}
	}

	return peers, nil
}

// SendTransaction injects a signed transaction into the pending pool for execution.
//
// If the transaction was a contract creation use the TransactionReceipt method to get the
// contract address after the transaction has been mined.
func (kc *Client) SendTransaction(ctx context.Context, tx *types.Transaction) error {
	data, err := rlp.EncodeToBytes(tx)
	if err != nil {
		return err
	}
	return kc.c.CallContext(ctx, nil, "klay_sendRawTransaction", hexutil.Encode(data))
}

func toBlockNumArg(number *big.Int) string {
	if number == nil {
		return "latest"
	}
	pending := big.NewInt(-1)
	if number.Cmp(pending) == 0 {
		return "pending"
	}
	return hexutil.EncodeBig(number)
}

// Transaction returns the transaction response of the Transaction identified
// by *RosettaTypes.TransactionIdentifier hash
func (kc *Client) Transaction(
	ctx context.Context,
	blockIdentifier *RosettaTypes.BlockIdentifier,
	transactionIdentifier *RosettaTypes.TransactionIdentifier,
) (*RosettaTypes.Transaction, error) {
	if transactionIdentifier.Hash == "" {
		return nil, errors.New("transaction hash is required")
	}

	var raw json.RawMessage
	err := kc.c.CallContext(ctx, &raw, "klay_getTransactionByHash", transactionIdentifier.Hash)
	if err != nil {
		return nil, fmt.Errorf("%w: transaction fetch failed", err)
	} else if len(raw) == 0 {
		return nil, klaytn.NotFound
	}

	// Decode transaction
	var body rpcTransaction

	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, err
	}

	var header *types.Header
	if blockIdentifier.Hash != "" {
		header, err = kc.blockHeaderByHash(ctx, blockIdentifier.Hash)
	} else {
		header, err = kc.blockHeaderByNumber(ctx, big.NewInt(blockIdentifier.Index))
	}

	if err != nil {
		return nil, fmt.Errorf("%w: could not get block header for %x", err, blockIdentifier.Hash)
	}

	receipt, err := kc.transactionReceipt(ctx, body.tx.Hash())
	if err != nil {
		return nil, fmt.Errorf("%w: could not get receipt for %x", err, body.tx.Hash())
	}

	var traces *Call
	var rawTraces json.RawMessage
	var addTraces bool
	if header.Number.Int64() != GenesisBlockIndex { // not possible to get traces at genesis
		addTraces = true
		traces, rawTraces, err = kc.getTransactionTraces(ctx, body.tx.Hash())
		if err != nil {
			return nil, fmt.Errorf("%w: could not get traces for %x", err, body.tx.Hash())
		}
	}

	loadedTx := body.LoadedTransaction()
	loadedTx.Transaction = body.tx
	feeAmount, feeBurned, err := kc.calculateGas(ctx, body.tx, receipt, *header)
	if err != nil {
		return nil, err
	}
	loadedTx.FeeAmount = feeAmount
	loadedTx.FeeBurned = feeBurned
	loadedTx.Receipt = receipt

	if addTraces {
		loadedTx.Trace = traces
		loadedTx.RawTrace = rawTraces
	}

	rewardRatioMap, _, err := kc.getRewardAndRatioInfo(ctx, toBlockNumArg(header.Number), header.Rewardbase.String())
	if err != nil {
		return nil, fmt.Errorf("%w: cannot get reward ratio %v", err, header)
	}
	// Since populateTransaction calculates the transaction fee calculation,
	// the addresses receiving the fee and the fee distribution ratios must be passed together as parameters.
	tx, err := kc.populateTransaction(loadedTx, rewardRatioMap)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot parse %s", err, loadedTx.Transaction.Hash().Hex())
	}
	return tx, nil
}

// Block returns a populated block at the *RosettaTypes.PartialBlockIdentifier.
// If neither the hash or index is populated in the *RosettaTypes.PartialBlockIdentifier,
// the current block is returned.
func (kc *Client) Block(
	ctx context.Context,
	blockIdentifier *RosettaTypes.PartialBlockIdentifier,
) (*RosettaTypes.Block, error) {
	if blockIdentifier != nil {
		if blockIdentifier.Hash != nil {
			return kc.getParsedBlock(ctx, "klay_getBlockByHash", *blockIdentifier.Hash, true)
		}

		if blockIdentifier.Index != nil {
			return kc.getParsedBlock(
				ctx,
				"klay_getBlockByNumber",
				toBlockNumArg(big.NewInt(*blockIdentifier.Index)),
				true,
			)
		}
	}

	return kc.getParsedBlock(ctx, "klay_getBlockByNumber", toBlockNumArg(nil), true)
}

// Header returns a block header from the current canonical chain. If number is
// nil, the latest known header is returned.
func (kc *Client) blockHeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error) {
	var head *types.Header
	err := kc.c.CallContext(ctx, &head, "klay_getBlockByNumber", toBlockNumArg(number), false)
	if err == nil && head == nil {
		return nil, klaytn.NotFound
	}

	return head, err
}

// Header returns a block header from the current canonical chain. If hash is empty
// it returns error.
func (kc *Client) blockHeaderByHash(ctx context.Context, hash string) (*types.Header, error) {
	var head *types.Header
	if hash == "" {
		return nil, errors.New("hash is empty")
	}
	err := kc.c.CallContext(ctx, &head, "klay_getBlockByHash", hash, false)
	if err == nil && head == nil {
		return nil, klaytn.NotFound
	}

	return head, err
}

type rpcBlock struct {
	Hash         common.Hash      `json:"hash"`
	Transactions []rpcTransaction `json:"transactions"`
}

func (kc *Client) getBlock(
	ctx context.Context,
	blockMethod string,
	args ...interface{},
) (
	*types.Block,
	[]*loadedTransaction,
	error,
) {
	var raw json.RawMessage
	err := kc.c.CallContext(ctx, &raw, blockMethod, args...)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: block fetch failed", err)
	} else if len(raw) == 0 {
		return nil, nil, klaytn.NotFound
	}

	// Decode header and transactions
	var head types.Header
	var body rpcBlock
	if err := json.Unmarshal(raw, &head); err != nil {
		return nil, nil, err
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, nil, err
	}

	// Get all transaction receipts
	receipts, err := kc.getBlockReceipts(ctx, body.Transactions)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: could not get receipts for %x", err, body.Hash[:])
	}

	// Get block traces (not possible to make idempotent block transaction trace requests)
	//
	// We fetch traces last because we want to avoid limiting the number of other
	// block-related data fetches we perform concurrently (we limit the number of
	// concurrent traces that are computed to 16 to avoid overwhelming Node).
	// TODO-Klaytn: Need to make sure those logic is fine with Klaytn
	var traces []*rpcCall
	var rawTraces []*rpcRawCall
	var addTraces bool
	if head.Number.Int64() != GenesisBlockIndex { // not possible to get traces at genesis
		addTraces = true
		traces, rawTraces, err = kc.getBlockTraces(ctx, body.Hash)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: could not get traces for %x", err, body.Hash[:])
		}
	}

	// Convert all txs to loaded txs
	txs := make([]*types.Transaction, len(body.Transactions))
	loadedTxs := make([]*loadedTransaction, len(body.Transactions))
	for i, tx := range body.Transactions {
		txs[i] = tx.tx
		receipt := receipts[i]
		if err != nil {
			return nil, nil, fmt.Errorf("%w: failure getting effective gas price", err)
		}
		loadedTxs[i] = tx.LoadedTransaction()
		loadedTxs[i].Transaction = txs[i]

		feeAmount, feeBurned, err := kc.calculateGas(ctx, txs[i], receipt, head)
		if err != nil {
			return nil, nil, err
		}
		loadedTxs[i].FeeAmount = feeAmount
		loadedTxs[i].FeeBurned = feeBurned
		loadedTxs[i].Receipt = receipt

		// Continue if calls does not exist (occurs at genesis)
		if !addTraces {
			continue
		}

		loadedTxs[i].Trace = traces[i].Result
		loadedTxs[i].RawTrace = rawTraces[i].Result
	}

	return types.NewBlockWithHeader(&head).WithBody(txs), loadedTxs, nil
}

// getBaseFee returns a `baseFeePerGas` field from Header RPC output.
func (kc *Client) getBaseFee(ctx context.Context, block string) (*big.Int, error) {
	header := make(map[string]interface{})
	err := kc.c.CallContext(ctx, &header, "klay_getHeaderByNumber", block)
	if err != nil {
		return nil, err
	}
	if err == nil && header == nil {
		return nil, klaytn.NotFound
	}

	bf, found := header["baseFeePerGas"].(string)
	if !found {
		// If header rpc output does not have `baseFeePerGas`,
		// return nil to handle the situation where the base fee is not supported.
		return nil, nil
	}
	baseFee, ok := new(big.Int).SetString(bf, 16)
	if !ok {
		return nil, errors.New("could not convert base fee type to big.Int")
	}
	return baseFee, nil
}

// calculateGas calculates the fee amount and burn amount of the transaction.
func (kc *Client) calculateGas(
	ctx context.Context,
	tx *types.Transaction,
	txReceipt *types.Receipt,
	head types.Header,
) (
	*big.Int, *big.Int, error,
) {
	gasUsed := new(big.Int).SetUint64(txReceipt.GasUsed)
	// Klaytn types.Header does not have `BaseFee` field.
	// To get baseFee, we need to use rpc output.
	baseFee, err := kc.getBaseFee(ctx, toBlockNumArg(head.Number))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: failure getting base fee", err)
	}
	gasPrice, err := effectiveGasPrice(tx, baseFee)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: failure getting effective gas price", err)
	}
	feeAmount := new(big.Int).Mul(gasUsed, gasPrice)
	var feeBurned *big.Int
	if baseFee != nil { // EIP-1559
		feeBurned = new(big.Int).Mul(gasUsed, baseFee)
	}

	return feeAmount, feeBurned, nil
}

// effectiveGasPrice returns the price of gas charged to this transaction to be included in the
// block.
func effectiveGasPrice(tx *types.Transaction, baseFee *big.Int) (*big.Int, error) {
	if tx.Type() != types.TxTypeEthereumDynamicFee {
		return tx.GasPrice(), nil
	}
	// For EIP-1559 (TxTypeEthereumDynamicFee) the gas price is determined
	// by the base fee & gas tip instead of the tx-specified gas price.
	tip := tx.EffectiveGasTip(baseFee)
	return new(big.Int).Add(tip, baseFee), nil
}

func (kc *Client) getTransactionTraces(
	ctx context.Context,
	transactionHash common.Hash,
) (*Call, json.RawMessage, error) {
	if err := kc.traceSemaphore.Acquire(ctx, semaphoreTraceWeight); err != nil {
		return nil, nil, err
	}
	defer kc.traceSemaphore.Release(semaphoreTraceWeight)

	var call *Call
	var raw json.RawMessage
	err := kc.c.CallContext(ctx, &raw, "debug_traceTransaction", transactionHash, kc.tc)
	if err != nil {
		return nil, nil, err
	}

	// Decode *Call
	if err := json.Unmarshal(raw, &call); err != nil {
		return nil, nil, err
	}

	return call, raw, nil
}

func (kc *Client) getBlockTraces(
	ctx context.Context,
	blockHash common.Hash,
) ([]*rpcCall, []*rpcRawCall, error) {
	if err := kc.traceSemaphore.Acquire(ctx, semaphoreTraceWeight); err != nil {
		return nil, nil, err
	}
	defer kc.traceSemaphore.Release(semaphoreTraceWeight)

	var calls []*rpcCall
	var rawCalls []*rpcRawCall
	var raw json.RawMessage
	err := kc.c.CallContext(ctx, &raw, "debug_traceBlockByHash", blockHash, kc.tc)
	if err != nil {
		return nil, nil, err
	}

	// Decode []*rpcCall
	if err := json.Unmarshal(raw, &calls); err != nil {
		return nil, nil, err
	}

	// Decode []*rpcRawCall
	if err := json.Unmarshal(raw, &rawCalls); err != nil {
		return nil, nil, err
	}

	return calls, rawCalls, nil
}

func (kc *Client) getBlockReceipts(
	ctx context.Context,
	txs []rpcTransaction,
) ([]*types.Receipt, error) {
	receipts := make([]*types.Receipt, len(txs))
	if len(txs) == 0 {
		return receipts, nil
	}

	reqs := make([]rpc.BatchElem, len(txs))
	for i := range reqs {
		reqs[i] = rpc.BatchElem{
			Method: "klay_getTransactionReceipt",
			Args:   []interface{}{txs[i].tx.Hash().Hex()},
			Result: &receipts[i],
		}
	}
	if err := kc.c.BatchCallContext(ctx, reqs); err != nil {
		return nil, err
	}
	for i := range reqs {
		if reqs[i].Error != nil {
			return nil, reqs[i].Error
		}
		if receipts[i] == nil {
			return nil, fmt.Errorf("got empty receipt for %x", txs[i].tx.Hash().Hex())
		}
	}

	return receipts, nil
}

type rpcCall struct {
	Result *Call `json:"result"`
}

type rpcRawCall struct {
	Result json.RawMessage `json:"result"`
}

// Call is an Klaytn debug trace.
type Call struct {
	Type         string         `json:"type"`
	From         common.Address `json:"from"`
	To           common.Address `json:"to"`
	Value        *big.Int       `json:"value"`
	GasUsed      *big.Int       `json:"gasUsed"`
	Revert       bool
	ErrorMessage string  `json:"error"`
	Calls        []*Call `json:"calls"`
}

type flatCall struct {
	Type         string         `json:"type"`
	From         common.Address `json:"from"`
	To           common.Address `json:"to"`
	Value        *big.Int       `json:"value"`
	GasUsed      *big.Int       `json:"gasUsed"`
	Revert       bool
	ErrorMessage string `json:"error"`
}

func (t *Call) flatten() *flatCall {
	return &flatCall{
		Type:         t.Type,
		From:         t.From,
		To:           t.To,
		Value:        t.Value,
		GasUsed:      t.GasUsed,
		Revert:       t.Revert,
		ErrorMessage: t.ErrorMessage,
	}
}

// UnmarshalJSON is a custom unmarshaler for Call.
func (t *Call) UnmarshalJSON(input []byte) error {
	type CustomTrace struct {
		Type         string         `json:"type"`
		From         common.Address `json:"from"`
		To           common.Address `json:"to"`
		Value        *hexutil.Big   `json:"value"`
		GasUsed      *hexutil.Big   `json:"gasUsed"`
		Revert       bool
		ErrorMessage string  `json:"error"`
		Calls        []*Call `json:"calls"`
	}
	var dec CustomTrace
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}

	t.Type = dec.Type
	t.From = dec.From
	t.To = dec.To
	if dec.Value != nil {
		t.Value = (*big.Int)(dec.Value)
	} else {
		t.Value = new(big.Int)
	}
	if dec.GasUsed != nil {
		t.GasUsed = (*big.Int)(dec.Value)
	} else {
		t.GasUsed = new(big.Int)
	}
	if dec.ErrorMessage != "" {
		// Any error surfaced by the decoder means that the transaction
		// has reverted.
		t.Revert = true
	}
	t.ErrorMessage = dec.ErrorMessage
	t.Calls = dec.Calls
	return nil
}

// flattenTraces recursively flattens all traces.
func flattenTraces(data *Call, flattened []*flatCall) []*flatCall {
	results := append(flattened, data.flatten())
	for _, child := range data.Calls {
		// Ensure all children of a reverted call
		// are also reverted!
		if data.Revert {
			child.Revert = true

			// Copy error message from parent
			// if child does not have one
			if len(child.ErrorMessage) == 0 {
				child.ErrorMessage = data.ErrorMessage
			}
		}

		children := flattenTraces(child, flattened)
		results = append(results, children...)
	}
	return results
}

// traceOps returns all *RosettaTypes.Operation for a given
// array of flattened traces.
func traceOps(calls []*flatCall, startIndex int) []*RosettaTypes.Operation { // nolint: gocognit
	var ops []*RosettaTypes.Operation
	if len(calls) == 0 {
		return ops
	}

	destroyedAccounts := map[string]*big.Int{}
	for _, trace := range calls {
		// Handle partial transaction success
		metadata := map[string]interface{}{}
		opStatus := SuccessStatus
		if trace.Revert {
			opStatus = FailureStatus
			metadata["error"] = trace.ErrorMessage
		}

		var zeroValue bool
		if trace.Value.Sign() == 0 {
			zeroValue = true
		}

		// Skip all 0 value CallType operations (TODO: make optional to include)
		//
		// We can't continue here because we may need to adjust our destroyed
		// accounts map if a CallTYpe operation resurrects an account.
		shouldAdd := true
		if zeroValue && CallType(trace.Type) {
			shouldAdd = false
		}

		// Checksum addresses
		from := MustChecksum(trace.From.String())
		to := MustChecksum(trace.To.String())

		if shouldAdd {
			fromOp := &RosettaTypes.Operation{
				OperationIdentifier: &RosettaTypes.OperationIdentifier{
					Index: int64(len(ops) + startIndex),
				},
				Type:   trace.Type,
				Status: RosettaTypes.String(opStatus),
				Account: &RosettaTypes.AccountIdentifier{
					Address: from,
				},
				Amount: &RosettaTypes.Amount{
					Value:    new(big.Int).Neg(trace.Value).String(),
					Currency: Currency,
				},
				Metadata: metadata,
			}
			if zeroValue {
				fromOp.Amount = nil
			} else {
				_, destroyed := destroyedAccounts[from]
				if destroyed && opStatus == SuccessStatus {
					destroyedAccounts[from] = new(big.Int).Sub(destroyedAccounts[from], trace.Value)
				}
			}

			ops = append(ops, fromOp)
		}

		// Add to destroyed accounts if SELFDESTRUCT
		// and overwrite existing balance.
		if trace.Type == SelfDestructOpType {
			destroyedAccounts[from] = new(big.Int)

			// If destination of of SELFDESTRUCT is self,
			// we should skip. In the EVM, the balance is reset
			// after the balance is increased on the destination
			// so this is a no-op.
			if from == to {
				continue
			}
		}

		// Skip empty to addresses (this may not
		// actually occur but leaving it as a
		// sanity check)
		if len(trace.To.String()) == 0 {
			continue
		}

		// If the account is resurrected, we remove it from
		// the destroyed accounts map.
		if CreateType(trace.Type) {
			delete(destroyedAccounts, to)
		}

		if shouldAdd {
			lastOpIndex := ops[len(ops)-1].OperationIdentifier.Index
			toOp := &RosettaTypes.Operation{
				OperationIdentifier: &RosettaTypes.OperationIdentifier{
					Index: lastOpIndex + 1,
				},
				RelatedOperations: []*RosettaTypes.OperationIdentifier{
					{
						Index: lastOpIndex,
					},
				},
				Type:   trace.Type,
				Status: RosettaTypes.String(opStatus),
				Account: &RosettaTypes.AccountIdentifier{
					Address: to,
				},
				Amount: &RosettaTypes.Amount{
					Value:    trace.Value.String(),
					Currency: Currency,
				},
				Metadata: metadata,
			}
			if zeroValue {
				toOp.Amount = nil
			} else {
				_, destroyed := destroyedAccounts[to]
				if destroyed && opStatus == SuccessStatus {
					destroyedAccounts[to] = new(big.Int).Add(destroyedAccounts[to], trace.Value)
				}
			}

			ops = append(ops, toOp)
		}
	}

	// Zero-out all destroyed accounts that are removed
	// during transaction finalization.
	for acct, val := range destroyedAccounts {
		if val.Sign() == 0 {
			continue
		}

		if val.Sign() < 0 {
			log.Fatalf("negative balance for suicided account %s: %s\n", acct, val.String())
		}

		ops = append(ops, &RosettaTypes.Operation{
			OperationIdentifier: &RosettaTypes.OperationIdentifier{
				Index: ops[len(ops)-1].OperationIdentifier.Index + 1,
			},
			Type:   DestructOpType,
			Status: RosettaTypes.String(SuccessStatus),
			Account: &RosettaTypes.AccountIdentifier{
				Address: acct,
			},
			Amount: &RosettaTypes.Amount{
				Value:    new(big.Int).Neg(val).String(),
				Currency: Currency,
			},
		})
	}

	return ops
}

type txExtraInfo struct {
	BlockNumber *string         `json:"blockNumber,omitempty"`
	BlockHash   *common.Hash    `json:"blockHash,omitempty"`
	From        *common.Address `json:"from,omitempty"`
}

type rpcTransaction struct {
	tx *types.Transaction
	txExtraInfo
}

func (tx *rpcTransaction) UnmarshalJSON(msg []byte) error {
	if err := json.Unmarshal(msg, &tx.tx); err != nil {
		return err
	}
	return json.Unmarshal(msg, &tx.txExtraInfo)
}

func (tx *rpcTransaction) LoadedTransaction() *loadedTransaction {
	klayTx := &loadedTransaction{
		Transaction: tx.tx,
		From:        tx.txExtraInfo.From,
		BlockNumber: tx.txExtraInfo.BlockNumber,
		BlockHash:   tx.txExtraInfo.BlockHash,
	}
	return klayTx
}

type loadedTransaction struct {
	Transaction *types.Transaction
	From        *common.Address
	BlockNumber *string
	BlockHash   *common.Hash
	FeeAmount   *big.Int
	FeeBurned   *big.Int // nil if no fees were burned
	Status      bool

	Trace    *Call
	RawTrace json.RawMessage
	Receipt  *types.Receipt
}

func createSuccessFeeOperation(idx int64, account string, amount *big.Int) *RosettaTypes.Operation {
	return &RosettaTypes.Operation{
		OperationIdentifier: &RosettaTypes.OperationIdentifier{
			Index: idx,
		},
		Type:   FeeOpType,
		Status: RosettaTypes.String(SuccessStatus),
		Account: &RosettaTypes.AccountIdentifier{
			Address: MustChecksum(account),
		},
		Amount: &RosettaTypes.Amount{
			Value:    amount.String(),
			Currency: Currency,
		},
	}
}

// feeOps returns the transaction's fee operations.
// In the case of Klaytn, depending on the transaction type, the address where the fee is paid may be different.
// In addition, transaction fees must be allocated to CN, KIR, and KGF addresses according to a fixed rate.
func feeOps(tx *loadedTransaction, rewardRatioMap map[string]*big.Int) ([]*RosettaTypes.Operation, error) {
	var proposerEarnedAmount *big.Int
	if tx.FeeBurned == nil {
		proposerEarnedAmount = tx.FeeAmount
	} else {
		proposerEarnedAmount = new(big.Int).Sub(tx.FeeAmount, tx.FeeBurned)
	}

	// There are three cases
	// 1. Basic tx: sender will pay all tx fee
	// 2. Fee Delegation tx: fee payer will pay all tx fee
	// 3. Partial Fee Delegation tx: sender and fee payer will pay tx fee
	ops := []*RosettaTypes.Operation{}

	// FD(Fee Delegation), FDR(Partial Fee Delegation)
	if tx.Transaction.Type().IsFeeDelegatedTransaction() {
		feePayerAddress, err := tx.Transaction.FeePayer()
		if err != nil {
			return nil, fmt.Errorf("could not extract fee payer from %v", tx.Transaction)
		}
		if tx.Transaction.Type().IsFeeDelegatedWithRatioTransaction() {
			// Partial Fee Delegation transaction (sender and fee payer will pay the tx fee)
			ratio, ok := tx.Transaction.FeeRatio()
			if !ok {
				return nil, fmt.Errorf("could not extract fee ratio from %v", tx.Transaction)
			}
			senderRatio := big.NewInt(int64(100 - ratio))
			feePayerRatio := big.NewInt(int64(ratio))

			// fee * ratio / 100
			senderAmount := new(big.Int).Div(new(big.Int).Mul(proposerEarnedAmount, senderRatio), big.NewInt(100))
			feePayerAmount := new(big.Int).Div(new(big.Int).Mul(proposerEarnedAmount, feePayerRatio), big.NewInt(100))

			// Set sender tx fee payment and fee payer tx fee payment.
			opsForFDR := []*RosettaTypes.Operation{
				createSuccessFeeOperation(0, tx.From.String(), new(big.Int).Neg(senderAmount)),
				createSuccessFeeOperation(1, feePayerAddress.String(), new(big.Int).Neg(feePayerAmount)),
			}
			ops = append(ops, opsForFDR...)

			// If tx.FeeBurned is not nil, append the burnt operations.
			if tx.FeeBurned != nil {
				senderBurnAmount := new(big.Int).Div(new(big.Int).Mul(tx.FeeBurned, senderRatio), big.NewInt(100))
				feePayerBurnAmount := new(big.Int).Div(new(big.Int).Mul(tx.FeeBurned, feePayerRatio), big.NewInt(100))
				burntOps := []*RosettaTypes.Operation{
					createSuccessFeeOperation(2, tx.From.String(), new(big.Int).Neg(senderBurnAmount)),
					createSuccessFeeOperation(3, feePayerAddress.String(), new(big.Int).Neg(feePayerBurnAmount)),
				}
				ops = append(ops, burntOps...)
			}
		} else {
			// Fee Delegation transaction (fee payer will pay the tx fee)
			op := createSuccessFeeOperation(0, feePayerAddress.String(), new(big.Int).Neg(proposerEarnedAmount))
			ops = append(ops, op)

			// If FeeBurned is not nil, add a burnt operation.
			if tx.FeeBurned != nil {
				burntOp := createSuccessFeeOperation(1, feePayerAddress.String(), new(big.Int).Neg(tx.FeeBurned))
				ops = append(ops, burntOp)
			}
		}
	} else {
		// Basic transaction (sender will pay the tx fee)
		op := createSuccessFeeOperation(0, tx.From.String(), new(big.Int).Neg(proposerEarnedAmount))
		ops = append(ops, op)

		// If FeeBurned is not nil, add a burnt operation.
		if tx.FeeBurned != nil {
			burntOp := createSuccessFeeOperation(1, tx.From.String(), new(big.Int).Neg(tx.FeeBurned))
			ops = append(ops, burntOp)
		}
	}

	// Transaction fee reward is also allocated to CN, KGF, and KIR addresses according to the ratios.
	idx := len(ops)
	for addr, ratio := range rewardRatioMap {
		// reward * ratio / 100
		partialReward := new(big.Int).Div(new(big.Int).Mul(proposerEarnedAmount, ratio), big.NewInt(100))
		op := createSuccessFeeOperation(int64(idx), addr, partialReward)
		ops = append(ops, op)
		idx++
	}

	return ops, nil
}

// transactionReceipt returns the receipt of a transaction by transaction hash.
// Note that the receipt is not available for pending transactions.
func (kc *Client) transactionReceipt(
	ctx context.Context,
	txHash common.Hash,
) (*types.Receipt, error) {
	var r *types.Receipt
	err := kc.c.CallContext(ctx, &r, "klay_getTransactionReceipt", txHash)
	if err == nil && r == nil {
		return nil, klaytn.NotFound
	}

	return r, err
}

// blockByNumber returns the block by number.
func (kc *Client) blockByNumber(
	ctx context.Context,
	index *int64,
	showTxDetails bool,
) (map[string]interface{}, error) {
	var blockIndex string
	if index == nil {
		blockIndex = toBlockNumArg(nil)
	} else {
		blockIndex = toBlockNumArg(big.NewInt(*index))
	}

	r := make(map[string]interface{})
	err := kc.c.CallContext(ctx, &r, "klay_getBlockByNumber", blockIndex, showTxDetails)
	if err == nil && r == nil {
		return nil, klaytn.NotFound
	}

	return r, err
}

// contractCall returns the data specified by the given contract method.
func (kc *Client) contractCall(
	ctx context.Context,
	params map[string]interface{},
) (map[string]interface{}, error) {
	// validate call input
	input, err := validateCallInput(params)
	if err != nil {
		return nil, err
	}

	// default query
	blockQuery := "latest"

	// if block number or hash, override blockQuery
	if input.BlockIndex > int64(0) {
		blockQuery = toBlockNumArg(big.NewInt(input.BlockIndex))
	} else if len(input.BlockHash) > 0 {
		blockQuery = input.BlockHash
	}

	// ensure valid contract address
	_, ok := ChecksumAddress(input.To)
	if !ok {
		return nil, ErrCallParametersInvalid
	}

	// parameters for klay_call
	callParams := map[string]string{
		"to":   input.To,
		"data": input.Data,
	}

	var resp string
	if err := kc.c.CallContext(ctx, &resp, "klay_call", callParams, blockQuery); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"data": resp,
	}, nil
}

// estimateGas returns the data specified by the given contract method
func (kc *Client) estimateGas(
	ctx context.Context,
	params map[string]interface{},
) (map[string]interface{}, error) {
	// validate call input
	input, err := validateCallInput(params)
	if err != nil {
		return nil, err
	}

	// ensure valid contract address
	_, ok := ChecksumAddress(input.To)
	if !ok {
		return nil, ErrCallParametersInvalid
	}

	// ensure valid from address
	_, ok = ChecksumAddress(input.From)
	if !ok {
		return nil, ErrCallParametersInvalid
	}

	// parameters for klay_estimateGas
	estimateGasParams := map[string]string{
		"from": input.From,
		"to":   input.To,
		"data": input.Data,
	}

	var resp string
	if err := kc.c.CallContext(ctx, &resp, "klay_estimateGas", estimateGasParams); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"data": resp,
	}, nil
}

func validateCallInput(params map[string]interface{}) (*GetCallInput, error) {
	var input GetCallInput
	if err := RosettaTypes.UnmarshalMap(params, &input); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrCallParametersInvalid, err.Error())
	}

	// to address is required for call requests
	if len(input.To) == 0 {
		return nil, fmt.Errorf("%w:to address is missing from parameters", ErrCallParametersInvalid)
	}

	if len(input.Data) == 0 {
		return nil, fmt.Errorf("%w:data is missing from parameters", ErrCallParametersInvalid)
	}
	return &input, nil
}

func (kc *Client) getParsedBlock(
	ctx context.Context,
	blockMethod string,
	args ...interface{},
) (
	*RosettaTypes.Block,
	error,
) {
	block, loadedTransactions, err := kc.getBlock(ctx, blockMethod, args...)
	if err != nil {
		return nil, fmt.Errorf("%w: could not get block", err)
	}

	blockIdentifier := &RosettaTypes.BlockIdentifier{
		Hash:  block.Hash().String(),
		Index: block.Number().Int64(),
	}

	parentBlockIdentifier := blockIdentifier
	if blockIdentifier.Index != GenesisBlockIndex {
		parentBlockIdentifier = &RosettaTypes.BlockIdentifier{
			Hash:  block.ParentHash().Hex(),
			Index: blockIdentifier.Index - 1,
		}
	}

	txs, err := kc.populateTransactions(block, loadedTransactions)
	if err != nil {
		return nil, err
	}

	return &RosettaTypes.Block{
		BlockIdentifier:       blockIdentifier,
		ParentBlockIdentifier: parentBlockIdentifier,
		Timestamp:             convertTime(block.Time().Uint64()),
		Transactions:          txs,
	}, nil
}

func convertTime(time uint64) int64 {
	return int64(time) * 1000
}

func (kc *Client) populateTransactions(
	block *types.Block,
	loadedTransactions []*loadedTransaction,
) ([]*RosettaTypes.Transaction, error) {
	transactions := make(
		[]*RosettaTypes.Transaction,
		len(block.Transactions())+1, // include reward tx
	)

	var err error
	var rewardRatioMap map[string]*big.Int
	transactions[0], rewardRatioMap, err = kc.blockRewardTransaction(block)
	if err != nil {
		return nil, fmt.Errorf("cannot calculate block(%s) reward: %w", block.Hash().String(), err)
	}

	for i, tx := range loadedTransactions {
		transaction, err := kc.populateTransaction(
			tx,
			rewardRatioMap,
		)
		if err != nil {
			return nil, fmt.Errorf("%w: cannot parse %s", err, tx.Transaction.Hash().Hex())
		}

		transactions[i+1] = transaction
	}

	return transactions, nil
}

func (kc *Client) populateTransaction(
	tx *loadedTransaction,
	rewardRatioMap map[string]*big.Int,
) (*RosettaTypes.Transaction, error) {
	var ops []*RosettaTypes.Operation

	// Compute fee operations
	feeOperations, err := feeOps(tx, rewardRatioMap)
	if err != nil {
		return nil, err
	}
	ops = append(ops, feeOperations...)

	// Compute trace operations
	traces := flattenTraces(tx.Trace, []*flatCall{})

	traceOperations := traceOps(traces, len(ops))
	ops = append(ops, traceOperations...)

	// Marshal receipt and trace data
	// TODO: replace with marshalJSONMap (used in `services`)
	receiptBytes, err := tx.Receipt.MarshalJSON()
	if err != nil {
		return nil, err
	}

	var receiptMap map[string]interface{}
	if err := json.Unmarshal(receiptBytes, &receiptMap); err != nil {
		return nil, err
	}

	var traceMap map[string]interface{}
	if err := json.Unmarshal(tx.RawTrace, &traceMap); err != nil {
		return nil, err
	}

	populatedTransaction := &RosettaTypes.Transaction{
		TransactionIdentifier: &RosettaTypes.TransactionIdentifier{
			Hash: tx.Transaction.Hash().Hex(),
		},
		Operations: ops,
		Metadata: map[string]interface{}{
			"gas_limit": hexutil.EncodeUint64(tx.Transaction.Gas()),
			"gas_price": hexutil.EncodeBig(tx.Transaction.GasPrice()),
			"receipt":   receiptMap,
			"trace":     traceMap,
		},
	}

	return populatedTransaction, nil
}

// getRewardAndRatioInfo returns the block minting reward and reward ratio of the given block height.
// In order to obtain the minting amount per block and rate per block and kir and kgf addresses, blockReward uses the governance API.
func (kc *Client) getRewardAndRatioInfo(ctx context.Context, block string, rewardbase string) (map[string]*big.Int, *big.Int, error) {
	govItems := make(map[string]interface{})
	// Call `governance_itemsAt` to get reward ratio.
	err := kc.c.CallContext(ctx, &govItems, "governance_itemsAt", block)
	if err != nil {
		return nil, nil, err
	}

	// `governance_itemsAt` has a field `reward.ratio`
	// where the reward ratios of cn, kgf and kir are defined using the `/` delimiter.
	var cnRatio, kgfRatio, kirRatio *big.Int
	ratio, found := govItems["reward.ratio"].(string)
	if !found {
		return nil, nil, fmt.Errorf("could not extract reward.ratio from %v", govItems)
	}

	// Split "34/54/12" to ["34", "54", "12"]
	ratios := strings.Split(ratio, "/")
	if len(ratios) != 3 {
		return nil, nil, fmt.Errorf("could not parse reward ratio from %v", ratio)
	}

	_, ok := cnRatio.SetString(ratios[0], 10)
	if !ok {
		return nil, nil, fmt.Errorf("could not convert CN reward ratio string to int type from %s", ratios[0])
	}
	_, ok = kgfRatio.SetString(ratios[1], 10)
	if !ok {
		return nil, nil, fmt.Errorf("could not convert KGF reward ratio string to int type from %s", ratios[1])
	}
	_, ok = kirRatio.SetString(ratios[2], 10)
	if !ok {
		return nil, nil, fmt.Errorf("could not convert KIR reward ratio string to int type from %s", ratios[2])
	}

	// In `governance_itemsAt`, there is a field `reward.mintingamount`
	// which is the amount of Peb minted when a block is generated. (e.g., "9600000000000000000")
	var mintingAmount *big.Int
	minted, found := govItems["reward.mintingamount"].(string)
	if !found {
		return nil, nil, fmt.Errorf("could not extract reward.mintingamount from %v", govItems)
	}
	_, ok = mintingAmount.SetString(minted, 10)
	if !ok {
		return nil, nil, fmt.Errorf("could not convert minting amount type from %s", minted)
	}

	// Call `governance_getStakingInfo` to get KIR and KGF addresses.
	var stakingInfo reward.StakingInfo
	err = kc.c.CallContext(ctx, &stakingInfo, "governance_getStakingInfo", block)
	if err != nil {
		return nil, nil, err
	}

	// TODO-Klaytn: Have to use stakingInfo.KGFAddr instead of stakingInfo.PoCAddr
	kirAddress := stakingInfo.KIRAddr.String()
	kgfAddress := stakingInfo.PoCAddr.String()

	// Set the reward assigned to each address in rewardMap.
	rewardRatioMap := map[string]*big.Int{}
	rewardRatioMap[rewardbase] = cnRatio
	rewardRatioMap[kgfAddress] = kgfRatio
	rewardRatioMap[kirAddress] = kirRatio

	return rewardRatioMap, mintingAmount, nil
}

// blockReward returns the block reward information of the given block height.
// The block reward is distributed to cn, kir, and kgf according to the defined ratio.
func (kc *Client) blockMintingReward(
	currentBlock *types.Block,
) (map[string]*big.Int, map[string]*big.Int, error) {
	ctx := context.Background()

	var err error
	rewardRatioMap, mintingAmount, err := kc.getRewardAndRatioInfo(ctx, toBlockNumArg(currentBlock.Number()), currentBlock.Rewardbase().String())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get reward ratio info: %s", err.Error())
	}

	// Set the block minting reward amount assigned to each address in rewardMap.
	rewardAmountMap := map[string]*big.Int{}
	for addr, ratio := range rewardRatioMap {
		// reward * ratio / 100
		rewardAmountMap[addr] = new(big.Int).Div(new(big.Int).Mul(mintingAmount, ratio), big.NewInt(100))
	}

	return rewardAmountMap, rewardRatioMap, nil
}

func (kc *Client) blockRewardTransaction(
	block *types.Block,
) (*RosettaTypes.Transaction, map[string]*big.Int, error) {
	var ops []*RosettaTypes.Operation
	rewardAmountMap, rewardRatioMap, err := kc.blockMintingReward(block)
	if err != nil {
		return nil, nil, err
	}

	idx := int64(0)
	for addr, r := range rewardAmountMap {
		miningRewardOp := &RosettaTypes.Operation{
			OperationIdentifier: &RosettaTypes.OperationIdentifier{
				Index: idx,
			},
			Type:   BlockRewardOpType,
			Status: RosettaTypes.String(SuccessStatus),
			Account: &RosettaTypes.AccountIdentifier{
				Address: MustChecksum(addr),
			},
			Amount: &RosettaTypes.Amount{
				Value:    r.String(),
				Currency: Currency,
			},
		}
		ops = append(ops, miningRewardOp)
		idx++
	}

	return &RosettaTypes.Transaction{
		TransactionIdentifier: &RosettaTypes.TransactionIdentifier{
			Hash: block.Hash().String(),
		},
		Operations: ops,
	}, rewardRatioMap, nil
}

type rpcProgress struct {
	StartingBlock hexutil.Uint64
	CurrentBlock  hexutil.Uint64
	HighestBlock  hexutil.Uint64
	PulledStates  hexutil.Uint64
	KnownStates   hexutil.Uint64
}

// syncProgress retrieves the current progress of the sync algorithm. If there's
// no sync currently running, it returns nil.
func (kc *Client) syncProgress(ctx context.Context) (*klaytn.SyncProgress, error) {
	var raw json.RawMessage
	if err := kc.c.CallContext(ctx, &raw, "klay_syncing"); err != nil {
		return nil, err
	}

	var syncing bool
	if err := json.Unmarshal(raw, &syncing); err == nil {
		return nil, nil // Not syncing (always false)
	}

	var progress rpcProgress
	if err := json.Unmarshal(raw, &progress); err != nil {
		return nil, err
	}

	return &klaytn.SyncProgress{
		StartingBlock: uint64(progress.StartingBlock),
		CurrentBlock:  uint64(progress.CurrentBlock),
		HighestBlock:  uint64(progress.HighestBlock),
		PulledStates:  uint64(progress.PulledStates),
		KnownStates:   uint64(progress.KnownStates),
	}, nil
}

// Balance returns the balance of a *RosettaTypes.AccountIdentifier
// at a *RosettaTypes.PartialBlockIdentifier.
//
// Currently, Klaytn does not support graphQL, so it uses multiple RPC calls.
// Since Balance RPC Call supports block information as a parameter, there is no need to use graphQL.
func (kc *Client) Balance(
	ctx context.Context,
	accountIdf *RosettaTypes.AccountIdentifier,
	block *RosettaTypes.PartialBlockIdentifier,
) (*RosettaTypes.AccountBalanceResponse, error) {
	blockQuery := "latest"
	blockQueryMethod := "klay_getBlockByNumber"
	if block != nil {
		if block.Hash != nil {
			blockQuery = *block.Hash
			blockQueryMethod = "klay_getBlockByHash"
		}
		if block.Hash == nil && block.Index != nil {
			blockQuery = "0x" + strconv.FormatInt(*block.Index, 16)
		}
	}

	var accountInfo account.AccountSerializer
	if err := kc.c.CallContext(ctx, &accountInfo, "klay_getAccount", accountIdf.Address, blockQuery); err != nil {
		return nil, err
	}

	balance := accountInfo.GetAccount().GetBalance().String()
	nonce := accountInfo.GetAccount().GetNonce()

	var blockInfo types.Header
	if err := kc.c.CallContext(ctx, &blockInfo, blockQueryMethod, blockQuery, false); err != nil {
		return nil, err
	}

	blockHash := blockInfo.Hash().String()
	blockNumber := blockInfo.Number.Int64()

	return &RosettaTypes.AccountBalanceResponse{
		Balances: []*RosettaTypes.Amount{
			{
				Value:    balance,
				Currency: Currency,
			},
		},
		BlockIdentifier: &RosettaTypes.BlockIdentifier{
			Hash:  blockHash,
			Index: blockNumber,
		},
		Metadata: map[string]interface{}{
			"nonce": int64(nonce),
		},
	}, nil
}

// GetBlockByNumberInput is the input to the call
// method "klay_getBlockByNumber".
type GetBlockByNumberInput struct {
	Index         *int64 `json:"index,omitempty"`
	ShowTxDetails bool   `json:"show_transaction_details"`
}

// GetTransactionReceiptInput is the input to the call
// method "klay_getTransactionReceipt".
type GetTransactionReceiptInput struct {
	TxHash string `json:"tx_hash"`
}

// GetCallInput is the input to the call
// method "klay_call", "klay_estimateGas".
type GetCallInput struct {
	BlockIndex int64  `json:"index,omitempty"`
	BlockHash  string `json:"hash,omitempty"`
	From       string `json:"from"`
	To         string `json:"to"`
	Gas        int64  `json:"gas"`
	GasPrice   int64  `json:"gas_price"`
	Value      int64  `json:"value"`
	Data       string `json:"data"`
}

// Call handles calls to the /call endpoint.
func (kc *Client) Call(
	ctx context.Context,
	request *RosettaTypes.CallRequest,
) (*RosettaTypes.CallResponse, error) {
	switch request.Method { // nolint:gocritic
	case "klay_getBlockByNumber":
		var input GetBlockByNumberInput
		if err := RosettaTypes.UnmarshalMap(request.Parameters, &input); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrCallParametersInvalid, err.Error())
		}

		res, err := kc.blockByNumber(ctx, input.Index, input.ShowTxDetails)
		if err != nil {
			return nil, err
		}

		return &RosettaTypes.CallResponse{
			Result: res,
		}, nil
	case "klay_getTransactionReceipt":
		var input GetTransactionReceiptInput
		if err := RosettaTypes.UnmarshalMap(request.Parameters, &input); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrCallParametersInvalid, err.Error())
		}

		if len(input.TxHash) == 0 {
			return nil, fmt.Errorf("%w:tx_hash missing from params", ErrCallParametersInvalid)
		}

		// Use RPC call directly to avoid struggle with nil contract address in the test code.
		// types.Receipt has empty common.Address{} instead of nil.
		var receiptMap map[string]interface{}
		err := kc.c.CallContext(ctx, &receiptMap, "klay_getTransactionReceipt", input.TxHash)
		if err == nil && receiptMap == nil {
			return nil, klaytn.NotFound
		}

		// We must encode data over the wire so we can unmarshal correctly
		return &RosettaTypes.CallResponse{
			Result: receiptMap,
		}, nil
	case "klay_call":
		resp, err := kc.contractCall(ctx, request.Parameters)
		if err != nil {
			return nil, err
		}

		return &RosettaTypes.CallResponse{
			Result: resp,
		}, nil
	case "klay_estimateGas":
		resp, err := kc.estimateGas(ctx, request.Parameters)
		if err != nil {
			return nil, err
		}

		return &RosettaTypes.CallResponse{
			Result: resp,
		}, nil
	}

	return nil, fmt.Errorf("%w: %s", ErrCallMethodInvalid, request.Method)
}

// txPoolContentResponse represents the response for a call to
// geth node on the "txpool_content" method.
type txPoolContentResponse struct {
	Pending txPool `json:"pending"`
	Queued  txPool `json:"queued"`
}

type txPool map[string]txPoolInner

type txPoolInner map[string]rpcTransaction

// GetMempool get and returns all the transactions on Ethereum TxPool (pending and queued).
func (kc *Client) GetMempool(ctx context.Context) (*RosettaTypes.MempoolResponse, error) {
	var response txPoolContentResponse
	if err := kc.c.CallContext(ctx, &response, "txpool_content"); err != nil {
		return nil, err
	}

	identifiers := make([]*RosettaTypes.TransactionIdentifier, 0)

	for _, inner := range response.Pending {
		for _, info := range inner {
			identifiers = append(identifiers, &RosettaTypes.TransactionIdentifier{
				Hash: info.tx.Hash().String(),
			})
		}
	}

	for _, inner := range response.Queued {
		for _, info := range inner {
			identifiers = append(identifiers, &RosettaTypes.TransactionIdentifier{
				Hash: info.tx.Hash().String(),
			})
		}
	}

	return &RosettaTypes.MempoolResponse{TransactionIdentifiers: identifiers}, nil
}
