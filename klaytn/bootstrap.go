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

package klaytn

import (
	"fmt"
	"math/big"
	"sort"

	"github.com/klaytn/rosetta-sdk-go-klaytn/storage/modules"
	"github.com/klaytn/rosetta-sdk-go-klaytn/types"
	"github.com/klaytn/rosetta-sdk-go-klaytn/utils"
)

type genesis struct {
	Alloc          map[string]genesisAllocation `json:"alloc"`
	Config         map[string]interface{}       `json:"config"`
	Timestamp      string                       `json:"timestamp"`
	ExtraData      string                       `json:"extraData"`
	GovernanceData string                       `json:"governanceData"`
	BlockScore     string                       `json:"blockScore"`
	Number         string                       `json:"number"`
	GasUsed        string                       `json:"gasUsed"`
	ParentHash     string                       `json:"parentHash"`
	Nonce          string                       `json:"nonce"`
	Coinbase       string                       `json:"coinbase"`
}

type genesisAllocation struct {
	Balance string `json:"balance"`
	Code    string `json:"code"`
}

// GenerateBootstrapFile creates the bootstrap balances file
// for a particular genesis file.
func GenerateBootstrapFile(genesisFile string, outputFile string) error {
	var genesisAllocations genesis
	if err := utils.LoadAndParse(genesisFile, &genesisAllocations); err != nil {
		return fmt.Errorf("%w: could not load genesis file", err)
	}

	// Sort keys for deterministic genesis creation
	keys := make([]string, 0)
	formattedAllocations := map[string]string{}
	for k := range genesisAllocations.Alloc {
		checkAddr, ok := ChecksumAddress(k)
		if !ok {
			return fmt.Errorf("invalid address 0x%s", k)
		}
		keys = append(keys, checkAddr)
		formattedAllocations[checkAddr] = genesisAllocations.Alloc[k].Balance
	}
	sort.Strings(keys)

	// Write to file
	balances := []*modules.BootstrapBalance{}
	for _, k := range keys {
		v := formattedAllocations[k]
		bal, ok := new(big.Int).SetString(v[2:], 16) // nolint:gomnd
		if !ok {
			return fmt.Errorf("cannot parse %s for integer", v)
		}

		if bal.Sign() == 0 {
			continue
		}

		balances = append(balances, &modules.BootstrapBalance{
			Account: &types.AccountIdentifier{
				Address: k,
			},
			Value:    bal.String(),
			Currency: Currency,
		})
	}

	if err := utils.SerializeAndWrite(outputFile, balances); err != nil {
		return fmt.Errorf("%w: could not write bootstrap balances", err)
	}

	return nil
}
