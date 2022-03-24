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

package configuration

import (
	"errors"
	"fmt"
	"github.com/klaytn/klaytn/params"
	"github.com/klaytn/rosetta-klaytn/klaytn"
	"os"
	"strconv"

	"github.com/coinbase/rosetta-sdk-go/types"
)

// Mode is the setting that determines if
// the implementation is "online" or "offline".
type Mode string

const (
	// Online is when the implementation is permitted
	// to make outbound connections.
	Online Mode = "ONLINE"

	// Offline is when the implementation is not permitted
	// to make outbound connections.
	Offline Mode = "OFFLINE"

	// Mainnet is the Klaytn Mainnet.
	Mainnet string = "MAINNET"

	// Baobab is the Klaytn Baobab testnet.
	Baobab string = "BAOBAB"

	// DataDirectory is the default location for all
	// persistent data.
	DataDirectory = "/data"

	// ModeEnv is the environment variable read
	// to determine mode.
	ModeEnv = "MODE"

	// NetworkEnv is the environment variable
	// read to determine network.
	NetworkEnv = "NETWORK"

	// PortEnv is the environment variable
	// read to determine the port for the Rosetta
	// implementation.
	PortEnv = "PORT"

	// KlaytnNodeEnv is an optional environment variable
	// used to connect rosetta-klaytn to an already
	// running klaytn client node.
	KlaytnNodeEnv = "KLAYTN_NODE"

	// DefaultKlaytnNodeURL is the default URL for
	// a running geth node. This is used
	// when KlaytnNodeEnv is not populated.
	DefaultKlaytnNodeURL = "http://localhost:8551"

	// SkipAdminEnv is an optional environment variable
	// to skip `admin` calls which are typically not supported
	// by hosted node services. When not set, defaults to false.
	SkipAdminEnv = "SKIP_ADMIN"

	// MiddlewareVersion is the version of rosetta-klaytn.
	MiddlewareVersion = "0.0.1"
)

// Configuration determines how
type Configuration struct {
	Mode                   Mode
	Network                *types.NetworkIdentifier
	GenesisBlockIdentifier *types.BlockIdentifier
	KlaytnNodeURL          string
	RemoteNode             bool
	Port                   int
	KlaytnNodeArguments    string
	SkipAdmin              bool

	// Block Reward Data
	Params *params.ChainConfig
}

// LoadConfiguration attempts to create a new Configuration
// using the ENVs in the environment.
func LoadConfiguration() (*Configuration, error) {
	config := &Configuration{}

	modeValue := Mode(os.Getenv(ModeEnv))
	switch modeValue {
	case Online:
		config.Mode = Online
	case Offline:
		config.Mode = Offline
	case "":
		return nil, errors.New("MODE must be populated")
	default:
		return nil, fmt.Errorf("%s is not a valid mode", modeValue)
	}

	networkValue := os.Getenv(NetworkEnv)
	switch networkValue {
	case Mainnet:
		config.Network = &types.NetworkIdentifier{
			Blockchain: klaytn.Blockchain,
			Network:    klaytn.MainnetNetwork,
		}
		config.GenesisBlockIdentifier = klaytn.MainnetGenesisBlockIdentifier
		config.Params = params.CypressChainConfig
		config.KlaytnNodeArguments = klaytn.MainnetKlaytnNodeArguments
	case Baobab:
		config.Network = &types.NetworkIdentifier{
			Blockchain: klaytn.Blockchain,
			Network:    klaytn.BaobabNetwork,
		}
		config.GenesisBlockIdentifier = klaytn.BaobabGenesisBlockIdentifier
		config.Params = params.BaobabChainConfig
		config.KlaytnNodeArguments = klaytn.BaobabKlaytnNodeArguments
	case "":
		return nil, errors.New("NETWORK must be populated")
	default:
		return nil, fmt.Errorf("%s is not a valid network", networkValue)
	}

	config.KlaytnNodeURL = DefaultKlaytnNodeURL
	envKlaytnNodeURL := os.Getenv(KlaytnNodeEnv)
	if len(envKlaytnNodeURL) > 0 {
		config.RemoteNode = true
		config.KlaytnNodeURL = envKlaytnNodeURL
	}

	config.SkipAdmin = false
	envSkipAdmin := os.Getenv(SkipAdminEnv)
	if len(envSkipAdmin) > 0 {
		val, err := strconv.ParseBool(envSkipAdmin)
		if err != nil {
			return nil, fmt.Errorf("%w: unable to parse SKIP_ADMIN %s", err, envSkipAdmin)
		}
		config.SkipAdmin = val
	}

	portValue := os.Getenv(PortEnv)
	if len(portValue) == 0 {
		return nil, errors.New("PORT must be populated")
	}

	port, err := strconv.Atoi(portValue)
	if err != nil || len(portValue) == 0 || port <= 0 {
		return nil, fmt.Errorf("%w: unable to parse port %s", err, portValue)
	}
	config.Port = port

	return config, nil
}
