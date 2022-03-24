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
	"github.com/klaytn/klaytn/params"
	"github.com/klaytn/rosetta-klaytn/klaytn"
	"os"
	"testing"

	"github.com/coinbase/rosetta-sdk-go/types"
	"github.com/stretchr/testify/assert"
)

func TestLoadConfiguration(t *testing.T) {
	tests := map[string]struct {
		Mode      string
		Network   string
		Port      string
		Geth      string
		SkipAdmin string

		cfg *Configuration
		err error
	}{
		"no envs set": {
			err: errors.New("MODE must be populated"),
		},
		"only mode set": {
			Mode: string(Online),
			err:  errors.New("NETWORK must be populated"),
		},
		"only mode and network set": {
			Mode:    string(Online),
			Network: Mainnet,
			err:     errors.New("PORT must be populated"),
		},
		"all set (mainnet)": {
			Mode:      string(Online),
			Network:   Mainnet,
			Port:      "1000",
			SkipAdmin: "FALSE",
			cfg: &Configuration{
				Mode: Online,
				Network: &types.NetworkIdentifier{
					Network:    klaytn.MainnetNetwork,
					Blockchain: klaytn.Blockchain,
				},
				Params:                 params.CypressChainConfig,
				GenesisBlockIdentifier: klaytn.MainnetGenesisBlockIdentifier,
				Port:                   1000,
				KlaytnNodeURL:          DefaultKlaytnNodeURL,
				KlaytnNodeArguments:    klaytn.MainnetKlaytnNodeArguments,
				SkipAdmin:              false,
			},
		},
		"all set (mainnet) + geth": {
			Mode:      string(Online),
			Network:   Mainnet,
			Port:      "1000",
			Geth:      "http://blah",
			SkipAdmin: "TRUE",
			cfg: &Configuration{
				Mode: Online,
				Network: &types.NetworkIdentifier{
					Network:    klaytn.MainnetNetwork,
					Blockchain: klaytn.Blockchain,
				},
				Params:                 params.CypressChainConfig,
				GenesisBlockIdentifier: klaytn.MainnetGenesisBlockIdentifier,
				Port:                   1000,
				KlaytnNodeURL:          "http://blah",
				RemoteNode:             true,
				KlaytnNodeArguments:    klaytn.MainnetKlaytnNodeArguments,
				SkipAdmin:              true,
			},
		},
		"all set (baobab)": {
			Mode:    string(Online),
			Network: Baobab,
			Port:    "1000",
			cfg: &Configuration{
				Mode: Online,
				Network: &types.NetworkIdentifier{
					Network:    klaytn.BaobabNetwork,
					Blockchain: klaytn.Blockchain,
				},
				Params:                 params.BaobabChainConfig,
				GenesisBlockIdentifier: klaytn.BaobabGenesisBlockIdentifier,
				Port:                   1000,
				KlaytnNodeURL:          DefaultKlaytnNodeURL,
				KlaytnNodeArguments:    klaytn.BaobabKlaytnNodeArguments,
			},
		},
		"invalid mode": {
			Mode:    "bad mode",
			Network: Baobab,
			Port:    "1000",
			err:     errors.New("bad mode is not a valid mode"),
		},
		"invalid network": {
			Mode:    string(Offline),
			Network: "bad network",
			Port:    "1000",
			err:     errors.New("bad network is not a valid network"),
		},
		"invalid port": {
			Mode:    string(Offline),
			Network: Baobab,
			Port:    "bad port",
			err:     errors.New("unable to parse port bad port"),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			os.Setenv(ModeEnv, test.Mode)
			os.Setenv(NetworkEnv, test.Network)
			os.Setenv(PortEnv, test.Port)
			os.Setenv(KlaytnNodeEnv, test.Geth)
			os.Setenv(SkipAdminEnv, test.SkipAdmin)

			cfg, err := LoadConfiguration()
			if test.err != nil {
				assert.Nil(t, cfg)
				assert.Contains(t, err.Error(), test.err.Error())
			} else {
				assert.Equal(t, test.cfg, cfg)
				assert.NoError(t, err)
			}
		})
	}
}
