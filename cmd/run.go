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

package cmd

import (
	"context"
	"errors"
	"fmt"
	"github.com/klaytn/rosetta-klaytn/klaytn"
	"log"
	"net/http"
	"time"

	"github.com/klaytn/rosetta-klaytn/configuration"
	"github.com/klaytn/rosetta-klaytn/services"

	"github.com/klaytn/rosetta-sdk-go-klaytn/asserter"
	"github.com/klaytn/rosetta-sdk-go-klaytn/server"
	"github.com/klaytn/rosetta-sdk-go-klaytn/types"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

const (
	// readTimeout is the maximum duration for reading the entire
	// request, including the body.
	readTimeout = 5 * time.Second

	// writeTimeout is the maximum duration before timing out
	// writes of the response. It is reset whenever a new
	// request's header is read.
	writeTimeout = 120 * time.Second

	// idleTimeout is the maximum amount of time to wait for the
	// next request when keep-alives are enabled.
	idleTimeout = 30 * time.Second
)

var (
	runCmd = &cobra.Command{
		Use:   "run",
		Short: "Run rosetta-klaytn",
		RunE:  runRunCmd,
	}
)

func runRunCmd(cmd *cobra.Command, args []string) error {
	cfg, err := configuration.LoadConfiguration()
	if err != nil {
		return fmt.Errorf("%w: unable to load configuration", err)
	}

	// The asserter automatically rejects incorrectly formatted
	// requests.
	asserter, err := asserter.NewServer(
		klaytn.OperationTypes,
		klaytn.HistoricalBalanceSupported,
		[]*types.NetworkIdentifier{cfg.Network},
		klaytn.CallMethods,
		klaytn.IncludeMempoolCoins,
		"",
	)
	if err != nil {
		return fmt.Errorf("%w: could not initialize server asserter", err)
	}

	// Start required services
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	go handleSignals([]context.CancelFunc{cancel})

	g, ctx := errgroup.WithContext(ctx)

	var client *klaytn.Client
	if cfg.Mode == configuration.Online {
		if !cfg.RemoteNode {
			g.Go(func() error {
				return klaytn.StartKlaytnNode(ctx, cfg.KlaytnNodeArguments, g)
			})
		}

		var err error
		client, err = klaytn.NewClient(cfg.KlaytnNodeURL, cfg.Params, cfg.SkipAdmin)
		if err != nil {
			return fmt.Errorf("%w: cannot initialize klaytn client", err)
		}
		defer client.Close()
	}

	router := services.NewBlockchainRouter(cfg, client, asserter)

	loggedRouter := server.LoggerMiddleware(router)
	corsRouter := server.CorsMiddleware(loggedRouter)
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      corsRouter,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}

	g.Go(func() error {
		log.Printf("server listening on port %d", cfg.Port)
		return server.ListenAndServe()
	})

	g.Go(func() error {
		// If we don't shutdown server in errgroup, it will
		// never stop because server.ListenAndServe doesn't
		// take any context.
		<-ctx.Done()

		return server.Shutdown(ctx)
	})

	err = g.Wait()
	if SignalReceived {
		return errors.New("rosetta-klaytn halted")
	}

	return err
}
