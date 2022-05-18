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
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/sync/errgroup"
)

const (
	kenLogger       = "ken"
	kenStdErrLogger = "ken err"
)

// logPipe prints out logs from ken. We don't end when context
// is canceled beacause there are often logs printed after this.
func logPipe(pipe io.ReadCloser, identifier string) error {
	reader := bufio.NewReader(pipe)
	for {
		str, err := reader.ReadString('\n')
		if err != nil {
			log.Println("closing", identifier, err)
			return err
		}

		message := strings.ReplaceAll(str, "\n", "")
		log.Println(identifier, message)
	}
}

// StartKlaytnNode starts a Klaytn EN node daemon in another goroutine
// and logs the results to the console.
func StartKlaytnNode(ctx context.Context, arguments string, g *errgroup.Group) error {
	parsedArgs := strings.Split(arguments, " ")
	cmd := exec.Command(
		"/app/ken",
		parsedArgs...,
	) // #nosec G204

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	g.Go(func() error {
		return logPipe(stdout, kenLogger)
	})

	g.Go(func() error {
		return logPipe(stderr, kenStdErrLogger)
	})

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("%w: unable to start Klaytn EN node", err)
	}

	g.Go(func() error {
		<-ctx.Done()

		log.Println("sending interrupt to Klaytn EN node")
		return cmd.Process.Signal(os.Interrupt)
	})

	return cmd.Wait()
}
