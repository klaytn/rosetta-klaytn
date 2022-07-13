<p align="center">
  <a href="https://www.rosetta-api.org">
    <img width="90%" alt="Rosetta" src="https://www.rosetta-api.org/img/rosetta_header.png">
  </a>
</p>
<h3 align="center">
   Rosetta Klaytn
</h3>

## Overview
`rosetta-klaytn` provides an implementation of the Rosetta API for Klaytn in Golang, based off the [rosetta-ethereum](https://github.com/coinbase/rosetta-ethereum) reference implementation provided by Coinbase. If you haven't heard of the Rosetta API, you can find more information [here](https://rosetta-api.org).
The project started with a fork of [23561f903bc93d4fa97bebc1fbbe4c7e5b374e5e commit](https://github.com/coinbase/rosetta-ethereum/commit/23561f903bc93d4fa97bebc1fbbe4c7e5b374e5e), a commit on February 25, 2022.

## Features
* Comprehensive tracking of all ETH balance changes
* Stateless, offline, curve-based transaction construction (with address checksum validation)
* Atomic balance lookups using go-ethereum's GraphQL Endpoint
* Idempotent access to all transaction traces and receipts

## System Requirements
### For rosetta-klaytn
`rosetta-klaytn` has been tested on an [AWS c5.2xlarge instance](https://aws.amazon.com/ec2/instance-types/c5).
This instance type has 8 vCPU and 16 GB of RAM. If you use a computer with less than 16 GB of RAM,
it is possible that `rosetta-klaytn` will exit with an OOM error.

#### Recommended OS Settings
To increase the load `rosetta-klaytn` can handle, it is recommended to tune your OS
settings to allow for more connections. On a linux-based OS, you can run the following
commands ([source](http://www.tweaked.io/guide/kernel)):
```text
sysctl -w net.ipv4.tcp_tw_reuse=1
sysctl -w net.core.rmem_max=16777216
sysctl -w net.core.wmem_max=16777216
sysctl -w net.ipv4.tcp_max_syn_backlog=10000
sysctl -w net.core.somaxconn=10000
sysctl -p (when done)
```
_We have not tested `rosetta-klaytn` with `net.ipv4.tcp_tw_recycle` and do not recommend
enabling it._

You should also modify your open file settings to `100000`. This can be done on a linux-based OS
with the command: `ulimit -n 100000`.

### For Klaytn Node
For Klaytn Node, you should operate an [EN(Endpoint Node)](https://docs.klaytn.foundation/node/endpoint-node) with `arcive` mode.
And also you can see the system requirements for [Endpoint Node](https://docs.klaytn.foundation/node/endpoint-node/system-requirements) in here.

#### Recommended `kend.conf` configuration
To serve rosetta-klaytn API, EN should enable rpc api like `RPC_ENABLE=1` and serve `klay`, `debug`, `txpool`, `governance` and `admin`(admin rpc api is optional) rpc apis.

```text
# rpc options setting
RPC_ENABLE=1 # if this is set, the following options will be used
RPC_API="admin,debug,klay,txpool,governance"
RPC_CONCURRENCYLIMIT=48000
RPC_READ_TIMEOUT=48000
RPC_WRITE_TIMEOUT=48000
RPC_IDLE_TIMEOUT=48000
RPC_EXECUTION_TIMEOUT=48000

# Raw options e.g) "--txpool.nolocals"
ADDITIONAL="--gcmode archive"
```

To run EN in archive mode, you can append the `--gcmode archive` flag to `ADDITIONAL`.

## Usage
As specified in the [Rosetta API Principles](https://www.rosetta-api.org/docs/automated_deployment.html),
all Rosetta implementations must be deployable via Docker and support running via either an
[`online` or `offline` mode](https://www.rosetta-api.org/docs/node_deployment.html#multiple-modes).

**YOU MUST INSTALL DOCKER FOR THE FOLLOWING INSTRUCTIONS TO WORK. YOU CAN DOWNLOAD
DOCKER [HERE](https://www.docker.com/get-started).**

### Install
Running the following commands will create a Docker image called `rosetta-klaytn:latest`.

#### From GitHub
To download the pre-built Docker image from the latest release, run:
```text
curl -sSfL https://raw.githubusercontent.com/klaytn/rosetta-klaytn/master/install.sh | sh -s
```

_Do not try to install rosetta-klaytn using GitHub Packages!_


#### From Source
After cloning this repository, run:
```text
make build-local
```

### Run
Running the following commands will start a Docker container in
[detached mode](https://docs.docker.com/engine/reference/run/#detached--d) with
a data directory at `<working directory>/klaytn-data` and the Rosetta API accessible
at port `8080`.

#### Configuration Environment Variables
* `MODE` (required) - Determines if Rosetta can make outbound connections. Options: `ONLINE` or `OFFLINE`.
* `NETWORK` (required) - Klaytn network to launch and/or communicate with. Options: `MAINNET` or `TESTNET`.
* `PORT`(required) - Which port to use for Rosetta.
* `KEN` (optional) - Point to a remote `klaytn` EN node instead of initializing one
* `SKIP_ADMIN` (optional, default: `FALSE`) - Instruct Rosetta to not use the `ken` `admin` RPC calls. This is typically disabled by hosted blockchain node services.

#### Mainnet:Online
```text
docker run -d --rm --ulimit "nofile=100000:100000" -v "$(pwd)/klaytn-data:/data" -e "MODE=ONLINE" -e "NETWORK=MAINNET" -e "PORT=8080" -p 8080:8080 -p 30303:30303 rosetta-klaytn:latest
```
_If you cloned the repository, you can run `make run-mainnet-online`._

#### Mainnet:Online (Remote)
```text
docker run -d --rm --ulimit "nofile=100000:100000" -e "MODE=ONLINE" -e "NETWORK=MAINNET" -e "PORT=8080" -e "KEN=<NODE URL>" -p 8080:8080 -p 30303:30303 rosetta-klaytn:latest
```
_If you cloned the repository, you can run `make run-mainnet-remote ken=<NODE URL>`._

#### Mainnet:Offline
```text
docker run -d --rm -e "MODE=OFFLINE" -e "NETWORK=MAINNET" -e "PORT=8081" -p 8081:8081 rosetta-klaytn:latest
```
_If you cloned the repository, you can run `make run-mainnet-offline`._

#### Testnet:Online
```text
docker run -d --rm --ulimit "nofile=100000:100000" -v "$(pwd)/klaytn-data:/data" -e "MODE=ONLINE" -e "NETWORK=TESTNET" -e "PORT=8080" -p 8080:8080 -p 30303:30303 rosetta-klaytn:latest
```
_If you cloned the repository, you can run `make run-testnet-online`._

#### Testnet:Online (Remote)
```text
docker run -d --rm --ulimit "nofile=100000:100000" -e "MODE=ONLINE" -e "NETWORK=TESTNET" -e "PORT=8080" -e "KEN=<NODE URL>" -p 8080:8080 -p 30303:30303 rosetta-klaytn:latest
```
_If you cloned the repository, you can run `make run-testnet-remote ken=<NODE URL>`._

#### Testnet:Offline
```text
docker run -d --rm -e "MODE=OFFLINE" -e "NETWORK=TESTNET" -e "PORT=8081" -p 8081:8081 rosetta-klaytn:latest
```
_If you cloned the repository, you can run `make run-testnet-offline`._

If you are using MacOS M1, you might need to add `--platform linux/amd64` flag like below when you run docker container.
```shell
docker run --platform linux/amd64 -d --rm -e "MODE=OFFLINE" -e "NETWORK=TESTNET" -e "PORT=8081" -p 8081:8081 rosetta-klaytn:latest
```

## Testing with rosetta-cli
To validate `rosetta-klaytn`, [install `rosetta-cli`](https://github.com/klaytn/rosetta-cli#install)
and run one of the following commands:
* `rosetta-cli check:data --configuration-file rosetta-cli-conf/testnet/config.json` - This command validates that the Data API implementation is correct using the Klaytn `testnet` node. It also ensures that the implementation does not miss any balance-changing operations.
* `rosetta-cli check:construction --configuration-file rosetta-cli-conf/testnet/config.json` - This command validates the Construction API implementation. It also verifies transaction construction, signing, and submissions to the `testnet` network.
* `rosetta-cli check:data --configuration-file rosetta-cli-conf/mainnet/config.json` - This command validates that the Data API implementation is correct using the Klaytn `mainnet` node. It also ensures that the implementation does not miss any balance-changing operations.

## Issues
Interested in helping fix issues in this repository? You can find to-dos in the [Issues](https://github.com/klaytn/rosetta-klaytn/issues) section. Be sure to reach out on our [community](https://community.rosetta-api.org) before you tackle anything on this list.

## Development
* `make deps` to install dependencies
* `make test` to run tests
* `make lint` to lint the source code
* `make salus` to check for security concerns
* `make build-local` to build a Docker image from the local context
* `make coverage-local` to generate a coverage report

## How to create test data for block testing in client_test.go
We need to execute client_test.go by generating the API result and creating the expected result as json data.

### Generate a test data in the network
You can create test data by sending a transaction to the network.

Alternatively, it is okay to use data that already exists in the network.

### Make test data files
In this step, the return data of the API called when the client function is executed is made into a json file, and when the actual test is performed, the data is returned using a mock.

Create a `block_{block number}.json` file using the value of the "result" field of the API result below.
```shell
curl -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"klay_getBlockByNumber","params":["0x{block number}", true],"id":1}' http://{your en url}:8551 > block.txt
```

Create a `block_receipts_0x{block hash}.json` file using the value of the "result" field of the API result below.
```shell
curl -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"klay_getBlockReceipts","params":["0x{block hash}"],"id":1}' http://{your en url}:8551 > receipts.txt
```

Create a `block_trace_0x{block hash}.json` file using the value of the "result" field of the API result below.
```shell
curl -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"debug_traceBlockByHash","params":["0x{block hash}", {"tracer": "fastCallTracer"}],"id":1}' http://{your en url}:8551 > trace.txt
```

### Make expected response data
Create a response object to be returned based on the above result in the `block_response_{block number}.json` file.

You can refer to `block_response_1078.json` file.

- 

## License
This project is available open source under the terms of the [Apache 2.0 License](https://opensource.org/licenses/Apache-2.0).

© 2021 Coinbase
