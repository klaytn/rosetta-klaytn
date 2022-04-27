.PHONY: deps build run lint run-mainnet-online run-mainnet-offline run-testnet-online \
	run-testnet-offline check-comments add-license check-license shorten-lines \
	spellcheck salus build-local format check-format update-tracer test coverage coverage-local \
	update-bootstrap-balances mocks

ADDLICENSE_IGNORE=-ignore "**/*.xml" -ignore "**/*.sh" -ignore "**/*.yml"
ADDLICENSE_INSTALL=go install github.com/google/addlicense@latest
ADDLICENSE_CMD=addlicense
ADDLICENCE_SCRIPT=${ADDLICENSE_CMD} -c "Klaytn Authors" -l "apache" -v ${ADDLICENSE_IGNORE}
SPELLCHECK_CMD=go run github.com/client9/misspell/cmd/misspell
GOLINES_INSTALL=go install github.com/segmentio/golines@latest
GOLINES_CMD=golines
GOLINT_INSTALL=go get golang.org/x/lint/golint
GOLINT_CMD=golint
GOVERALLS_INSTALL=go install github.com/mattn/goveralls@latest
GOVERALLS_CMD=goveralls
GOIMPORTS_CMD=go run golang.org/x/tools/cmd/goimports
GO_PACKAGES=./services/... ./cmd/... ./configuration/... ./klaytn/...
GO_FOLDERS=$(shell echo ${GO_PACKAGES} | sed -e "s/\.\///g" | sed -e "s/\/\.\.\.//g")
TEST_SCRIPT=go test ${GO_PACKAGES}
LINT_SETTINGS=golint,misspell,gocyclo,gocritic,whitespace,goconst,gocognit,bodyclose,unconvert,lll,unparam
PWD=$(shell pwd)
NOFILE=100000

deps:
	go get ./...

test:
	${TEST_SCRIPT}

build:
	docker build -t rosetta-klaytn:latest https://github.com/klaytn/rosetta-klaytn.git

build-m1:
	docker build --platform linux/amd64 -t rosetta-klaytn:latest https://github.com/klaytn/rosetta-klaytn.git

build-local:
	docker build -t rosetta-klaytn:latest .

build-local-m1:
	docker build --platform linux/amd64 -t rosetta-klaytn:latest .

# make build-release -e "version=vx.x.x"
build-release:
	# make sure to always set version with vX.X.X
	docker build -t rosetta-klaytn:$(version) .;
	docker save rosetta-klaytn:$(version) | gzip > rosetta-klaytn-$(version).tar.gz;

# make build-release-m1 -e "version=vx.x.x"
build-release-m1:
	# make sure to always set version with vX.X.X
	docker build --platform linux/amd64 -t rosetta-klaytn:$(version) .;
	docker save rosetta-klaytn:$(version) | gzip > rosetta-klaytn-$(version).tar.gz;

update-bootstrap-balances:
	go run main.go utils:generate-bootstrap klaytn/genesis_files/mainnet.json rosetta-cli-conf/mainnet/bootstrap_balances.json;
	go run main.go utils:generate-bootstrap klaytn/genesis_files/testnet.json rosetta-cli-conf/testnet/bootstrap_balances.json;

run-mainnet-online:
	docker run -d --rm --ulimit "nofile=${NOFILE}:${NOFILE}" -v "${PWD}/klaytn-data:/data" -e "MODE=ONLINE" -e "NETWORK=MAINNET" -e "PORT=8080" -p 8080:8080 -p 30303:30303 rosetta-klaytn:latest

run-mainnet-online-m1:
	docker run --platform linux/amd64 -d --rm --ulimit "nofile=${NOFILE}:${NOFILE}" -v "${PWD}/klaytn-data:/data" -e "MODE=ONLINE" -e "NETWORK=MAINNET" -e "PORT=8080" -p 8080:8080 -p 30303:30303 rosetta-klaytn:latest

run-mainnet-offline:
	docker run -d --rm -e "MODE=OFFLINE" -e "NETWORK=MAINNET" -e "PORT=8081" -p 8081:8081 rosetta-klaytn:latest

run-mainnet-offline-m1:
	docker run --platform linux/amd64 -d --rm -e "MODE=OFFLINE" -e "NETWORK=MAINNET" -e "PORT=8081" -p 8081:8081 rosetta-klaytn:latest

run-testnet-online:
	docker run -d --rm --ulimit "nofile=${NOFILE}:${NOFILE}" -v "${PWD}/klaytn-data:/data" -e "MODE=ONLINE" -e "NETWORK=TESTNET" -e "PORT=8080" -p 8080:8080 -p 30303:30303 rosetta-klaytn:latest

run-testnet-online-m1:
	docker run --platform linux/amd64 -d --rm --ulimit "nofile=${NOFILE}:${NOFILE}" -v "${PWD}/klaytn-data:/data" -e "MODE=ONLINE" -e "NETWORK=TESTNET" -e "PORT=8080" -p 8080:8080 -p 30303:30303 rosetta-klaytn:latest

run-testnet-offline:
	docker run -d --rm -e "MODE=OFFLINE" -e "NETWORK=TESTNET" -e "PORT=8081" -p 8081:8081 rosetta-klaytn:latest

run-testnet-offline-m1:
	docker run --platform linux/amd64 -d --rm -e "MODE=OFFLINE" -e "NETWORK=TESTNET" -e "PORT=8081" -p 8081:8081 rosetta-klaytn:latest

run-mainnet-remote:
	docker run -d --rm --ulimit "nofile=${NOFILE}:${NOFILE}" -e "MODE=ONLINE" -e "NETWORK=MAINNET" -e "PORT=8080" -e "KEN=$(ken)" -p 8080:8080 -p 30303:30303 rosetta-klaytn:latest

# make run-mainnet-remote-m1 -e "ken=http://x.x.x.x:8551"
run-mainnet-remote-m1:
	docker run --platform linux/amd64 -d --rm --ulimit "nofile=${NOFILE}:${NOFILE}" -e "MODE=ONLINE" -e "NETWORK=MAINNET" -e "PORT=8080" -e "KEN=$(ken)" -p 8080:8080 -p 30303:30303 rosetta-klaytn:latest

run-testnet-remote:
	docker run -d --rm --ulimit "nofile=${NOFILE}:${NOFILE}" -e "MODE=ONLINE" -e "NETWORK=TESTNET" -e "PORT=8080" -e "KEN=$(ken)" -p 8080:8080 -p 30303:30303 rosetta-klaytn:latest

run-testnet-remote-m1:
	docker run --platform linux/amd64 -d --rm --ulimit "nofile=${NOFILE}:${NOFILE}" -e "MODE=ONLINE" -e "NETWORK=TESTNET" -e "PORT=8080" -e "KEN=$(ken)" -p 8080:8080 -p 30303:30303 rosetta-klaytn:latest

check-comments:
	${GOLINT_INSTALL}
	${GOLINT_CMD} -set_exit_status ${GO_FOLDERS} .
	go mod tidy

lint: | check-comments
	golangci-lint run --timeout 2m0s -v -E ${LINT_SETTINGS},gomnd

add-license:
	${ADDLICENSE_INSTALL}
	${ADDLICENCE_SCRIPT} .

check-license:
	${ADDLICENSE_INSTALL}
	${ADDLICENCE_SCRIPT} -check .

shorten-lines:
	${GOLINES_INSTALL}
	${GOLINES_CMD} -w --shorten-comments ${GO_FOLDERS} .

format:
	gofmt -s -w -l .
	${GOIMPORTS_CMD} -w .

check-format:
	! gofmt -s -l . | read
	! ${GOIMPORTS_CMD} -l . | read

salus:
	docker run --rm -t -v ${PWD}:/home/repo coinbase/salus

salus-m1:
	docker run --platform linux/amd64 --rm -t -v ${PWD}:/home/repo coinbase/salus

spellcheck:
	${SPELLCHECK_CMD} -error .

coverage:
	${GOVERALLS_INSTALL}
	if [ "${COVERALLS_TOKEN}" ]; then ${TEST_SCRIPT} -coverprofile=c.out -covermode=count; ${GOVERALLS_CMD} -coverprofile=c.out -repotoken ${COVERALLS_TOKEN}; fi

coverage-local:
	${TEST_SCRIPT} -cover

mocks:
	rm -rf mocks;
	mockery --dir services --all --case underscore --outpkg services --output mocks/services;
	mockery --dir klaytn --all --case underscore --outpkg klaytn --output mocks/klaytn;
	${ADDLICENSE_INSTALL}
	${ADDLICENCE_SCRIPT} .;
