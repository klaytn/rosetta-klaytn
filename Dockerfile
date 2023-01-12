# Copyright 2020 Coinbase, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Modifications Copyright © 2022 Klaytn
# Modified and improved for the Klaytn development

# I used below command to make docker image (If you do not use the Mac M1 chip, remove `--platform=linux/amd64`).
# docker build --platform=linux/amd64 -t rosetta-klaytn:latest .
# And i also used below command to run a docker container (If you do not use the Mac M1 chip, remove `--platform=linux/amd64`).
# docker run --platform linux/amd64 --rm --ulimit "nofile=100000:100000" -e "MODE=ONLINE" -e "NETWORK=TESTNET" -e "PORT=8080" -e "KEN=http://x.x.x.x:8551" -p 8080:8080 -p 30303:30303 rosetta-klaytn:latest
# docker run --platform linux/amd64 --rm --ulimit "nofile=100000:100000" -e "MODE=OFFLINE" -e "NETWORK=TESTNET" -e "PORT=8081" -e "KEN=http://x.x.x.x:8551" -p 8081:8081 rosetta-klaytn:latest

# Compile golang
FROM ubuntu:20.04 as golang-builder

RUN mkdir -p /app \
  && chown -R nobody:nogroup /app
WORKDIR /app

RUN apt-get update && apt-get install -y curl make gcc g++ git
ENV GOLANG_VERSION 1.18.4
ENV GOLANG_DOWNLOAD_SHA256 c9b099b68d93f5c5c8a8844a89f8db07eaa58270e3a1e01804f17f4cf8df02f5
ENV GOLANG_DOWNLOAD_URL https://golang.org/dl/go$GOLANG_VERSION.linux-amd64.tar.gz

RUN curl -fsSL "$GOLANG_DOWNLOAD_URL" -o golang.tar.gz \
  && echo "$GOLANG_DOWNLOAD_SHA256  golang.tar.gz" | sha256sum -c - \
  && tar -C /usr/local -xzf golang.tar.gz \
  && rm golang.tar.gz

ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH
RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"

# Compile ken
FROM golang-builder as ken-builder

# VERSION: klaytn v.1.10.1
RUN git clone https://github.com/klaytn/klaytn \
  && cd klaytn \
  && git checkout v1.10.1

RUN cd klaytn \
  && make ken

RUN mv klaytn/build/bin/ken /app/ken \
  && rm -rf klaytn

# Compile rosetta-klaytn
FROM golang-builder as rosetta-builder

# Use native remote build context to build in any directory
COPY . src
RUN cd src \
  && go build

RUN mv src/rosetta-klaytn /app/rosetta-klaytn \
  && mkdir /app/klaytn \
  && mv src/klaytn/ken.yaml /app/klaytn/ken.yaml \
  && rm -rf src

## Build Final Image
FROM ubuntu:20.04

RUN apt-get update && apt-get install -y ca-certificates && update-ca-certificates

RUN mkdir -p /app \
  && chown -R nobody:nogroup /app \
  && mkdir -p /data \
  && chown -R nobody:nogroup /data

WORKDIR /app

# Copy binary from ken-builder
COPY --from=ken-builder /app/ken /app/ken

# Copy binary from rosetta-builder
COPY --from=rosetta-builder /app/klaytn /app/klaytn
COPY --from=rosetta-builder /app/rosetta-klaytn /app/rosetta-klaytn

# Set permissions for everything added to /app
RUN chmod -R 755 /app/*

CMD ["/app/rosetta-klaytn", "run"]
