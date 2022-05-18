# Copyright 2022 Klaytn
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
# Run rosetta-klaytn for testnet
# Use this script when you want to run it in the terminal.

export MODE=ONLINE
export NETWORK=TESTNET
export PORT=9090

if [ ! -z "$1" ]
  then
    export KEN=$1
  else
    export KEN="<Replace this with Archive Node URL>"
fi

go run main.go run >> ros-testnet.log
