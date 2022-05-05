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
