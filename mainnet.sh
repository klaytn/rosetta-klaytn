# Run rosetta-klaytn for mainnet
# Use this script when you want to run it in the terminal.

export MODE=ONLINE
export NETWORK=MAINNET
export PORT=8080
export KEN="<Replace this with Archive Node URL>"

if [ ! -z "$1" ]
  then
    export KEN=$1
  else
    export KEN="<Replace this with Archive Node URL>"
fi

go run main.go run >> ros-mainnet.log
