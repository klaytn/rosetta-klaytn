# Run rosetta-klaytn for testnet
# Use this script when you want to run it in the terminal.

export MODE=ONLINE
export NETWORK=TESTNET
export PORT=9090
export KEN="<Replace this with Acrhive Node URL>"

go run main.go run >> ros-mainnet.log
