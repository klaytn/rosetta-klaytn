module github.com/klaytn/rosetta-klaytn

require (
	github.com/fatih/color v1.13.0
	github.com/go-stack/stack v1.8.1 // indirect
	github.com/golang/mock v1.5.0 // indirect
	github.com/json-iterator/go v1.1.11 // indirect
	github.com/klaytn/klaytn v1.8.2
	github.com/klaytn/rosetta-sdk-go-klaytn v0.7.5
	github.com/pbnjay/memory v0.0.0-20210728143218-7b4eea64cf58 // indirect
	github.com/spf13/cobra v1.4.0
	github.com/stretchr/objx v0.3.0 // indirect
	github.com/stretchr/testify v1.7.1
	go.uber.org/atomic v1.9.0 // indirect
	go.uber.org/multierr v1.8.0 // indirect
	go.uber.org/zap v1.21.0 // indirect
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	google.golang.org/genproto v0.0.0-20210602131652-f16073e35f0c // indirect
)

replace github.com/klaytn/rosetta-sdk-go-klaytn => ../rosetta-sdk-go-klaytn

go 1.16
