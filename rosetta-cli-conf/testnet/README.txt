For testing testnet in automated way, we should fill account infos for
`construction.prefunded_accounts` field info at `config.json` file.

We need at least 2 accounts which have enough KLAY to test transfer scenario.

Tip for testing.
- check:data
  - Give a value to `end_conditions.index` of `config.json` to limit the work scope.
  - If you don't write `end_conditions.index` it would run endlessly because there is no end conditions.
