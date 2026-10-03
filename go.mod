module github.com/agent-harness/policy

go 1.27

require (
	github.com/agent-harness/contracts/gen v0.0.0
	github.com/agent-harness/taint v0.0.0
)

replace github.com/agent-harness/contracts/gen => ../../contracts/gen
replace github.com/agent-harness/taint => ../../taint/go
