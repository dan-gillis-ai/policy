module github.com/dan-gillis-ai/policy

go 1.27

require (
	github.com/dan-gillis-ai/contracts/gen v0.0.0
	github.com/dan-gillis-ai/taint v0.0.0
)

replace github.com/dan-gillis-ai/contracts/gen => ../../contracts/gen
replace github.com/dan-gillis-ai/taint => ../../taint/go
